#!/usr/bin/env bash
set -euo pipefail
umask 022

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/config"

# shellcheck disable=SC1090
[[ -f "${CONFIG_DIR}/.env" ]] && source "${CONFIG_DIR}/.env"
# shellcheck disable=SC1090
[[ -f "${CONFIG_DIR}/nginx.conf" ]] && source "${CONFIG_DIR}/nginx.conf"
# shellcheck disable=SC1090
[[ -f "${CONFIG_DIR}/index.html" ]] && source "${CONFIG_DIR}/index.html"

NGINX_VERSION="${NGINX_VERSION:-1.29.1}"
NGINX_URL="${NGINX_URL:-https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz,https://github.com/nginx/nginx/archive/refs/tags/release-${NGINX_VERSION}.tar.gz}"
NGINX_SHA256="${NGINX_SHA256:-c589f7e7ed801ddbd904afbf3de26ae24eb0cce27c7717a2e94df7fb12d6ad27}"

OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.3}"
OPENSSL_URL="${OPENSSL_URL:-https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz,https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz}"
OPENSSL_SHA256="${OPENSSL_SHA256:-c9489d2abcf943cdc8329a57092331c598a402938054dc3a22218aea8a8ec3bf}"

PCRE2_VERSION="${PCRE2_VERSION:-10.46}"
PCRE2_URL="${PCRE2_URL:-https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/pcre2-${PCRE2_VERSION}.tar.gz}"
PCRE2_SHA256="${PCRE2_SHA256:-8d28d7f2c3b970c3a4bf3776bcbb5adfc923183ce74bc8df1ebaad8c1985bd07}"

ZLIB_VERSION="${ZLIB_VERSION:-1.3.1}"
ZLIB_URL="${ZLIB_URL:-https://zlib.net/zlib-${ZLIB_VERSION}.tar.gz,https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/zlib-${ZLIB_VERSION}.tar.gz}"
ZLIB_SHA256="${ZLIB_SHA256:-9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23}"

HEADERS_MORE_VERSION="${HEADERS_MORE_VERSION:-0.39}"
HEADERS_MORE_URL="${HEADERS_MORE_URL:-https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v${HEADERS_MORE_VERSION}.tar.gz}"
HEADERS_MORE_SHA256="${HEADERS_MORE_SHA256:-dde68d3fa2a9fc7f52e436d2edc53c6d703dcd911283965d889102d3a877c778}"

ZSTD_MODULE_VERSION="${ZSTD_MODULE_VERSION:-0.1.1}"
ZSTD_MODULE_URL="${ZSTD_MODULE_URL:-https://github.com/tokers/zstd-nginx-module/archive/refs/tags/${ZSTD_MODULE_VERSION}.tar.gz}"
ZSTD_MODULE_SHA256="${ZSTD_MODULE_SHA256:-707d534f8ca4263ff043066db15eac284632aea875f9fe98c96cea9529e15f41}"

PREFIX="${PREFIX:-/usr/local/nginx}"
BACKUP_DIR="${BACKUP_DIR:-/root/nginx-backup-$(date +%Y%m%d-%H%M%S)}"
SERVICE_NAME="${SERVICE_NAME:-nginx}"
BUILD_DIR="${BUILD_DIR:-$(mktemp -d -t nginx-build-XXXXXXXX)}"
LOG_DIR="${LOG_DIR:-$(mktemp -d -t nginx-logs-XXXXXXXX)}"
CURRENT_STEP=""
CHECKSUM_POLICY="${CHECKSUM_POLICY:-strict}"
ZSTD_BUILD_MODE="dynamic"

ARTIFACTS=(
  "nginx|nginx-${NGINX_VERSION}.tar.gz|${NGINX_SHA256}|1|nginx-${NGINX_VERSION}||${NGINX_URL}"
  "openssl|openssl-${OPENSSL_VERSION}.tar.gz|${OPENSSL_SHA256}|0|openssl-${OPENSSL_VERSION}||${OPENSSL_URL}"
  "pcre2|pcre2-${PCRE2_VERSION}.tar.gz|${PCRE2_SHA256}|0|pcre2-${PCRE2_VERSION}||${PCRE2_URL}"
  "zlib|zlib-${ZLIB_VERSION}.tar.gz|${ZLIB_SHA256}|0|zlib-${ZLIB_VERSION}||${ZLIB_URL}"
  "headers-more|headers-more.tar.gz|${HEADERS_MORE_SHA256}|1|headers-more-module|ENABLE_HEADERS_MORE|${HEADERS_MORE_URL}"
  "zstd|zstd-module.tar.gz|${ZSTD_MODULE_SHA256}|1|zstd-module|ENABLE_ZSTD|${ZSTD_MODULE_URL}"
)

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

log_info()   { echo -e "${BLUE}[INFO]${NC} $1"; }
log_warn()   { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()  { echo -e "${RED}[ERR]${NC} $1" >&2; }
log_success(){ echo -e "${GREEN}[OK]${NC} $1"; }
log_step()   { CURRENT_STEP="$1"; echo -e "${PURPLE}[STEP]${NC} ${BOLD}$1${NC}"; }

cleanup() {
  local exit_code=$?
  if [[ -d "${BUILD_DIR}" ]]; then rm -rf "${BUILD_DIR}"; fi
  if [[ -d "${LOG_DIR}" ]]; then
    if [[ ${exit_code} -eq 0 ]]; then
      rm -rf "${LOG_DIR}"
    else
      log_warn "Logs preserved in ${LOG_DIR}"
    fi
  fi
}

on_err() {
  local exit_code=$?
  log_error "Command failed (exit=${exit_code}) during: ${CURRENT_STEP:-unknown step}"
  log_info "Check logs under ${LOG_DIR}"
}

trap on_err ERR
trap cleanup EXIT

validate_env() {
  case "${CHECKSUM_POLICY,,}" in
    strict|allow-missing|skip) ;;    
    *)
      log_error "Invalid CHECKSUM_POLICY: ${CHECKSUM_POLICY}"
      exit 1
      ;;
  esac
}

is_enabled() {
  local name="$1"; local fallback="${2:-auto}"; local value
  value="${!name:-$fallback}"
  case "${value,,}" in
    0|no|false|off|disable|disabled) return 1 ;;
    *) return 0 ;;
  esac
}

check_root() {
  if [[ ${EUID} -ne 0 ]]; then
    log_error "Run this script as root"
    exit 1
  fi
}

has_systemd() {
  command -v systemctl &>/dev/null && [[ -d /run/systemd/system ]]
}

confirm_or_exit() {
  local prompt="$1"; local envvar="${2:-CONFIRM}"; local val
  val="${!envvar:-yes}"
  case "${val,,}" in
    yes|y|true|1|auto|continue|proceed)
      log_info "Auto-confirmed: ${prompt} (${envvar}=${val})"
      return 0
      ;;
    no|n|false|0|stop|abort)
      log_warn "Operation cancelled via ${envvar}=${val}"
      exit 0
      ;;
    *)
      log_info "Auto-confirmed: ${prompt} (${envvar}=${val})"
      return 0
      ;;
  esac
}

require_cmds() {
  local missing=()
  local cmds=(curl make tar perl awk sed grep)
  for cmd in "${cmds[@]}"; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  if ! command -v sha256sum &>/dev/null && ! command -v shasum &>/dev/null; then
    missing+=("sha256sum or shasum")
  fi
  if ((${#missing[@]})); then
    log_error "Missing required tools: ${missing[*]}"
    exit 1
  fi
}

num_procs() {
  getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 2
}

compute_sha256() {
  local file="$1"
  if command -v sha256sum &>/dev/null; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

run_logged() {
  local log_name="$1"; shift
  local log_path="${LOG_DIR}/${log_name}"
  if ! "$@" >"${log_path}" 2>&1; then
    log_error "Command failed: $*"
    log_info "See ${log_path}"
    tail -n 60 "${log_path}" || true
    exit 1
  fi
}

install_dependencies() {
  log_step "Installing build dependencies"
  if command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    run_logged apt-update.log apt-get update -qq
    run_logged apt-install.log apt-get install -y build-essential libpcre2-dev zlib1g-dev perl curl gcc make hostname zstd libzstd-dev pkg-config
  elif command -v dnf &>/dev/null; then
    if dnf --version 2>/dev/null | grep -q "dnf5"; then
      run_logged dnf-install.log dnf install -y @development-tools
    else
      run_logged dnf-install.log dnf groupinstall -y "Development Tools"
    fi
    run_logged dnf-packages.log dnf install -y pcre2-devel zlib-devel perl curl gcc make hostname zstd libzstd libzstd-devel pkgconfig pkgconf-pkg-config
  elif command -v yum &>/dev/null; then
    run_logged yum-install.log yum groupinstall -y "Development Tools"
    run_logged yum-packages.log yum install -y pcre2-devel zlib-devel perl curl gcc make hostname zstd libzstd libzstd-devel pkgconfig pkgconf-pkg-config
  else
    log_error "Unsupported package manager (apt, dnf or yum required)"
    exit 1
  fi
  log_success "Dependencies installed"
}

backup_existing() {
  log_step "Backing up existing installation"
  mkdir -p "${BACKUP_DIR}"
  [[ -d /etc/nginx ]] && cp -a /etc/nginx "${BACKUP_DIR}/"
  [[ -f /usr/sbin/nginx ]] && cp /usr/sbin/nginx "${BACKUP_DIR}/nginx.sbin"
  if has_systemd; then
    if systemctl is-active --quiet nginx; then
      echo "nginx was active" > "${BACKUP_DIR}/service_status.txt"
    else
      echo "nginx was inactive" > "${BACKUP_DIR}/service_status.txt"
    fi
  fi
  log_success "Backup stored at ${BACKUP_DIR}"
}

verify_checksum() {
  local file="$1" expected="$2"
  case "${CHECKSUM_POLICY}" in
    skip) log_warn "Skipping checksum for ${file}"; return 0 ;;
    allow-missing)
      if [[ -z "${expected}" ]]; then
        log_warn "No checksum for ${file} (policy allow-missing)"; return 0
      fi
      ;;
    strict)
      if [[ -z "${expected}" ]]; then
        log_error "Missing checksum for ${file}"
        exit 1
      fi
      ;;
  esac
  local actual
  actual=$(compute_sha256 "${file}")
  if [[ "${actual}" != "${expected}" ]]; then
    log_error "Checksum mismatch for ${file}"
    log_error "Expected: ${expected}"
    log_error "Actual:   ${actual}"
    exit 1
  fi
  log_success "Checksum verified for ${file}"
}

download_artifacts() {
  log_step "Downloading source archives"
  pushd "${BUILD_DIR}" >/dev/null
  for spec in "${ARTIFACTS[@]}"; do
    IFS='|' read -r id archive sha strip target toggle urls <<< "${spec}"
    if [[ -n "${toggle}" ]] && ! is_enabled "${toggle}" auto; then
      log_info "${id}: disabled via ${toggle}"
      continue
    fi
    IFS=',' read -r -a url_list <<< "${urls}"
    local success=0
    for url in "${url_list[@]}"; do
      [[ -z "${url}" ]] && continue
      log_info "Downloading ${id} from ${url}"
      if run_logged "download-${id}.log" curl -fsSL --connect-timeout 20 -o "${archive}" "${url}"; then
        success=1
        break
      fi
    done
    if ((success == 0)); then
      log_error "Failed to download ${id} from all sources"
      exit 1
    fi
    verify_checksum "${archive}" "${sha}"
    if [[ "${strip}" == "0" ]]; then
      run_logged "extract-${id}.log" tar xzf "${archive}"
    else
      mkdir -p "${target}"
      run_logged "extract-${id}.log" tar xzf "${archive}" --strip-components="${strip}" -C "${target}"
    fi
    log_success "Prepared ${id}"
  done
  popd >/dev/null
}

detect_openssl_target() {
  case "$(uname -m)" in
    x86_64|amd64) echo "linux-x86_64" ;;
    aarch64|arm64) echo "linux-aarch64" ;;
    armv7l|armv6l|armhf) echo "linux-armv4" ;;
    *) echo "linux-generic64" ;;
  esac
}

build_openssl() {
  log_step "Building OpenSSL ${OPENSSL_VERSION}"
  local src="${BUILD_DIR}/openssl-${OPENSSL_VERSION}"
  local dest="${BUILD_DIR}/openssl-install"
  mkdir -p "${dest}"
  pushd "${src}" >/dev/null
  run_logged openssl-configure.log ./Configure "$(detect_openssl_target)" "--prefix=${dest}" "--openssldir=${dest}/ssl" enable-tls1_3 no-shared no-tests -fPIC -O3
  run_logged openssl-make.log make -j"$(num_procs)"
  run_logged openssl-install.log make install_sw
  mkdir -p "${dest}/ssl"
  cp apps/openssl.cnf "${dest}/ssl/openssl.cnf"
  popd >/dev/null
  log_success "OpenSSL built"
}

build_nginx() {
  log_step "Building NGINX ${NGINX_VERSION}"
  local src="${BUILD_DIR}/nginx-${NGINX_VERSION}"
  pushd "${src}" >/dev/null

  local -a base_args=(
    "--prefix=${PREFIX}"
    "--sbin-path=/usr/sbin/nginx"
    "--conf-path=/etc/nginx/nginx.conf"
    "--http-log-path=/var/log/nginx/access.log"
    "--error-log-path=/var/log/nginx/error.log"
    "--pid-path=/run/nginx.pid"
    "--lock-path=/var/lock/nginx.lock"
    "--with-openssl=${BUILD_DIR}/openssl-${OPENSSL_VERSION}"
    "--with-pcre=${BUILD_DIR}/pcre2-${PCRE2_VERSION}"
    "--with-zlib=${BUILD_DIR}/zlib-${ZLIB_VERSION}"
    "--with-pcre-jit"
    "--with-http_ssl_module"
    "--with-http_v2_module"
    "--with-http_v3_module"
    "--with-http_gzip_static_module"
    "--with-http_stub_status_module"
    "--with-http_realip_module"
    "--with-http_sub_module"
    "--with-http_slice_module"
    "--with-http_secure_link_module"
    "--with-file-aio"
    "--with-threads"
  )

  if is_enabled ENABLE_STREAM auto; then
    base_args+=("--with-stream" "--with-stream_realip_module" "--with-stream_ssl_module" "--with-stream_ssl_preread_module")
  fi

  local -a dynamic_args=("${base_args[@]}" "--modules-path=/etc/nginx/modules")
  local -a static_args=("${base_args[@]}")

  if is_enabled ENABLE_HEADERS_MORE auto && [[ -d "${BUILD_DIR}/headers-more-module" ]]; then
    dynamic_args+=("--add-dynamic-module=${BUILD_DIR}/headers-more-module")
    static_args+=("--add-module=${BUILD_DIR}/headers-more-module")
  fi

  if is_enabled ENABLE_ZSTD auto && [[ -d "${BUILD_DIR}/zstd-module" ]]; then
    dynamic_args+=("--add-dynamic-module=${BUILD_DIR}/zstd-module")
    static_args+=("--add-module=${BUILD_DIR}/zstd-module")
  fi

  local configure_cmd
  if [[ -x ./configure ]]; then
    configure_cmd=("./configure")
  else
    configure_cmd=("/bin/bash" "auto/configure")
  fi

  if ! run_logged nginx-configure.log "${configure_cmd[@]}" "${dynamic_args[@]}"; then
    exit 1
  fi
  if run_logged nginx-build.log make -j"$(num_procs)"; then
    ZSTD_BUILD_MODE="dynamic"
    popd >/dev/null
    log_success "NGINX built"
    return
  fi

  if is_enabled ENABLE_ZSTD auto && grep -qE "recompile with -fPIC|ngx_http_zstd" "${LOG_DIR}/nginx-build.log"; then
    log_warn "Dynamic zstd build failed; retrying statically"
    run_logged nginx-make-clean.log make clean
    if run_logged nginx-configure.log "${configure_cmd[@]}" "${static_args[@]}" && run_logged nginx-build.log make -j"$(num_procs)"; then
      ZSTD_BUILD_MODE="static"
      popd >/dev/null
      log_success "NGINX built (zstd static)"
      return
    fi
  fi

  log_error "NGINX build failed"
  tail -n 80 "${LOG_DIR}/nginx-build.log" || true
  exit 1
}

copy_modules() {
  local src="${BUILD_DIR}/nginx-${NGINX_VERSION}/objs"
  local dest="/etc/nginx/modules"
  mkdir -p "${dest}"
  if find "${src}" -maxdepth 1 -name '*.so' -print -quit | grep -q .; then
    find "${src}" -maxdepth 1 -name '*.so' -exec cp {} "${dest}" \;
    chown root:root "${dest}"/*.so 2>/dev/null || true
    chmod 0644 "${dest}"/*.so 2>/dev/null || true
    log_success "Copied dynamic modules"
  else
    log_warn "No dynamic modules produced"
  fi
}

write_module_loader() {
  local so_path="$1"; local loader_name="$2"
  if [[ ! -f "${so_path}" ]]; then
    log_warn "Module not found: ${so_path}"
    return
  fi
  mkdir -p /etc/nginx/modules.d
  cat > "/etc/nginx/modules.d/${loader_name}" <<EOF
load_module ${so_path};
EOF
  chmod 0644 "/etc/nginx/modules.d/${loader_name}" || true
  log_success "Enabled module loader: ${loader_name}"
}

remove_module_loader() {
  local loader_name="$1"
  rm -f "/etc/nginx/modules.d/${loader_name}" 2>/dev/null || true
}

apply_templates() {
  if declare -F create_main_config >/dev/null 2>&1; then
    create_main_config
  else
    log_warn "create_main_config not found"
  fi
  if declare -F create_config_snippets >/dev/null 2>&1; then
    create_config_snippets
  fi
  if declare -F create_html_files >/dev/null 2>&1; then
    create_html_files
  fi
}

ensure_self_signed_cert() {
  local ssl_dir="/etc/nginx/ssl"
  local crt="${ssl_dir}/localhost.crt"
  local key="${ssl_dir}/localhost.key"
  [[ -f "${crt}" && -f "${key}" ]] && return
  log_step "Generating self-signed certificate"
  mkdir -p "${ssl_dir}"
  local openssl_bin="${BUILD_DIR}/openssl-install/bin/openssl"
  if [[ ! -x "${openssl_bin}" ]]; then
    log_error "OpenSSL binary not found at ${openssl_bin}"
    exit 1
  fi
  run_logged openssl-selfsigned.log "${openssl_bin}" req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "${key}" -out "${crt}" -days 397 -sha256 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"
  chmod 0600 "${key}" || true
  chmod 0644 "${crt}" || true
  log_success "Created self-signed certificate"
}

configure_https_only() {
  ensure_self_signed_cert
  cat > /etc/nginx/conf.d/https-localhost.conf <<'EOF'
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    listen 443 quic reuseport;
    listen [::]:443 quic reuseport;
    http2 on;

    server_name _;
    root /usr/share/nginx/html;

    ssl_certificate     /etc/nginx/ssl/localhost.crt;
    ssl_certificate_key /etc/nginx/ssl/localhost.key;

    include /etc/nginx/snippets/ssl_core.conf;
    include /etc/nginx/snippets/compression.conf;
    include /etc/nginx/snippets/security.conf;
    include /etc/nginx/snippets/http_hardening.snippet;
    include /etc/nginx/snippets/zstd.conf;

    add_header Alt-Svc 'h3=":443"; ma=86400' always;

    location / {
        index index.html index.htm;
    }

    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    location = /50x.html { root /usr/share/nginx/html; }
}
EOF
  chmod 0644 /etc/nginx/conf.d/https-localhost.conf || true
}

install_nginx() {
  log_step "Installing NGINX"
  if ! id nginx &>/dev/null; then
    local nologin="/usr/sbin/nologin"
    [[ -x /sbin/nologin ]] && nologin="/sbin/nologin"
    [[ -x /bin/false ]] && nologin="/bin/false"
    getent group nginx >/dev/null 2>&1 || groupadd --system nginx
    useradd --system --home /var/cache/nginx --no-create-home --shell "${nologin}" --gid nginx nginx
  fi

  mkdir -p /var/cache/nginx/{client_temp,proxy_temp,fastcgi_temp,uwsgi_temp,scgi_temp}
  mkdir -p /var/log/nginx /etc/nginx/{conf.d,snippets,modules,modules.d,stream.d} /usr/share/nginx/html
  touch /var/log/nginx/{error.log,access.log}

  pushd "${BUILD_DIR}/nginx-${NGINX_VERSION}" >/dev/null
  run_logged nginx-install.log make install
  popd >/dev/null

  copy_modules
  chown -R root:nginx /etc/nginx
  chmod -R 775 /etc/nginx
  find /etc/nginx -type f -exec chmod 664 {} + 2>/dev/null || true

  chown -R nginx:nginx /var/log/nginx /var/cache/nginx
  chmod -R 775 /var/log/nginx
  find /var/log/nginx -type f -exec chmod 664 {} + 2>/dev/null || true
  chmod -R 750 /var/cache/nginx || true

  apply_templates

  if is_enabled ENABLE_HEADERS_MORE auto; then
    write_module_loader /etc/nginx/modules/ngx_http_headers_more_filter_module.so headers_more.conf
  else
    remove_module_loader headers_more.conf
  fi

  if is_enabled ENABLE_ZSTD auto; then
    if [[ "${ZSTD_BUILD_MODE}" == "dynamic" ]]; then
      write_module_loader /etc/nginx/modules/ngx_http_zstd_filter_module.so zstd_filter.conf
      write_module_loader /etc/nginx/modules/ngx_http_zstd_static_module.so zstd_static.conf
    else
      log_info "Zstd built statically; loaders not needed"
      remove_module_loader zstd_filter.conf
      remove_module_loader zstd_static.conf
    fi
  else
    remove_module_loader zstd_filter.conf
    remove_module_loader zstd_static.conf
  fi
}

write_systemd_service() {
  if ! has_systemd; then
    log_warn "Systemd not detected; skipping service creation"
    return
  fi
  cat > /etc/systemd/system/${SERVICE_NAME}.service <<'EOF'
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable ${SERVICE_NAME}
  log_success "Systemd service created"
}

test_nginx() {
  log_step "Testing nginx configuration"
  if ! nginx -t &>"${LOG_DIR}/nginx-test.log"; then
    log_error "nginx -t failed"
    cat "${LOG_DIR}/nginx-test.log"
    exit 1
  fi
  if has_systemd; then
    if systemctl is-active --quiet ${SERVICE_NAME}; then
      systemctl reload ${SERVICE_NAME}
    else
      systemctl start ${SERVICE_NAME}
    fi
  else
    if pgrep -f "nginx: master" >/dev/null; then
      /usr/sbin/nginx -s reload
    else
      /usr/sbin/nginx
    fi
  fi
  log_success "nginx configuration valid"
}

show_summary() {
  log_step "Installation summary"
  if command -v nginx &>/dev/null; then
    log_success "$(nginx -v 2>&1)"
    nginx -V 2>&1 | grep 'built with OpenSSL' || true
    if has_systemd; then
      systemctl status ${SERVICE_NAME} --no-pager | head -n 5 || true
    fi
  else
    log_warn "nginx binary not found"
  fi
  log_info "Configs: /etc/nginx"
  log_info "Logs:    /var/log/nginx"
  log_info "Webroot: /usr/share/nginx/html"
  log_info "Backup:  ${BACKUP_DIR}"
}

cmd_install() {
  validate_env
  check_root
  confirm_or_exit "Install NGINX ${NGINX_VERSION}?"
  require_cmds
  backup_existing
  install_dependencies
  download_artifacts
  build_openssl
  build_nginx
  install_nginx
  configure_https_only
  write_systemd_service
  test_nginx
  show_summary
  log_success "NGINX installation complete"
}

cmd_remove() {
  check_root
  confirm_or_exit "Remove NGINX installation?"
  if has_systemd; then
    systemctl stop ${SERVICE_NAME} 2>/dev/null || true
    systemctl disable ${SERVICE_NAME} 2>/dev/null || true
    rm -f /etc/systemd/system/${SERVICE_NAME}.service
    systemctl daemon-reload 2>/dev/null || true
  fi
  rm -rf "${PREFIX}" /usr/sbin/nginx /etc/nginx /var/log/nginx /var/cache/nginx /usr/share/nginx
  userdel nginx 2>/dev/null || true
  log_success "NGINX removed"
  log_info "Backup preserved at ${BACKUP_DIR}"
}

cmd_verify() {
  validate_env
  local issues=0
  if [[ -x /usr/sbin/nginx ]]; then
    log_success "Binary present"
  else
    log_error "Binary missing"
    ((issues++))
  fi
  if nginx -t &>"${LOG_DIR}/nginx-verify.log"; then
    log_success "nginx -t passed"
  else
    log_error "nginx -t failed"
    cat "${LOG_DIR}/nginx-verify.log"
    ((issues++))
  fi
  if has_systemd; then
    systemctl is-active --quiet ${SERVICE_NAME} && log_success "Service active" || log_warn "Service inactive"
  fi
  if ((issues == 0)); then
    log_success "Verification complete"
  else
    exit 1
  fi
}

print_usage() {
  cat <<EOF
Usage: ${0##*/} {install|remove|verify}

Environment overrides:
  CONFIRM=no             Abort automatically without executing
  ENABLE_HEADERS_MORE=0  Disable headers-more module
  ENABLE_ZSTD=0          Disable Zstandard module
  ENABLE_STREAM=0        Disable stream core
  CHECKSUM_POLICY=strict|allow-missing|skip
EOF
}

main() {
  case "${1:-install}" in
    install) cmd_install ;;
    remove)  cmd_remove ;;
    verify)  cmd_verify ;;
    help|-h|--help) print_usage ;;
    *)
      log_error "Unknown command: ${1}"
      print_usage
      exit 1
      ;;
  esac
}

main "$@"
