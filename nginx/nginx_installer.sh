#!/usr/bin/env bash
#
# NGINX Compiler and Installer (Bash)
#
# SYNOPSIS
#     Compile and install NGINX from source with OpenSSL using Bash.
#
# DESCRIPTION
#     This script maintains feature parity with the PowerShell installer while drawing
#     templates from the files stored in the `config` folder beside the script. No
#     configuration values are embedded directly in the script; all nginx configuration
#     and default site files are sourced from those templates.
#

set -euo pipefail

# ============================================================================
# PARAMETER PARSING
# ============================================================================
COMMAND="${1:-install}"

# ============================================================================
# GLOBALS & CONSTANTS
# ============================================================================
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/config"
BUILD_DIR="$(mktemp -d -t nginx-build-XXXXXXXX)"
LOG_DIR="$(mktemp -d -t nginx-logs-XXXXXXXX)"
PREFIX="/usr/local/nginx"
SERVICE_NAME="nginx"
BACKUP_DIR="/root/nginx-backup-$(date +%Y%m%d-%H%M%S)"
CURRENT_STEP=""
ZSTD_BUILD_MODE="dynamic"

# Load configuration from .env file
if [[ -f "${CONFIG_DIR}/.env" ]]; then
    # shellcheck disable=SC1090
    source "${CONFIG_DIR}/.env"
fi

# Note: Config templates are generated inline in set_config_template function
# Only .env is sourced for version/checksum configuration

# Version catalogue (loaded from .env or fallback to defaults)
declare -A VERSIONS=(
    [Nginx]="${NGINX_VERSION:-1.29.2}"
    [OpenSSL]="${OPENSSL_VERSION:-3.6.0}"
    [PCRE2]="${PCRE2_VERSION:-10.47}"
    [Zlib]="${ZLIB_VERSION:-1.3.1}"
    [HeadersMore]="${HEADERS_MORE_VERSION:-0.39}"
    [ZstdModule]="${ZSTD_MODULE_VERSION:-0.1.1}"
)

# Helper function to split URLs from .env
get_url_array() {
    local url_string="$1"
    echo "${url_string}" | tr ',' '\n'
}

# Artifacts array (Id|Archive|Sha256|Strip|Target|Toggle|Urls)
ARTIFACTS=(
    "nginx|nginx-${VERSIONS[Nginx]}.tar.gz|${NGINX_SHA256:-5669e3c29d49bf7f6eb577275b86efe4504cf81af885c58a1ed7d2e7b8492437}|1|nginx-${VERSIONS[Nginx]}||${NGINX_URL:-https://nginx.org/download/nginx-${VERSIONS[Nginx]}.tar.gz,https://github.com/nginx/nginx/archive/refs/tags/release-${VERSIONS[Nginx]}.tar.gz}"
    "openssl|openssl-${VERSIONS[OpenSSL]}.tar.gz|${OPENSSL_SHA256:-b6a5f44b7eb69e3fa35dbf15524405b44837a481d43d81daddde3ff21fcbb8e9}|0|openssl-${VERSIONS[OpenSSL]}||${OPENSSL_URL:-https://www.openssl.org/source/openssl-${VERSIONS[OpenSSL]}.tar.gz,https://github.com/openssl/openssl/releases/download/openssl-${VERSIONS[OpenSSL]}/openssl-${VERSIONS[OpenSSL]}.tar.gz}"
    "pcre2|pcre2-${VERSIONS[PCRE2]}.tar.gz|${PCRE2_SHA256:-c08ae2388ef333e8403e670ad70c0a11f1eed021fd88308d7e02f596fcd9dc16}|0|pcre2-${VERSIONS[PCRE2]}||${PCRE2_URL:-https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${VERSIONS[PCRE2]}/pcre2-${VERSIONS[PCRE2]}.tar.gz}"
    "zlib|zlib-${VERSIONS[Zlib]}.tar.gz|${ZLIB_SHA256:-9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23}|0|zlib-${VERSIONS[Zlib]}||${ZLIB_URL:-https://zlib.net/zlib-${VERSIONS[Zlib]}.tar.gz,https://github.com/madler/zlib/releases/download/v${VERSIONS[Zlib]}/zlib-${VERSIONS[Zlib]}.tar.gz}"
    "headers-more|headers-more.tar.gz|${HEADERS_MORE_SHA256:-dde68d3fa2a9fc7f52e436d2edc53c6d703dcd911283965d889102d3a877c778}|1|headers-more-module|ENABLE_HEADERS_MORE|${HEADERS_MORE_URL:-https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v${VERSIONS[HeadersMore]}.tar.gz}"
    "zstd|zstd-module.tar.gz|${ZSTD_MODULE_SHA256:-707d534f8ca4263ff043066db15eac284632aea875f9fe98c96cea9529e15f41}|1|zstd-module|ENABLE_ZSTD|${ZSTD_MODULE_URL:-https://github.com/tokers/zstd-nginx-module/archive/refs/tags/${VERSIONS[ZstdModule]}.tar.gz}"
)

# ============================================================================
# LOGGING HELPERS
# ============================================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

write_installer_log() {
    local level="$1"
    local message="$2"
    local prefix
    case "${level}" in
        Info)    prefix="${BLUE}[INFO]${NC}" ;;
        Success) prefix="${GREEN}[OK]${NC}" ;;
        Error)   prefix="${RED}[ERR]${NC}" ;;
        Warn)    prefix="${YELLOW}[WARN]${NC}" ;;
        Step)    prefix="${PURPLE}[STEP]${NC}" ;;
    esac
    [[ "${level}" == "Step" ]] && CURRENT_STEP="${message}"
    echo -e "${prefix} ${message}"
}

write_info()    { write_installer_log "Info" "$1"; }
write_warn()    { write_installer_log "Warn" "$1"; }
write_error_log() { write_installer_log "Error" "$1" >&2; }
write_step()    { write_installer_log "Step" "$1"; }
write_success() { write_installer_log "Success" "$1"; }

# Error handler
on_script_error() {
    local exit_code=$?
    if [[ ${exit_code} -ne 0 ]]; then
        write_error_log "An error occurred (exit=${exit_code}) during step: ${CURRENT_STEP:-unknown}"
        write_info "Log directory: ${LOG_DIR}"
    fi
}

trap on_script_error ERR

# ============================================================================
# UTILITY HELPERS
# ============================================================================
test_is_root() {
    [[ ${EUID} -eq 0 ]]
}

assert_root_privilege() {
    if ! test_is_root; then
        echo "This installer must be run with administrative privileges (root)" >&2
        exit 1
    fi
}

get_env_value() {
    local name="$1"
    echo "${!name:-}"
}

get_env_toggle() {
    local name="$1"
    local default="${2:-auto}"
    local value="${!name:-${default}}"
    case "${value,,}" in
        0|no|false|off|disable|disabled) return 1 ;;
        auto|yes|true|on|enable|enabled|1) return 0 ;;
        *)
            echo "Invalid value '${value}' for ${name}. Valid: yes/no/true/false/on/off/auto" >&2
            exit 1
            ;;
    esac
}

get_checksum_policy() {
    local policy="${CHECKSUM_POLICY:-strict}"
    case "${policy,,}" in
        strict|allow-missing|skip) echo "${policy,,}" ;;
        *)
            echo "Invalid CHECKSUM_POLICY '${policy}'. Use strict, allow-missing, or skip." >&2
            exit 1
            ;;
    esac
}

confirm_action() {
    local prompt="$1"
    local env_var="${2:-CONFIRM}"
    local env_confirm="${!env_var:-yes}"
    local decision="${env_confirm,,}"
    case "${decision}" in
        yes|y|true|1|auto|continue|proceed)
            write_info "Auto-confirmed: ${prompt} (${env_var}=${decision})"
            return 0
            ;;
        no|n|false|0|stop|abort|cancel)
            write_warn "Operation cancelled via ${env_var}=${decision}"
            return 1
            ;;
        *)
            write_info "Auto-confirmed: ${prompt} (${env_var}=${decision})"
            return 0
            ;;
    esac
}

get_processor_count() {
    getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 2
}

test_systemd() {
    command -v systemctl &>/dev/null && [[ -d /run/systemd/system ]]
}

get_primary_ip_address() {
    local ip
    if ip=$(hostname -I 2>/dev/null | awk '{print $1}'); then
        [[ -n "${ip}" ]] && echo "${ip}" && return
    fi
    if ip=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1); then
        [[ -n "${ip}" ]] && echo "${ip}" && return
    fi
    echo "unknown"
}

get_log_file_path() {
    local name="$1"
    echo "${LOG_DIR}/${name}"
}

invoke_logged_process() {
    local log_name="$1"; shift
    local log_path
    log_path="$(get_log_file_path "${log_name}")"
    if ! "$@" >"${log_path}" 2>&1; then
        echo "Command '$*' failed. See log: ${log_path}" >&2
        exit 1
    fi
    echo "${log_path}"
}

invoke_command_with_shell() {
    local command="$1"
    local working_directory="${2:-}"
    local log_name="$3"
    local log_path
    log_path="$(get_log_file_path "${log_name}")"

    if [[ -n "${working_directory}" ]]; then
        pushd "${working_directory}" >/dev/null
    fi

    if ! bash -lc "${command}" >"${log_path}" 2>&1; then
        [[ -n "${working_directory}" ]] && popd >/dev/null
        echo "Shell command failed. See log: ${log_path}" >&2
        exit 1
    fi

    [[ -n "${working_directory}" ]] && popd >/dev/null
    echo "${log_path}"
}

set_config_template() {
    local enable_stream="$1"
    local enable_zstd="$2"

    write_step "Applying configuration templates"

    # Create main nginx.conf
    local stream_block=""
    if [[ ${enable_stream} -eq 1 ]]; then
        stream_block='
# TCP/UDP stream (optional)
stream {
    include /etc/nginx/stream.d/*.conf;
}'
    fi

    cat > /etc/nginx/nginx.conf << EOF
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /run/nginx.pid;

# Load dynamic modules when present/enabled
include /etc/nginx/modules.d/*.conf;

events {
    worker_connections 1024;
    use epoll;
}

http {
    # Hide NGINX version on error pages
    server_tokens off;

    include /etc/nginx/mime.types;

    # Pull in modular HTTP snippets (core, security, compression, TLS, etc.)
    include /etc/nginx/snippets/*.conf;

    # Site-specific vhosts belong in conf.d (kept empty by this installer)
    include /etc/nginx/conf.d/*.conf;
}
${stream_block}
EOF
    chmod 0644 /etc/nginx/nginx.conf 2>/dev/null || true
    write_success "Created main nginx.conf"

    # Create configuration snippets
    mkdir -p /etc/nginx/snippets

    cat > /etc/nginx/snippets/common.conf << 'EOF'
# Common HTTP core settings
default_type application/octet-stream;

log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                '$status $body_bytes_sent "$http_referer" '
                '"$http_user_agent" "$http_x_forwarded_for"';

access_log /var/log/nginx/access.log main;

sendfile on;
tcp_nopush on;
tcp_nodelay on;
keepalive_timeout 65;
EOF

    cat > /etc/nginx/snippets/security.conf << 'EOF'
# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;

# Completely remove the Server header
# This requires the headers-more module, which is enabled by default
more_clear_headers "Server";
EOF

    cat > /etc/nginx/snippets/ssl_core.conf << 'EOF'
# Core SSL/TLS settings (modern)
# TLS 1.3 only to avoid legacy/weak ciphers; TLSv1.3 cipher suites are chosen by OpenSSL
ssl_protocols TLSv1.3;

# Prefer modern curves for key exchange; X25519 first, fallback to secp384r1
# Note: ssl_conf_command requires OpenSSL 1.1.1+
ssl_conf_command Curves X25519:secp384r1;

ssl_session_cache shared:SSL:50m;
ssl_session_timeout 1d;
EOF

    cat > /etc/nginx/snippets/compression.conf << 'EOF'
# Gzip compression (fallback)
gzip on;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_types text/plain text/css text/xml application/json application/javascript \
           application/xml+rss application/atom+xml image/svg+xml;
EOF

    cat > /etc/nginx/snippets/zstd.conf << 'EOF'
# Enabled only when the zstd module is present
zstd on;
zstd_comp_level 7;
zstd_types text/plain text/css text_xml application/json application/javascript \
           application/xml+rss application/atom+xml image/svg+xml;
EOF

    cat > /etc/nginx/snippets/http_hardening.snippet << 'EOF'
# Block HTTP/1.0 and HTTP/1.1
# Return 444 (Connection Closed Without Response) if not HTTP/2 or HTTP/3
if ($server_protocol ~* "HTTP/1") {
    return 444;
}
EOF

    chmod 0644 /etc/nginx/snippets/*.conf /etc/nginx/snippets/*.snippet 2>/dev/null || true
    write_success "Created configuration snippets"

    # Create HTML files
    mkdir -p /usr/share/nginx/html

    cat > /usr/share/nginx/html/index.html << 'EOF'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Welcome to NGINX</title>
    <style>
        body {
            font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, sans-serif;
            margin: 0;
            background: #f7f9fb;
            color: #111;
        }
        header {
            background: linear-gradient(135deg, #009639, #00b36b);
            color: #fff;
            padding: 20px;
        }
        main {
            max-width: 900px;
            margin: 32px auto;
            padding: 0 16px;
        }
        code {
            background: #eef4f1;
            border-radius: 4px;
            padding: 2px 6px;
        }
        section {
            background: #fff;
            border: 1px solid #e5ece8;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 16px;
            box-shadow: 0 2px 4px rgba(0,0,0,.04);
        }
    </style>
</head>
<body>
    <header>
        <h1 style="margin:0">NGINX installed</h1>
    </header>
    <main>
        <section>
            <p>If you see this page, your server is running and serving content.</p>
            <ul>
                <li>Root: <code>/usr/share/nginx/html</code></li>
                <li>Config: <code>/etc/nginx/nginx.conf</code></li>
                <li>Snippets: <code>/etc/nginx/snippets/</code></li>
                <li>Sites: <code>/etc/nginx/conf.d/</code></li>
            </ul>
            <p>Reload with: <code>nginx -s reload</code></p>
            <p>Features: HTTP/3, TLS 1.3, optimized build</p>
        </section>
    </main>
</body>
</html>
EOF

    cat > /usr/share/nginx/html/404.html << 'EOF'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>404 Not Found</title>
    <style>
        body {
            font-family: system-ui, sans-serif;
            display: grid;
            place-items: center;
            min-height: 100vh;
            background: #f7f9fb;
        }
        main {
            background: #fff;
            border: 1px solid #e5ece8;
            border-radius: 10px;
            padding: 24px 28px;
            box-shadow: 0 2px 4px rgba(0,0,0,.04);
            text-align: center;
        }
    </style>
</head>
<body>
    <main>
        <h1 style="margin:0 0 8px;color:#c1121f">404</h1>
        <p>The requested resource could not be found.</p>
        <p><a href="/" style="color:#009639;text-decoration:none">Go to homepage</a></p>
    </main>
</body>
</html>
EOF

    cat > /usr/share/nginx/html/50x.html << 'EOF'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Server error</title>
    <style>
        body {
            font-family: system-ui, sans-serif;
            display: grid;
            place-items: center;
            min-height: 100vh;
            background: #f7f9fb;
        }
        main {
            background: #fff;
            border: 1px solid #e5ece8;
            border-radius: 10px;
            padding: 24px 28px;
            box-shadow: 0 2px 4px rgba(0,0,0,.04);
            text-align: center;
        }
    </style>
</head>
<body>
    <main>
        <h1 style="margin:0 0 8px;color:#b08900">Something went wrong</h1>
        <p>A temporary error occurred while processing your request.</p>
        <p>Please try again later.</p>
    </main>
</body>
</html>
EOF

    chmod 0644 /usr/share/nginx/html/*.html 2>/dev/null || true
    write_success "Created HTML files"
}

write_module_loader() {
    local module_path="$1"
    local loader_name="$2"
    local loader_dir="/etc/nginx/modules.d"

    mkdir -p "${loader_dir}"

    local loader_path="${loader_dir}/${loader_name}"
    local resolved_path
    if [[ "${module_path}" =~ ^/ ]]; then
        resolved_path="${module_path}"
    else
        resolved_path="/etc/nginx/${module_path}"
    fi

    echo "load_module ${resolved_path};" > "${loader_path}"
    chmod 0644 "${loader_path}" 2>/dev/null || true
    write_info "Module loader written: ${loader_path}"
}

remove_module_loader() {
    local loader_name="$1"
    local loader_path="/etc/nginx/modules.d/${loader_name}"
    if [[ -f "${loader_path}" ]]; then
        rm -f "${loader_path}"
        write_info "Removed module loader: ${loader_path}"
    fi
}

# ============================================================================
# CORE TASKS
# ============================================================================
install_build_dependency() {
    write_step "Installing build dependencies"
    local log_prefix="deps"
    export DEBIAN_FRONTEND=noninteractive

    if command -v apt-get &>/dev/null; then
        invoke_command_with_shell "apt-get update -qq" "" "${log_prefix}-install.log"
        local packages="build-essential libpcre2-dev zlib1g-dev perl curl gcc make hostname zstd libzstd-dev pkg-config"
        invoke_command_with_shell "apt-get install -y ${packages}" "" "${log_prefix}-packages.log"
    elif command -v dnf &>/dev/null; then
        local dnf_version
        dnf_version=$(dnf --version 2>/dev/null)
        if [[ "${dnf_version}" =~ dnf5 ]]; then
            invoke_command_with_shell "dnf install -y @development-tools" "" "${log_prefix}-install.log"
        else
            invoke_command_with_shell "dnf groupinstall -y \"Development Tools\"" "" "${log_prefix}-install.log"
        fi
        local packages="pcre2-devel zlib-devel perl curl gcc make hostname zstd libzstd libzstd-devel pkgconfig pkgconf-pkg-config"
        invoke_command_with_shell "dnf install -y ${packages}" "" "${log_prefix}-packages.log"
    elif command -v yum &>/dev/null; then
        invoke_command_with_shell "yum groupinstall -y \"Development Tools\"" "" "${log_prefix}-install.log"
        local packages="pcre2-devel zlib-devel perl curl gcc make hostname zstd libzstd libzstd-devel pkgconfig pkgconf-pkg-config"
        invoke_command_with_shell "yum install -y ${packages}" "" "${log_prefix}-packages.log"
    else
        echo "Unsupported package manager. Install dependencies manually (apt, dnf, or yum required)." >&2
        exit 1
    fi

    write_success "Build dependencies installed"
}

test_checksum() {
    local file_path="$1"
    local expected="$2"
    local policy="$3"

    if [[ "${policy}" == "skip" ]]; then
        write_warn "Checksum verification skipped for $(basename "${file_path}")"
        return
    fi

    if [[ -z "${expected}" ]]; then
        if [[ "${policy}" == "strict" ]]; then
            echo "Checksum missing for $(basename "${file_path}")" >&2
            exit 1
        fi
        write_warn "No checksum provided for $(basename "${file_path}"); continuing due to policy ${policy}"
        return
    fi

    local hash
    if command -v sha256sum &>/dev/null; then
        hash=$(sha256sum "${file_path}" | awk '{print $1}')
    else
        hash=$(shasum -a 256 "${file_path}" | awk '{print $1}')
    fi

    if [[ "${hash,,}" != "${expected,,}" ]]; then
        echo "Checksum mismatch for $(basename "${file_path}"). Expected ${expected}, got ${hash}" >&2
        exit 1
    fi

    write_success "Checksum verified for $(basename "${file_path}")"
}

invoke_download_artifact() {
    local policy
    policy="$(get_checksum_policy)"

    write_step "Downloading source archives"
    pushd "${BUILD_DIR}" >/dev/null

    for spec in "${ARTIFACTS[@]}"; do
        IFS='|' read -r id archive sha256 strip target toggle urls <<< "${spec}"

        if [[ -n "${toggle}" ]]; then
            if ! get_env_toggle "${toggle}" "auto"; then
                write_info "${id}: disabled via ${toggle}; skipping download"
                continue
            fi
        fi

        local success=0
        local archive_path="${BUILD_DIR}/${archive}"
        IFS=',' read -ra url_list <<< "${urls}"

        for url in "${url_list[@]}"; do
            [[ -z "${url}" ]] && continue
            write_info "Downloading ${id} from ${url}"
            if curl -fsSL --connect-timeout 20 -o "${archive_path}" "${url}" 2>&1 | tee "$(get_log_file_path "download-${id}.log")" >/dev/null; then
                success=1
                break
            fi
            write_warn "Download failed from ${url}"
        done

        if [[ ${success} -eq 0 ]]; then
            echo "All download sources failed for ${id}" >&2
            exit 1
        fi

        test_checksum "${archive_path}" "${sha256}" "${policy}"

        if [[ "${strip}" == "0" ]]; then
            invoke_logged_process "extract-${id}.log" tar xzf "${archive}"
        else
            mkdir -p "${target}"
            invoke_logged_process "extract-${id}.log" tar xzf "${archive}" --strip-components="${strip}" -C "${target}"
        fi

        write_success "Downloaded ${id}"
    done

    popd >/dev/null
}

build_openssl() {
    write_step "Building OpenSSL ${VERSIONS[OpenSSL]}"
    local source_dir="${BUILD_DIR}/openssl-${VERSIONS[OpenSSL]}"
    local install_dir="${BUILD_DIR}/openssl-install"
    mkdir -p "${install_dir}"

    pushd "${source_dir}" >/dev/null

    local target
    case "$(uname -m)" in
        x86_64|amd64) target="linux-x86_64" ;;
        aarch64|arm64) target="linux-aarch64" ;;
        armv7l|armv6l) target="linux-armv4" ;;
        *) target="linux-generic64" ;;
    esac

    invoke_logged_process "openssl-configure.log" \
        ./Configure "${target}" \
        "--prefix=${install_dir}" \
        "--openssldir=${install_dir}/ssl" \
        "enable-tls1_3" "no-shared" "no-tests" "-fPIC" "-O3"

    invoke_logged_process "openssl-make.log" make -j"$(get_processor_count)"
    invoke_logged_process "openssl-install.log" make install_sw

    mkdir -p "${install_dir}/ssl"
    cp apps/openssl.cnf "${install_dir}/ssl/openssl.cnf"

    popd >/dev/null
    write_success "OpenSSL built successfully"
}

build_nginx() {
    write_step "Building NGINX ${VERSIONS[Nginx]}"
    local source_dir="${BUILD_DIR}/nginx-${VERSIONS[Nginx]}"
    pushd "${source_dir}" >/dev/null

    local openssl_source="${BUILD_DIR}/openssl-${VERSIONS[OpenSSL]}"
    local pcre2_dir="${BUILD_DIR}/pcre2-${VERSIONS[PCRE2]}"
    local zlib_dir="${BUILD_DIR}/zlib-${VERSIONS[Zlib]}"
    local headers_dir="${BUILD_DIR}/headers-more-module"
    local zstd_dir="${BUILD_DIR}/zstd-module"

    local enable_headers enable_zstd enable_stream
    get_env_toggle "ENABLE_HEADERS_MORE" "auto" && enable_headers=1 || enable_headers=0
    get_env_toggle "ENABLE_ZSTD" "auto" && enable_zstd=1 || enable_zstd=0
    get_env_toggle "ENABLE_STREAM" "auto" && enable_stream=1 || enable_stream=0

    local -a common_args=(
        "--prefix=${PREFIX}"
        "--sbin-path=/usr/sbin/nginx"
        "--conf-path=/etc/nginx/nginx.conf"
        "--pid-path=/run/nginx.pid"
        "--lock-path=/var/lock/nginx.lock"
        "--http-log-path=/var/log/nginx/access.log"
        "--error-log-path=/var/log/nginx/error.log"
        "--with-pcre=${pcre2_dir}"
        "--with-zlib=${zlib_dir}"
        "--with-openssl=${openssl_source}"
        "--with-http_ssl_module"
        "--with-http_v2_module"
        "--with-http_v3_module"
        "--with-http_gzip_static_module"
        "--with-http_stub_status_module"
        "--with-http_realip_module"
        "--with-http_sub_module"
        "--with-http_slice_module"
        "--with-pcre-jit"
        "--with-threads"
        "--with-file-aio"
        "--with-http_secure_link_module"
    )

    if [[ ${enable_stream} -eq 1 ]]; then
        common_args+=(
            "--with-stream"
            "--with-stream_realip_module"
            "--with-stream_ssl_module"
            "--with-stream_ssl_preread_module"
        )
    fi

    local -a dynamic_args=("${common_args[@]}" "--modules-path=/etc/nginx/modules")
    if [[ ${enable_headers} -eq 1 && -d "${headers_dir}" ]]; then
        dynamic_args+=("--add-dynamic-module=${headers_dir}")
    fi
    if [[ ${enable_zstd} -eq 1 && -d "${zstd_dir}" ]]; then
        dynamic_args+=("--add-dynamic-module=${zstd_dir}")
    fi

    local -a static_args=("${common_args[@]}")
    if [[ ${enable_headers} -eq 1 && -d "${headers_dir}" ]]; then
        static_args+=("--add-module=${headers_dir}")
    fi
    if [[ ${enable_zstd} -eq 1 && -d "${zstd_dir}" ]]; then
        static_args+=("--add-module=${zstd_dir}")
    fi

    local configure_script
    if [[ -x ./configure ]]; then
        configure_script="./configure"
    elif [[ -f auto/configure ]]; then
        configure_script="bash auto/configure"
    else
        echo "Unable to locate nginx configure script" >&2
        exit 1
    fi

    # Try dynamic build first
    if ${configure_script} "${dynamic_args[@]}" >"$(get_log_file_path "nginx-configure.log")" 2>&1; then
        if make -j"$(get_processor_count)" >"$(get_log_file_path "nginx-build.log")" 2>&1; then
            ZSTD_BUILD_MODE="dynamic"
            popd >/dev/null
            write_success "NGINX built successfully"
            return
        fi
    fi

    # Fallback to static if dynamic fails (usually due to zstd)
    local log_content
    log_content=$(cat "$(get_log_file_path "nginx-build.log")" 2>/dev/null || true)
    if [[ ${enable_zstd} -eq 1 && ( "${log_content}" =~ "recompile with -fPIC" || "${log_content}" =~ "ngx_http_zstd" ) ]]; then
        write_warn "Dynamic zstd build failed; retrying with static module"
        invoke_logged_process "nginx-make-clean.log" make clean
        ${configure_script} "${static_args[@]}" >"$(get_log_file_path "nginx-configure.log")" 2>&1
        if make -j"$(get_processor_count)" >"$(get_log_file_path "nginx-build.log")" 2>&1; then
            ZSTD_BUILD_MODE="static"
            popd >/dev/null
            write_success "NGINX built successfully"
            return
        fi
    fi

    echo "NGINX build failed" >&2
    exit 1
}

initialize_nginx_user() {
    if ! command -v useradd &>/dev/null; then
        return
    fi

    if id nginx &>/dev/null 2>&1; then
        return
    fi

    local nologin
    if [[ -x /usr/sbin/nologin ]]; then
        nologin="/usr/sbin/nologin"
    elif [[ -x /sbin/nologin ]]; then
        nologin="/sbin/nologin"
    else
        nologin="/bin/false"
    fi

    getent group nginx &>/dev/null || groupadd --system nginx
    useradd --system --home /var/cache/nginx --no-create-home --shell "${nologin}" --gid nginx --comment "nginx user" nginx
    write_info "Created nginx system user"
}

copy_dynamic_module() {
    local objs="${BUILD_DIR}/nginx-${VERSIONS[Nginx]}/objs"
    local modules_dir="/etc/nginx/modules"

    mkdir -p "${modules_dir}"

    if [[ -d "${objs}" ]]; then
        find "${objs}" -maxdepth 1 -name '*.so' -exec cp {} "${modules_dir}/" \; 2>/dev/null || true
    fi

    if ! find "${modules_dir}" -maxdepth 1 -name '*.so' -print -quit | grep -q .; then
        write_warn "No dynamic modules were produced."
    else
        chown root:root "${modules_dir}"/*.so 2>/dev/null || true
        chmod 0644 "${modules_dir}"/*.so 2>/dev/null || true
        write_success "Dynamic modules copied to ${modules_dir}"
    fi

    local legacy_modules_dir="${PREFIX}/modules"
    if [[ -d "${legacy_modules_dir}" ]]; then
        rm -rf "${legacy_modules_dir}" 2>/dev/null || true
        write_info "Removed legacy module directory: ${legacy_modules_dir}"
    fi
}

install_nginx() {
    write_step "Installing NGINX"
    initialize_nginx_user

    local dirs=(
        "/var/cache/nginx/client_temp"
        "/var/cache/nginx/proxy_temp"
        "/var/cache/nginx/fastcgi_temp"
        "/var/cache/nginx/uwsgi_temp"
        "/var/cache/nginx/scgi_temp"
        "/var/log/nginx"
        "/etc/nginx/conf.d"
        "/etc/nginx/snippets"
        "/etc/nginx/stream.d"
    )

    for dir in "${dirs[@]}"; do
        mkdir -p "${dir}"
    done

    touch /var/log/nginx/error.log /var/log/nginx/access.log

    pushd "${BUILD_DIR}/nginx-${VERSIONS[Nginx]}" >/dev/null
    invoke_logged_process "nginx-install.log" make install
    popd >/dev/null

    copy_dynamic_module

    chown -R root:nginx /etc/nginx 2>/dev/null || true
    chmod -R 775 /etc/nginx 2>/dev/null || true
    find /etc/nginx -type f -exec chmod 664 {} + 2>/dev/null || true

    chown -R nginx:nginx /var/log/nginx /var/cache/nginx 2>/dev/null || true
    chmod -R 775 /var/log/nginx 2>/dev/null || true
    find /var/log/nginx -type f -exec chmod 664 {} + 2>/dev/null || true
    chmod -R 750 /var/cache/nginx 2>/dev/null || true

    write_success "NGINX files installed"
}

backup_existing_install() {
    write_step "Creating backup of any existing installation"
    mkdir -p "${BACKUP_DIR}"

    [[ -d /etc/nginx ]] && cp -a /etc/nginx "${BACKUP_DIR}/" 2>/dev/null || true
    [[ -f /usr/sbin/nginx ]] && cp /usr/sbin/nginx "${BACKUP_DIR}/nginx.sbin" 2>/dev/null || true

    if test_systemd; then
        if systemctl is-active --quiet nginx 2>/dev/null; then
            echo "nginx was active" > "${BACKUP_DIR}/service_status.txt"
        else
            echo "nginx was inactive" > "${BACKUP_DIR}/service_status.txt"
        fi
    fi

    write_success "Backup stored at ${BACKUP_DIR}"
}

write_systemd_service() {
    if ! test_systemd; then
        write_warn "Systemd not detected; skipping service creation."
        return
    fi

    local service_path="/etc/systemd/system/${SERVICE_NAME}.service"
    cat > "${service_path}" <<'EOF'
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

    systemctl daemon-reload 2>/dev/null || true
    systemctl enable "${SERVICE_NAME}" 2>/dev/null || true
    write_success "Systemd service created and enabled"
}

new_self_signed_cert_if_missing() {
    write_step "Ensuring self-signed certificate"
    local ssl_dir="/etc/nginx/ssl"
    local crt="${ssl_dir}/localhost.crt"
    local key="${ssl_dir}/localhost.key"

    if [[ -f "${crt}" && -f "${key}" ]]; then
        write_info "Self-signed certificate already exists: ${crt}"
        return
    fi

    local openssl_bin="${BUILD_DIR}/openssl-install/bin/openssl"
    if [[ ! -x "${openssl_bin}" ]]; then
        echo "OpenSSL binary not found at ${openssl_bin}" >&2
        exit 1
    fi

    mkdir -p "${ssl_dir}"
    invoke_logged_process "openssl-selfsigned.log" \
        "${openssl_bin}" req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "${key}" -out "${crt}" -days 397 -sha256 \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"

    chmod 0600 "${key}" 2>/dev/null || true
    chmod 0644 "${crt}" 2>/dev/null || true
    write_success "Created self-signed cert: ${crt}"
}

set_https_only_config() {
    write_step "Configuring HTTPS-only default server"
    new_self_signed_cert_if_missing

    local https_conf="/etc/nginx/conf.d/https-localhost.conf"
    cat > "${https_conf}" <<'EOF'
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
    include /etc/nginx/snippets/zstd.conf;
    include /etc/nginx/snippets/http_hardening.snippet;
    add_header Alt-Svc 'h3=":443"; ma=86400' always;
    location / {
        index index.html index.htm;
    }
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    location = /50x.html { root /usr/share/nginx/html; }
}
EOF
    chmod 0644 "${https_conf}" 2>/dev/null || true
}

test_nginx_configuration() {
    write_step "Testing NGINX configuration"
    mkdir -p /var/log/nginx
    touch /var/log/nginx/error.log /var/log/nginx/access.log
    chown -R nginx:nginx /var/log/nginx 2>/dev/null || true

    if ! nginx -t &>"$(get_log_file_path "nginx-test.log")"; then
        write_error_log "NGINX configuration test failed"
        cat "$(get_log_file_path "nginx-test.log")"
        exit 1
    fi

    write_success "NGINX configuration syntax is valid"

    if test_systemd; then
        if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
            systemctl reload "${SERVICE_NAME}"
            write_success "NGINX service reloaded"
        else
            systemctl start "${SERVICE_NAME}"
            write_success "NGINX service started via systemd"
        fi
    else
        if pgrep -f "nginx: master process" >/dev/null 2>&1; then
            /usr/sbin/nginx -s reload
            write_success "NGINX process reloaded"
        else
            /usr/sbin/nginx
            write_success "NGINX process started"
        fi
    fi
}

show_installation_summary() {
    echo ""
    echo "Installation Summary"
    echo "--------------------------------------------------------------------------"

    if command -v nginx &>/dev/null; then
        local nginx_version
        nginx_version=$(nginx -v 2>&1)
        local openssl_info
        openssl_info=$(nginx -V 2>&1 | grep "built with OpenSSL" || true)

        write_success "NGINX installed: ${nginx_version}"
        [[ -n "${openssl_info}" ]] && write_success "OpenSSL integration: ${openssl_info}"

        if test_systemd; then
            local active
            active=$(systemctl is-active "${SERVICE_NAME}" 2>/dev/null || echo "inactive")
            if [[ "${active}" == "active" ]]; then
                write_success "NGINX service is running"
            else
                write_warn "NGINX service not running"
            fi
        fi
    else
        write_error_log "NGINX binary not found; installation may have failed."
    fi

    echo ""
    echo "Service management:"
    if test_systemd; then
        echo "  sudo systemctl start nginx"
        echo "  sudo systemctl stop nginx"
        echo "  sudo systemctl reload nginx"
    else
        echo "  sudo /usr/sbin/nginx"
        echo "  sudo /usr/sbin/nginx -s reload"
    fi

    echo ""
    echo "Config directory: /etc/nginx"
    echo "Document root:  /usr/share/nginx/html"
    echo "Logs:           /var/log/nginx"
    echo "Backup:         ${BACKUP_DIR}"
    echo "Primary IP:     $(get_primary_ip_address)"
    echo ""
}

remove_nginx_install() {
    write_step "Removing NGINX"

    if test_systemd; then
        systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
        systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
        [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]] && \
            rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        systemctl daemon-reload 2>/dev/null || true
    fi

    local paths=(
        "${PREFIX}"
        "/usr/sbin/nginx"
        "/etc/nginx"
        "/var/log/nginx"
        "/var/cache/nginx"
        "/usr/share/nginx"
    )

    for path in "${paths[@]}"; do
        [[ -e "${path}" ]] && rm -rf "${path}" 2>/dev/null || true
    done

    userdel nginx 2>/dev/null || true
    write_success "NGINX removed"
}

test_nginx_install() {
    write_step "Verifying existing installation"
    local issues=0

    if [[ -x /usr/sbin/nginx ]]; then
        write_success "Binary found: /usr/sbin/nginx"
    else
        write_error_log "NGINX binary missing"
        ((issues++))
    fi

    if [[ -f /etc/nginx/nginx.conf ]]; then
        write_success "nginx.conf present"
        if nginx -t &>"$(get_log_file_path "nginx-verify.log")"; then
            write_success "nginx -t succeeded"
        else
            write_error_log "nginx -t failed"
            cat "$(get_log_file_path "nginx-verify.log")"
            ((issues++))
        fi
    else
        write_error_log "nginx.conf missing"
        ((issues++))
    fi

    if test_systemd; then
        if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
            write_success "Service running"
        else
            write_warn "Service not running"
        fi

        if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
            write_success "Service enabled"
        else
            write_warn "Service not enabled"
        fi
    fi

    if [[ ${issues} -eq 0 ]]; then
        write_success "Verification passed"
    else
        echo "Verification detected ${issues} issue(s)." >&2
        exit 1
    fi
}

invoke_install() {
    assert_root_privilege
    if ! confirm_action "Proceed with NGINX installation?" "CONFIRM"; then
        return
    fi

    backup_existing_install
    install_build_dependency
    invoke_download_artifact
    build_openssl
    build_nginx
    install_nginx

    local enable_stream enable_zstd
    get_env_toggle "ENABLE_STREAM" "auto" && enable_stream=1 || enable_stream=0
    get_env_toggle "ENABLE_ZSTD" "auto" && enable_zstd=1 || enable_zstd=0

    set_config_template "${enable_stream}" "${enable_zstd}"

    if [[ ${enable_zstd} -eq 1 ]]; then
        write_module_loader "modules/ngx_http_zstd_filter_module.so" "zstd_filter.conf"
        if [[ "${ZSTD_BUILD_MODE}" == "dynamic" ]]; then
            write_module_loader "modules/ngx_http_zstd_static_module.so" "zstd_static.conf"
        fi
    else
        remove_module_loader "zstd_filter.conf"
        remove_module_loader "zstd_static.conf"
    fi

    if get_env_toggle "ENABLE_HEADERS_MORE" "auto"; then
        write_module_loader "modules/ngx_http_headers_more_filter_module.so" "headers_more.conf"
    else
        remove_module_loader "headers_more.conf"
    fi

    write_systemd_service
    set_https_only_config
    test_nginx_configuration
    show_installation_summary
    write_success "NGINX installation completed"
}

invoke_remove() {
    assert_root_privilege
    if ! confirm_action "Remove NGINX installation?" "CONFIRM"; then
        return
    fi

    remove_nginx_install
    write_warn "Configuration backup located at ${BACKUP_DIR}"
}

invoke_verify() {
    test_nginx_install
}

# ============================================================================
# CLEANUP
# ============================================================================
remove_installer_temp_data() {
    [[ -d "${BUILD_DIR}" ]] && rm -rf "${BUILD_DIR}" 2>/dev/null || true
    [[ -d "${LOG_DIR}" ]] && rm -rf "${LOG_DIR}" 2>/dev/null || true
}

# ============================================================================
# ENTRY POINT
# ============================================================================
FAILURE_OCCURRED=0

cleanup_on_exit() {
    local exit_code=$?
    if [[ ${exit_code} -ne 0 ]]; then
        FAILURE_OCCURRED=1
    fi

    if [[ ${FAILURE_OCCURRED} -eq 1 ]]; then
        write_warn "Logs preserved in ${LOG_DIR}"
    else
        remove_installer_temp_data
    fi
}

trap cleanup_on_exit EXIT

main() {
    case "${COMMAND,,}" in
        install)
            invoke_install
            ;;
        remove)
            invoke_remove
            ;;
        verify)
            invoke_verify
            ;;
        help|-h|--help)
            cat <<EOF

NGINX Compiler and Installer
Usage: ./nginx_installer.sh {install|remove|verify}

Environment variables:
  CONFIRM=no               # Abort automatically without executing
  ENABLE_HEADERS_MORE=1|0  # Enable headers-more module
  ENABLE_ZSTD=1|0          # Enable Zstandard module
  ENABLE_STREAM=1|0        # Enable stream core
  CHECKSUM_POLICY=strict|allow-missing|skip

EOF
            ;;
        *)
            echo "Unknown command: ${COMMAND}" >&2
            echo "Usage: ./nginx_installer.sh {install|remove|verify|help}" >&2
            exit 1
            ;;
    esac
}

main
