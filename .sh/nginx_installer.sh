#!/usr/bin/env bash
#########################################################################
# NGINX Compiler and Installer
# 
# This script compiles and installs NGINX with OpenSSL from source
# 
# NGINX releases repository: https://github.com/nginx/nginx/releases
# 
# Version information:
# - 1.29.x: mainline branch (newer features, less stable) - this installer is using 1.29.1
# - 1.28.x: stable branch (recommended for production)    - not used in this script 
# 
# OpenSSL releases repository: https://github.com/openssl/openssl/releases
# - Latest stable: 3.5.2
# 
# This script downloads source code, verifies checksums, compiles, and
# installs NGINX with the latest OpenSSL for HTTP/3 support.
#########################################################################

# Environment variables (configure behavior)
# -------------------------------------------------------------
# CONFIRM=yes
#   Non-interactive confirmation for install/remove steps.
# FORCE_SSH_INSTALL=1
#   Allow running install over SSH without interactive safeguards.
# ENABLE_HEADERS_MORE=1|0|yes|no (default: auto/on)
#   Build and enable the headers-more dynamic module.
# ENABLE_ZSTD=1|0|yes|no (default: auto/on)
#   Build and enable the Zstandard dynamic modules and conf.
# ENABLE_STREAM=1|0|yes|no (default: auto/on)
#   Build NGINX with the stream (TCP/UDP) core and related modules.
# (GeoIP2 intentionally omitted for stability focus)
# CHECKSUM_POLICY=strict|allow-missing|skip (default: strict)
#   strict        -> Fail when checksum is missing or mismatched.
#   allow-missing -> Continue only when checksum is missing; mismatches still fail.
#   skip          -> Skip all checksum verification (NOT recommended).
#
# Quick examples:
#   CONFIRM=yes CHECKSUM_POLICY=strict   ./nginx_installer.sh install
#   ENABLE_ZSTD=0                       ./nginx_installer.sh install
#   CHECKSUM_POLICY=allow-missing       ./nginx_installer.sh install
#   CHECKSUM_POLICY=skip                ./nginx_installer.sh install   # dangerous


# Safer error handling
set -euo pipefail
set -E  # ensure ERR trap propagates into functions and subshells
umask 022

# Global toggles/state
# Hint for zstd build strategy; updated dynamically if we fallback to static
ZSTD_BUILD_MODE="dynamic"

# Determine and validate checksum policy (default: strict)
EFFECTIVE_CHECKSUM_POLICY=""

lc() { echo "$1" | tr 'A-Z' 'a-z'; }

print_env_overview() {
    echo "Environment vars:"
    echo "  CONFIRM=yes         # skip prompts"
    echo "  FORCE_SSH_INSTALL=1 # allow SSH installs"
    echo "  ENABLE_HEADERS_MORE=1|0 (default on)"
    echo "  ENABLE_ZSTD=1|0     (default on)"
    echo "  ENABLE_STREAM=1|0   (default on)"
    echo "  CHECKSUM_POLICY=strict|allow-missing|skip (default strict)"
    echo; echo "Examples:"
    echo "  CONFIRM=yes $0 install"
    echo "  ENABLE_ZSTD=0 $0 install"
    echo "  ENABLE_STREAM=0 $0 install"
    echo "  CHECKSUM_POLICY=allow-missing $0 install"
    echo "  CHECKSUM_POLICY=skip $0 install   # disables verification"
}

print_usage() {
    echo; echo -e "${BOLD}NGINX Compiler and Installer${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Usage: $0 {install|remove|verify}"; echo
    echo "  install - Build and install NGINX with OpenSSL from source"
    echo "  remove  - Remove NGINX installation and clean up"
    echo "  verify  - Check current installation"
    echo; print_env_overview; echo
    echo "Features:"
    echo "  • NGINX from source + OpenSSL"
    echo "  • HTTP/3 (QUIC), modern TLS"
    echo "  • Systemd integration"
    echo "  • Modular configs and verification"
}

invalid_env_choice() {
    local varname="$1"; local value="$2"; shift 2 || true
    log_error "Invalid value for ${varname}: '${value}'"
    echo "Valid options for ${varname}: $*"
    echo
    print_env_overview
    exit 1
}

validate_env() {
    local policy
    policy=$( (
        set +u
        printf '%s' "${CHECKSUM_POLICY-}"
    ) )
    policy=$(lc "${policy:-strict}")
    case "$policy" in
        strict|allow-missing|skip)
            EFFECTIVE_CHECKSUM_POLICY="$policy" ;;
        *)
            invalid_env_choice CHECKSUM_POLICY "${policy}" strict allow-missing skip ;;
    esac
}

## Versioned sources catalog (GitHub-only URLs)
# Each component has a fixed version, its respective download URL, and a SHA256.
# IMPORTANT: Each hash corresponds to exactly the version above it.
# If you change a version, update the hash (and possibly the URL) too.

# nginx
readonly NGINX_VERSION="1.29.1"
NGINX_URL="https://github.com/nginx/nginx/archive/refs/tags/release-${NGINX_VERSION}.tar.gz"  # GitHub tag archive
NGINX_SHA256="8b864d3d803d903b77f77bf45ef9dbc310c90719e350f2ae5a3515d1193481f6"  # for nginx (update when version changes)

# OpenSSL
readonly OPENSSL_VERSION="3.5.2"
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_SHA256="c53a47e5e441c930c3928cf7bf6fb00e5d129b630e0aa873b08258656e7345ec"  # for openssl-${OPENSSL_VERSION}.tar.gz

# PCRE2
readonly PCRE2_VERSION="10.45"
PCRE2_URL="https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/pcre2-${PCRE2_VERSION}.tar.gz"
PCRE2_SHA256="0e138387df7835d7403b8351e2226c1377da804e0737db0e071b48f07c9d12ee"  # for pcre2-${PCRE2_VERSION}.tar.gz

# zlib (reference: https://github.com/madler/zlib/releases/tag/v${ZLIB_VERSION})
readonly ZLIB_VERSION="1.3.1"
ZLIB_URL="https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/zlib-${ZLIB_VERSION}.tar.gz"
ZLIB_SHA256="9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"  # for zlib-${ZLIB_VERSION}.tar.gz

# headers-more module
readonly HEADERS_MORE_VERSION="0.39"
HEADERS_MORE_URL="https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v${HEADERS_MORE_VERSION}.tar.gz"
HEADERS_MORE_SHA256="dde68d3fa2a9fc7f52e436d2edc53c6d703dcd911283965d889102d3a877c778"  # for headers-more v${HEADERS_MORE_VERSION}

# zstd nginx module
readonly ZSTD_MODULE_VERSION="0.1.1"
ZSTD_MODULE_URL="https://github.com/tokers/zstd-nginx-module/archive/refs/tags/${ZSTD_MODULE_VERSION}.tar.gz"
ZSTD_MODULE_SHA256="707d534f8ca4263ff043066db15eac284632aea875f9fe98c96cea9529e15f41"  # for zstd-nginx-module ${ZSTD_MODULE_VERSION}

 # GeoIP2 omitted

# Build configuration
PREFIX="/usr/local/nginx"
# Secure, unique temp directories
BUILD_DIR="$(mktemp -d -t nginx-build-XXXXXXXX)"
LOG_DIR="$(mktemp -d -t nginx-logs-XXXXXXXX)"

# Source URLs defined above alongside versions and hashes (GitHub-only)

# Unified artifact catalog: id|archive_name|sha256|strip_components|target_dir|enabled_flag|urls (comma-separated for fallbacks)
ARTIFACTS=(
    "nginx|nginx-${NGINX_VERSION}.tar.gz|${NGINX_SHA256}|1|nginx-${NGINX_VERSION}||${NGINX_URL}"
    "openssl|openssl-${OPENSSL_VERSION}.tar.gz|${OPENSSL_SHA256}|0|openssl-${OPENSSL_VERSION}||${OPENSSL_URL}"
    "pcre2|pcre2-${PCRE2_VERSION}.tar.gz|${PCRE2_SHA256}|0|pcre2-${PCRE2_VERSION}||${PCRE2_URL}"
    "zlib|zlib-${ZLIB_VERSION}.tar.gz|${ZLIB_SHA256}|0|zlib-${ZLIB_VERSION}||${ZLIB_URL}"
    "headers-more|headers-more.tar.gz|${HEADERS_MORE_SHA256}|1|headers-more-module|ENABLE_HEADERS_MORE|${HEADERS_MORE_URL}"
    "zstd|zstd-module.tar.gz|${ZSTD_MODULE_SHA256}|1|zstd-module|ENABLE_ZSTD|${ZSTD_MODULE_URL}"
)

# Color definitions
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly NC='\033[0m' # No Color
readonly BOLD='\033[1m'

# Additional configuration
readonly BACKUP_DIR="/root/nginx-backup-$(date +%Y%m%d-%H%M%S)"
readonly SERVICE_NAME="nginx"

# mktemp created the directories already

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_step() { CURRENT_STEP="$1"; echo -e "${PURPLE}[→]${NC} ${BOLD}$1${NC}"; }

# Fatal helper
die() { log_error "$1"; exit 1; }

# Show the last N lines of a log file (default: 100), ignore errors
show_log_tail() {
    local f="$1"; local n="${2:-100}";
    [ -f "$f" ] || return 0
    log_info "Last ${n} lines of $(basename "$f"):"; tail -n "$n" "$f" || true
}

# Error trap to show failing line
on_err() {
    local exit_code=$?
    local src_line=${BASH_LINENO[0]:-unknown}
    log_error "An error occurred (exit=$exit_code) at line: $src_line"
    # Provide extra context about where to look
    if [ -n "${CURRENT_STEP:-}" ]; then
        log_info "While: ${CURRENT_STEP}"
    fi
    if [ -d "${LOG_DIR:-}" ]; then
        log_info "Logs are under: ${LOG_DIR}"
    fi
}
trap on_err ERR

# Cleanup function
cleanup() {
    if [ -n "$BUILD_DIR" ] && [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
    fi
    if [ -n "$LOG_DIR" ] && [ -d "$LOG_DIR" ]; then
        rm -rf "$LOG_DIR"
    fi
}
trap cleanup EXIT INT TERM

# Check for root privileges
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        echo -e "Usage: sudo $0"
        exit 1
    fi
}

# Check if systemd is available and usable (not always true in containers)
has_systemd() {
    if command -v systemctl >/dev/null 2>&1; then
        # Heuristic: presence of systemd runtime dir
        [ -d /run/systemd/system ]
    else
        return 1
    fi
}

# Ask for confirmation unless ENV confirms
confirm_or_exit() {
    local prompt_msg="$1"
    local envvar_name="${2:-CONFIRM}"
    local envval
    envval=$( (
        set +u
        printf '%s' "${!envvar_name-}"
    ) )

    if [[ "$envval" == "yes" ]]; then
        log_info "Confirmed via ${envvar_name}=yes"
        return 0
    fi
    if [[ -t 0 ]]; then
        read -rp "${prompt_msg} [y/N] " answer
        if [[ "${answer,,}" == "y" ]]; then
            return 0
        fi
        log_error "Operation cancelled"
        exit 0
    else
        die "Non-interactive mode detected. Use: ${envvar_name}=yes $0 <command>"
    fi
}

# Ensure required commands exist
require_cmds() {
    local missing=()
    # core tools; handle sha256 tooling separately below
    local cmds=(wget gcc make tar perl awk sed grep)
    for c in "${cmds[@]}"; do
        if ! command -v "$c" >/dev/null 2>&1; then
            missing+=("$c")
        fi
    done
    # Accept either sha256sum or shasum (macOS/BSD) for checksum verification
    if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
        missing+=("sha256sum or shasum")
    fi
    if [ ${#missing[@]} -gt 0 ]; then
        die "Missing required commands: ${missing[*]}"
    fi
}

# Compute SHA256 portable across distros
compute_sha256() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    else
        die "No SHA256 tool available"
    fi
}

# Get primary server IP (best-effort)
primary_ip() {
    local ip=""
    if command -v hostname >/dev/null 2>&1; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}' | head -n1 || true)
    fi
    if [[ -z "$ip" ]] && command -v ip >/dev/null 2>&1; then
        ip=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)
    fi
    if [[ -z "$ip" ]] && command -v ifconfig >/dev/null 2>&1; then
        ip=$(ifconfig 2>/dev/null | awk '/inet / && $2!="127.0.0.1" {print $2; exit}')
    fi
    echo "${ip:-unknown}"
}

# CPU count detection with fallbacks
num_procs() {
    local n
    n=$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)
    if [[ -z "$n" ]]; then
        n=$(nproc 2>/dev/null || true)
    fi
    if [[ -z "$n" ]]; then
        n=2
    fi
    echo "$n"
}

# Detect OpenSSL Configure target based on architecture
detect_openssl_target() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) echo "linux-x86_64" ;;
        aarch64|arm64) echo "linux-aarch64" ;;
        armv7l|armv6l|armhf) echo "linux-armv4" ;;
        *) echo "linux-generic64" ;;
    esac
}

# Determine if a feature/module is enabled based on an env var.
# Accepts typical truthy/falsey values; defaults to provided fallback (auto=yes).
is_enabled() {
    local var_name="$1"; shift || true
    local fallback="${1:-auto}"
    local val
    # Sanitize variable name to valid shell identifier (defensive)
    # Trim everything from the first invalid character onward
    var_name="${var_name%%[!A-Za-z0-9_]*}"
    # Read env var by name safely even with 'set -u'
    # Use a subshell to temporarily disable nounset
    val=$( (
        set +u
        printf '%s' "${!var_name-}"
    ) )
    if [ -z "$val" ]; then
        val="$fallback"
    fi
    case "${val,,}" in
        0|no|false|off|disable|disabled)
            return 1 ;;
        *)
            return 0 ;;
    esac
}

# Write a per-module loader conf if the .so exists and the module is enabled
write_module_loader_conf() {
    local so_path="$1"     # e.g., /etc/nginx/modules/ngx_http_headers_more_filter_module.so
    local conf_name="$2"   # e.g., headers_more.conf
    local enabled_flag="$3" # env var name controlling enablement (no trailing comment on same line)
    local fallback
    fallback="${4:-auto}"

    # Evaluate module enablement; avoid inline comment after var to prevent "invalid variable name" with set -u/-e
    if ! is_enabled "$enabled_flag" "$fallback"; then
        log_info "Module disabled via $enabled_flag: $(basename "$so_path")"
        return 0
    fi

    if [ -f "$so_path" ]; then
        mkdir -p /etc/nginx/modules.d
        cat > "/etc/nginx/modules.d/$conf_name" <<EOF
load_module $so_path;
EOF
        chmod 0644 "/etc/nginx/modules.d/$conf_name" || true
        log_success "Enabled module loader: /etc/nginx/modules.d/$conf_name"
    else
        log_warn "Module .so not found, skipping: $so_path"
    fi
}

# Print header
print_header() {
    echo
    echo -e "${BOLD}NGINX Compiler and Installer${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Compiling NGINX ${NGINX_VERSION} with OpenSSL ${OPENSSL_VERSION}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    # Reveal temp locations early for easier debugging
    log_info "Build dir: ${BUILD_DIR}"
    log_info "Logs dir:  ${LOG_DIR}"
}

# Verify file checksums honoring CHECKSUM_POLICY
verify_checksum() {
    local file="$1"
    local expected_sha="$2"
    local policy="$EFFECTIVE_CHECKSUM_POLICY"
    [ -z "$policy" ] && policy="strict"
    policy=$(lc "$policy")
    if [ "$policy" = "skip" ]; then
        log_warn "Checksum verification skipped for $file (CHECKSUM_POLICY=skip)"
        return 0
    fi
    
    if [ -z "$expected_sha" ]; then
        if [ "$policy" = "strict" ]; then
            log_error "Missing checksum for $file"
            log_info "Set CHECKSUM_POLICY=allow-missing to proceed without a hash, or CHECKSUM_POLICY=skip to disable all verification (not recommended)."
            return 1
        else
            log_warn "No checksum available for $file - continuing due to CHECKSUM_POLICY=$policy"
            return 0
        fi
    fi
    
    local actual_sha
    actual_sha=$(compute_sha256 "$file")
    
    if [ "$actual_sha" = "$expected_sha" ]; then
        log_success "Checksum verified for $file"
        return 0
    else
        log_error "Checksum mismatch for $file"
        log_error "Expected: $expected_sha"
        log_error "Actual:   $actual_sha"
        # Mismatches always fail unless policy=skip (handled above)
        return 1
    fi
}

# Install dependencies
install_dependencies() {
    log_step "Installing build dependencies"
    
    # Helpers to reduce repetition
    pkg_ok() { command -v "$1" &>/dev/null; }
    run_or_fail() { "$@" || { log_error "Package setup failed"; exit 1; }; }

    if pkg_ok apt-get; then
        log_info "Detected Debian/Ubuntu system"
        export DEBIAN_FRONTEND=noninteractive
        run_or_fail apt-get update -qq &>"$LOG_DIR/apt-update.log"
        local apt_pkgs=(build-essential libpcre2-dev zlib1g-dev perl wget gcc make hostname zstd libzstd-dev pkg-config)
        run_or_fail apt-get install -y "${apt_pkgs[@]}" &>"$LOG_DIR/apt-install.log"
    elif pkg_ok dnf; then
        log_info "Detected Fedora/RHEL system"
        if dnf --version 2>/dev/null | grep -q "dnf5"; then
            run_or_fail dnf install -y @development-tools &>"$LOG_DIR/dnf-install.log"
        else
            run_or_fail dnf groupinstall -y "Development Tools" &>"$LOG_DIR/dnf-install.log"
        fi
        local dnf_pkgs=(pcre2-devel zlib-devel perl wget gcc make hostname zstd libzstd libzstd-devel pkgconfig pkgconf-pkg-config)
        run_or_fail dnf install -y "${dnf_pkgs[@]}" &>"$LOG_DIR/dnf-install.log"
    elif pkg_ok yum; then
        log_info "Detected CentOS/RHEL system"
        run_or_fail yum groupinstall -y "Development Tools" &>"$LOG_DIR/yum-install.log"
        local yum_pkgs=(pcre2-devel zlib-devel perl wget gcc make hostname zstd libzstd libzstd-devel pkgconfig pkgconf-pkg-config)
        run_or_fail yum install -y "${yum_pkgs[@]}" &>"$LOG_DIR/yum-install.log"
    else
        log_error "Unsupported package manager. This script requires apt, dnf, or yum."
        exit 1
    fi
    
    log_success "Build dependencies installed"
}

# Create backup of existing NGINX installation
backup_existing() {
    log_step "Creating backup of existing installation"
    
    mkdir -p "$BACKUP_DIR"
    
    # Backup existing NGINX configuration
    if [ -d "/etc/nginx" ]; then
        cp -a /etc/nginx "$BACKUP_DIR/"
        log_info "NGINX configuration backed up to $BACKUP_DIR"
    fi
    
    # Backup existing NGINX binary
    if [ -f "/usr/sbin/nginx" ]; then
    # Avoid colliding with the backed up /etc/nginx directory named 'nginx'
    cp /usr/sbin/nginx "$BACKUP_DIR/nginx.sbin"
    log_info "NGINX binary backed up to $BACKUP_DIR/nginx.sbin"
    fi
    
    # Save current NGINX service status
    if has_systemd; then
        if systemctl is-active --quiet nginx &>/dev/null; then
            echo "nginx was active" > "$BACKUP_DIR/service_status.txt"
        else
            echo "nginx was inactive" > "$BACKUP_DIR/service_status.txt"
        fi
    fi
    
    log_success "Backup created successfully"
}

# Download and verify sources
download_sources() {
    log_step "Downloading source files"
    
    cd "$BUILD_DIR" || exit 1

    # Helper: download with fallbacks
    download_with_fallbacks() {
        local outfile="$1"; shift
        local urls_csv="$1"; shift
        local IFS=','
        local urls=($urls_csv)
        for u in "${urls[@]}"; do
            if [ -z "$u" ]; then continue; fi
            if wget -q --tries=3 --timeout=30 -O "$outfile" "$u"; then
                echo "$u"
                return 0
            fi
        done
        return 1
    }

    # Iterate artifacts
    for spec in "${ARTIFACTS[@]}"; do
        IFS='|' read -r id archive sha strip target_dir enabled_flag urls <<< "$spec"
        if [ -n "$enabled_flag" ] && ! is_enabled "$enabled_flag" auto; then
            log_info "${id}: disabled via ${enabled_flag}; skipping"
            continue
        fi
        log_info "Fetching ${id} from ${urls}"
        if ! src_url=$(download_with_fallbacks "$archive" "$urls"); then
            log_error "Failed to download ${id} from all sources"
            exit 1
        fi
    # Always call verify_checksum to allow policy enforcement on missing hashes
    verify_checksum "$archive" "$sha" || exit 1
        # Extract
        if [ "$strip" = "0" ]; then
            tar xf "$archive" || { log_error "Failed to extract ${id}"; exit 1; }
        else
            mkdir -p "$target_dir"
            tar -xzf "$archive" --strip-components="$strip" -C "$target_dir" || { log_error "Failed to extract ${id}"; exit 1; }
        fi
        log_success "Downloaded ${id} (${src_url})"
    done

    log_success "Source files downloaded and extracted"
}

# Build OpenSSL
build_openssl() {
    log_step "Building OpenSSL ${OPENSSL_VERSION}"
    
    cd "$BUILD_DIR/openssl-${OPENSSL_VERSION}" || exit 1
    
    local openssl_target
    openssl_target=$(detect_openssl_target)

    ./Configure "$openssl_target" \
        --prefix="$BUILD_DIR/openssl-install" \
        --openssldir="$BUILD_DIR/openssl-install/ssl" \
        enable-tls1_3 \
        no-shared \
        no-tests \
        -fPIC \
        -O3 &>"$LOG_DIR/openssl-configure.log" || { log_error "OpenSSL configure failed"; show_log_tail "$LOG_DIR/openssl-configure.log" 80; exit 1; }

    make -j"$(num_procs)" &>"$LOG_DIR/openssl-make.log" || { log_error "OpenSSL make failed"; show_log_tail "$LOG_DIR/openssl-make.log" 80; exit 1; }
    make install_sw &>"$LOG_DIR/openssl-install.log" || { log_error "OpenSSL install failed"; show_log_tail "$LOG_DIR/openssl-install.log" 80; exit 1; }

    log_success "OpenSSL built successfully"
    
    cd "$BUILD_DIR" || exit 1
}

# Configure and build NGINX
build_nginx() {
    log_step "Configuring NGINX ${NGINX_VERSION}"
    
    cd "$BUILD_DIR/nginx-${NGINX_VERSION}" || exit 1
    
    # Set build flags
    export CFLAGS="-I${BUILD_DIR}/openssl-install/include -O3"
    export LDFLAGS="-L${BUILD_DIR}/openssl-install/lib64 -L${BUILD_DIR}/openssl-install/lib"
    
    # Base configure args
    local configure_args_base=(
        --prefix="$PREFIX"
        --sbin-path=/usr/sbin/nginx
        --conf-path=/etc/nginx/nginx.conf
        --error-log-path=/var/log/nginx/error.log
        --http-log-path=/var/log/nginx/access.log
        --pid-path=/run/nginx.pid
        --lock-path=/run/nginx.lock
        --http-client-body-temp-path=/var/cache/nginx/client_temp
        --http-proxy-temp-path=/var/cache/nginx/proxy_temp
        --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp
        --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp
        --http-scgi-temp-path=/var/cache/nginx/scgi_temp
        --user=nginx
        --group=nginx
        --with-openssl="$BUILD_DIR/openssl-${OPENSSL_VERSION}"
        --with-pcre="$BUILD_DIR/pcre2-${PCRE2_VERSION}"
        --with-pcre-jit
        --with-zlib="$BUILD_DIR/zlib-${ZLIB_VERSION}"
        --with-compat
        --with-file-aio
        --with-threads
        --with-http_addition_module
        --with-http_auth_request_module
        --with-http_dav_module
        --with-http_flv_module
        --with-http_gunzip_module
        --with-http_gzip_static_module
        --with-http_mp4_module
        --with-http_random_index_module
        --with-http_realip_module
        --with-http_secure_link_module
        --with-http_slice_module
        --with-http_ssl_module
        --with-http_stub_status_module
        --with-http_sub_module
        --with-http_v2_module
        --with-http_v3_module
        --with-ld-opt="$LDFLAGS"
    )

    # Stream (TCP/UDP) support; include common stream modules when enabled
    if is_enabled ENABLE_STREAM auto; then
        configure_args_base+=(
            --with-stream
            --with-stream_ssl_module
            --with-stream_realip_module
            --with-stream_ssl_preread_module
        )
    fi

    # Conditionally add dynamic modules based on flags
    local configure_args_dynamic=("${configure_args_base[@]}")
    if is_enabled ENABLE_HEADERS_MORE auto && [ -d "$BUILD_DIR/headers-more-module" ]; then
        configure_args_dynamic+=( --add-dynamic-module="$BUILD_DIR/headers-more-module" )
    fi
    if is_enabled ENABLE_ZSTD auto && [ -d "$BUILD_DIR/zstd-module" ]; then
        configure_args_dynamic+=( --add-dynamic-module="$BUILD_DIR/zstd-module" )
    fi

    # Prepare a static variant we can fall back to for zstd to avoid -fPIC issues
    local configure_args_static=("${configure_args_base[@]}")
    if is_enabled ENABLE_HEADERS_MORE auto && [ -d "$BUILD_DIR/headers-more-module" ]; then
        configure_args_static+=( --add-dynamic-module="$BUILD_DIR/headers-more-module" )
    fi
    if is_enabled ENABLE_ZSTD auto && [ -d "$BUILD_DIR/zstd-module" ]; then
        configure_args_static+=( --add-module="$BUILD_DIR/zstd-module" )
    fi

    # Some sources provide ./configure, others require auto/configure
    local cfg_cmd
    if [ -x "./configure" ]; then
        cfg_cmd=("./configure")
    elif [ -f "auto/configure" ]; then
        cfg_cmd=("bash" "auto/configure")
    else
        log_error "No configure script found in nginx source tree"
        log_info "Checked: ./configure and auto/configure"
        exit 1
    fi

    # Helper to run configure + make with a given arg list
    run_configure_make() {
        local mode="$1"; shift
        local -a args=("$@")
        : >"$LOG_DIR/nginx-configure.log"
        : >"$LOG_DIR/nginx-build.log"
        "${cfg_cmd[@]}" "${args[@]}" &>"$LOG_DIR/nginx-configure.log" || return 2
        log_step "Building NGINX (${mode})"
        if ! make -j"$(num_procs)" &>"$LOG_DIR/nginx-build.log"; then
            return 3
        fi
        return 0
    }

    # Try dynamic first; fallback to static zstd if we hit non-PIC static lib link error
    if run_configure_make "dynamic" "${configure_args_dynamic[@]}"; then
        ZSTD_BUILD_MODE="dynamic"
        log_success "NGINX built successfully"
    else
        local cfg_rc=$?
        if [ $cfg_rc -eq 2 ]; then
            log_error "NGINX configuration failed"; show_log_tail "$LOG_DIR/nginx-configure.log" 100; exit 1; fi
        # Build failed; check if it's zstd shared object -fPIC issue
        if is_enabled ENABLE_ZSTD auto && grep -qE "recompile with -fPIC|ngx_http_zstd_.*\.so" "$LOG_DIR/nginx-build.log"; then
            log_warn "Zstd dynamic module failed to link (-fPIC). Falling back to static module build."
            make clean >/dev/null 2>&1 || true
            if run_configure_make "static-zstd" "${configure_args_static[@]}"; then
                ZSTD_BUILD_MODE="static"
                log_success "NGINX built successfully with static Zstd module"
            else
                log_error "NGINX build failed after zstd static fallback"; show_log_tail "$LOG_DIR/nginx-build.log" 200
                exit 1
            fi
        else
            log_error "NGINX build failed"; show_log_tail "$LOG_DIR/nginx-build.log" 200
            exit 1
        fi
    fi
}

# Install NGINX files and configure system
install_nginx() {
    log_step "Installing NGINX"
    
    # Create nginx user and group safely
    if ! id nginx >/dev/null 2>&1; then
        local nologin_shell
        if [ -x /usr/sbin/nologin ]; then
            nologin_shell=/usr/sbin/nologin
        elif [ -x /sbin/nologin ]; then
            nologin_shell=/sbin/nologin
        else
            nologin_shell=/bin/false
        fi
        getent group nginx >/dev/null 2>&1 || groupadd --system nginx
        useradd --system --home /var/cache/nginx --no-create-home --shell "$nologin_shell" --gid nginx --comment "nginx user" nginx
        log_info "Created nginx user"
    fi
    
    # Create directories
    mkdir -p /var/cache/nginx/{client_temp,proxy_temp,fastcgi_temp,uwsgi_temp,scgi_temp}
    mkdir -p /var/log/nginx
    touch /var/log/nginx/error.log /var/log/nginx/access.log 2>/dev/null || true
    # conf.d reserved for site-specific configs; feature/common configs go in snippets/
    mkdir -p /etc/nginx/conf.d
    mkdir -p /etc/nginx/snippets
    mkdir -p /etc/nginx/stream.d
    
    # Install NGINX
    cd "$BUILD_DIR/nginx-${NGINX_VERSION}" || exit 1
    make install &>"$LOG_DIR/nginx-install.log" || { log_error "NGINX installation failed. See $LOG_DIR/nginx-install.log"; exit 1; }
    log_success "NGINX installed successfully"

    # Modules
    mkdir -p /etc/nginx/modules /etc/nginx/modules.d
    log_info "Installing dynamic modules"
    if [ -d "$BUILD_DIR/nginx-${NGINX_VERSION}/objs" ]; then
        # Try copying directly from objs using find to avoid wildcard issues
        if find "$BUILD_DIR/nginx-${NGINX_VERSION}/objs" -maxdepth 1 -type f -name "*.so" | grep -q .; then
            find "$BUILD_DIR/nginx-${NGINX_VERSION}/objs" -maxdepth 1 -type f -name "*.so" -exec cp {} /etc/nginx/modules/ \;
        else
            log_warn "No dynamic modules found in objs directory"
            # Fallback: search the entire build tree for built modules
            find "$BUILD_DIR" -type f -name "*.so" -exec cp {} /etc/nginx/modules/ \; 2>/dev/null || true
        fi

        # Set correct permissions (best-effort)
        chown root:root /etc/nginx/modules/*.so 2>/dev/null || true
        chmod 0644 /etc/nginx/modules/*.so 2>/dev/null || true

    # Report result
        if ls /etc/nginx/modules/*.so >/dev/null 2>&1; then
            log_success "Dynamic modules installed to /etc/nginx/modules/"
        else
            log_warn "No dynamic module .so files were installed"
        fi
    else
        log_error "NGINX objs directory not found - modules may not be available"
    fi
    
    # Set permissions
    chown -R nginx:nginx /var/cache/nginx /var/log/nginx
    chmod 755 /var/cache/nginx /var/log/nginx
    
    # Create basic configuration and modular snippets
    create_basic_config
    create_snippets
    
    # Create mime.types file
    create_mime_types

    # Module loader snippets
    write_module_loader_conf \
        "/etc/nginx/modules/ngx_http_headers_more_filter_module.so" \
        headers_more.conf \
        ENABLE_HEADERS_MORE auto
    is_enabled ENABLE_HEADERS_MORE auto || rm -f /etc/nginx/modules.d/headers_more.conf 2>/dev/null || true

    if is_enabled ENABLE_ZSTD auto; then
        if [ "$ZSTD_BUILD_MODE" = "dynamic" ]; then
            write_module_loader_conf "/etc/nginx/modules/ngx_http_zstd_filter_module.so"  zstd_filter.conf  ENABLE_ZSTD auto
            write_module_loader_conf "/etc/nginx/modules/ngx_http_zstd_static_module.so"  zstd_static.conf  ENABLE_ZSTD auto
        else
            log_info "Zstd compiled statically; no loader needed"
            rm -f /etc/nginx/modules.d/zstd_*.conf 2>/dev/null || true
        fi
    else
        log_info "Zstd disabled via ENABLE_ZSTD"
        rm -f /etc/nginx/modules.d/zstd_*.conf 2>/dev/null || true
    fi


    # Create any optional, feature-gated configs (like zstd)
    create_optional_confs
    
    # Create systemd service
    create_systemd_service
    
    log_success "NGINX installation completed"
}

# Create basic NGINX configuration
create_basic_config() {
    local stream_block=""
    if is_enabled ENABLE_STREAM auto; then
        stream_block=$(cat <<'EOS'

# TCP/UDP stream (optional)
stream {
    include /etc/nginx/stream.d/*.conf;
}
EOS
)
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
    include /etc/nginx/mime.types;

    # Pull in modular HTTP snippets (core, security, compression, TLS, etc.)
    include /etc/nginx/snippets/*.conf;

    # Site-specific vhosts belong in conf.d (kept empty by this installer)
    include /etc/nginx/conf.d/*.conf;
    
    # Default server
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name _;
        root /usr/share/nginx/html;
        
        location / {
            index index.html index.htm;
        }
        
        error_page 404 /404.html;
        error_page 500 502 503 504 /50x.html;
        location = /50x.html {
            root /usr/share/nginx/html;
        }
    }
}

${stream_block}
EOF

    # Create default index.html
    mkdir -p /usr/share/nginx/html
    cat > /usr/share/nginx/html/index.html << 'EOF'
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Welcome to NGINX</title><style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;margin:0;background:#f7f9fb;color:#111}header{background:linear-gradient(135deg,#009639,#00b36b);color:#fff;padding:20px}main{max-width:900px;margin:32px auto;padding:0 16px}code{background:#eef4f1;border-radius:4px;padding:2px 6px}section{background:#fff;border:1px solid #e5ece8;border-radius:10px;padding:20px;margin-bottom:16px;box-shadow:0 2px 4px rgba(0,0,0,.04)}</style></head><body><header><h1 style="margin:0">NGINX installed</h1></header><main><section><p>If you see this page, your server is running and serving content.</p><ul><li>Root: <code>/usr/share/nginx/html</code></li><li>Config: <code>/etc/nginx/nginx.conf</code></li><li>Snippets: <code>/etc/nginx/snippets/</code></li><li>Sites: <code>/etc/nginx/conf.d/</code></li></ul><p>Reload with: <code>nginx -s reload</code></p><p>Features: HTTP/3, TLS 1.3, optimized build</p></section></main></body></html>
EOF

    # Compact error pages (404 & 50x)
    cat > /usr/share/nginx/html/404.html << 'EOF'
<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>404 Not Found</title><style>body{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;background:#f7f9fb}main{background:#fff;border:1px solid #e5ece8;border-radius:10px;padding:24px 28px;box-shadow:0 2px 4px rgba(0,0,0,.04);text-align:center}</style><main><h1 style="margin:0 0 8px;color:#c1121f">404</h1><p>The requested resource could not be found.</p><p><a href="/" style="color:#009639;text-decoration:none">Go to homepage</a></p></main></html>
EOF

    cat > /usr/share/nginx/html/50x.html << 'EOF'
<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Server error</title><style>body{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;background:#f7f9fb}main{background:#fff;border:1px solid #e5ece8;border-radius:10px;padding:24px 28px;box-shadow:0 2px 4px rgba(0,0,0,.04);text-align:center}</style><main><h1 style="margin:0 0 8px;color:#b08900">Something went wrong</h1><p>A temporary error occurred while processing your request.</p><p>Please try again later.</p></main></html>
EOF
}

# Create optional, feature-gated configs (e.g., zstd) based on module availability
create_optional_confs() {
    mkdir -p /etc/nginx/snippets

    # Zstd configuration: only if enabled and module loader exists
    if is_enabled ENABLE_ZSTD auto; then
        # Consider present if dynamic .so exists, loader exists, or nginx was built with the module statically
        if [ -f /etc/nginx/modules/ngx_http_zstd_filter_module.so ] || \
           [ -f /etc/nginx/modules.d/zstd_filter.conf ] || \
           nginx -V 2>&1 | grep -qE "--add-(dynamic-)?module=.*zstd-module"; then
            cat > /etc/nginx/snippets/zstd.conf << 'EOF'
# Enabled only when the zstd module is present
zstd on;
zstd_comp_level 7;
zstd_types text/plain text/css text/xml application/json application/javascript application/xml+rss application/atom+xml image/svg+xml;
EOF
            chmod 0644 /etc/nginx/snippets/zstd.conf || true
            log_success "Enabled Zstandard HTTP config: /etc/nginx/snippets/zstd.conf"
            # Remove legacy/conflicting zstd configs placed under conf.d by prior runs or other tools
            if [ -f /etc/nginx/conf.d/zstd.conf ]; then
                rm -f /etc/nginx/conf.d/zstd.conf || true
                log_info "Removed legacy /etc/nginx/conf.d/zstd.conf to avoid duplicate 'zstd' directives"
            fi
        else
            log_warn "Zstd module not present; skipping snippets/zstd.conf"
        fi
    else
        # If explicitly disabled, ensure any previous zstd.conf is removed to avoid unknown directives
        rm -f /etc/nginx/snippets/zstd.conf /etc/nginx/conf.d/zstd.conf 2>/dev/null || true
        log_info "Zstd disabled via ENABLE_ZSTD; removed snippets/zstd.conf if it existed"
    fi
}

# Create modular HTTP snippets for a clean, reusable structure
create_snippets() {
    mkdir -p /etc/nginx/snippets

    # Common core settings
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
    chmod 0644 /etc/nginx/snippets/common.conf || true

    # Security headers
    cat > /etc/nginx/snippets/security.conf << 'EOF'
# Basic security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
EOF
    chmod 0644 /etc/nginx/snippets/security.conf || true

    # TLS core
    cat > /etc/nginx/snippets/ssl_core.conf << 'EOF'
# Core SSL/TLS settings
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:50m;
ssl_session_timeout 1d;
EOF
    chmod 0644 /etc/nginx/snippets/ssl_core.conf || true

    # Compression (gzip); Zstd lives in its own snippet when module present
    cat > /etc/nginx/snippets/compression.conf << 'EOF'
# Gzip compression (fallback)
gzip on;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_types text/plain text/css text/xml application/json application/javascript \
           application/xml+rss application/atom+xml image/svg+xml;
EOF
    chmod 0644 /etc/nginx/snippets/compression.conf || true
}

# Create mime.types file
create_mime_types() {
    local src="$BUILD_DIR/nginx-${NGINX_VERSION}/conf/mime.types"
    if [ -f "$src" ]; then
        /usr/bin/install -D -m 0644 "$src" /etc/nginx/mime.types
        log_success "Installed mime.types from NGINX source"
    else
        # Minimal, safe fallback to keep nginx functional
        cat > /etc/nginx/mime.types << 'EOF'
types { text/html html htm shtml; text/plain txt; application/json json; application/javascript js; text/css css; image/png png; image/jpeg jpeg jpg; image/svg+xml svg; }
EOF
        chmod 0644 /etc/nginx/mime.types || true
        log_warn "Using minimal fallback mime.types (source file not found)"
    fi
}

# Create systemd service
create_systemd_service() {
    if ! has_systemd; then
        log_warn "Systemd not detected; skipping service creation. Manage nginx manually."
        return 0
    fi
    cat > /etc/systemd/system/nginx.service << 'EOF'
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
    systemctl enable nginx
    log_info "Created and enabled systemd service"
}

# Test NGINX configuration
test_configuration() {
    log_step "Testing NGINX configuration"
    
    # Ensure log directory and files exist to avoid permission warnings during nginx -t
    mkdir -p /var/log/nginx
    touch /var/log/nginx/error.log /var/log/nginx/access.log 2>/dev/null || true
    chown -R nginx:nginx /var/log/nginx 2>/dev/null || true

    # Test configuration syntax
    if nginx -t 2>/dev/null; then
        log_success "NGINX configuration syntax is valid"
    else
        log_error "NGINX configuration has syntax errors"
        log_info "Running configuration test with verbose output:"
        nginx -t
        return 1
    fi
    
    # Check if NGINX service can start
    if has_systemd; then

        if systemctl is-active --quiet nginx; then
            log_info "NGINX service is already running"
        else
            if systemctl start nginx; then
                log_success "NGINX service started successfully"
            else
                log_error "Failed to start NGINX service"
                return 1
            fi
        fi
    fi
    
    log_success "NGINX configuration test passed"
}

# Show installation summary
show_summary() {
    echo
    echo -e "${BOLD}Installation Summary${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if command -v nginx &>/dev/null; then
        local nginx_version=$(nginx -v 2>&1 | grep -o 'nginx/[0-9.]*' || echo "Unknown")
        local openssl_version=$(nginx -V 2>&1 | grep -o 'built with OpenSSL [0-9.]*' | cut -d' ' -f4 || echo "Unknown")

        echo -e "${GREEN}✓${NC} NGINX compiled and installed: $nginx_version"
        echo -e "${GREEN}✓${NC} OpenSSL integration: $openssl_version"
        echo -e "${GREEN}✓${NC} HTTP/3 support with QUIC protocol"
        echo -e "${GREEN}✓${NC} Modern, modular configuration applied"
        echo -e "${GREEN}✓${NC} Systemd service created and enabled"

        if has_systemd && systemctl is-active --quiet nginx; then
            echo -e "${GREEN}✓${NC} NGINX service is running"
        else
            echo -e "${YELLOW}!${NC} NGINX service is not running"
        fi
    else
        echo -e "${RED}✗${NC} NGINX installation may have failed"
    fi

    echo
    echo -e "${BOLD}Service Management${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if has_systemd; then
        echo -e "Start NGINX:    ${BLUE}sudo systemctl start nginx${NC}"
        echo -e "Stop NGINX:     ${BLUE}sudo systemctl stop nginx${NC}"
        echo -e "Restart NGINX:  ${BLUE}sudo systemctl restart nginx${NC}"
        echo -e "Enable NGINX:   ${BLUE}sudo systemctl enable nginx${NC}"
        echo -e "Status:         ${BLUE}sudo systemctl status nginx${NC}"
    else
        echo -e "Run NGINX:      ${BLUE}sudo /usr/sbin/nginx${NC}"
        echo -e "Reload:         ${BLUE}sudo /usr/sbin/nginx -s reload${NC}"
        echo -e "Stop:           ${BLUE}sudo pkill -TERM nginx${NC}"
    fi
    echo -e "Test config:    ${BLUE}sudo nginx -t${NC}"
    echo -e "Reload config:  ${BLUE}sudo nginx -s reload${NC}"
    echo
    echo -e "${BOLD}Connection Information${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "HTTP Port:      ${BLUE}80${NC}"
    echo -e "HTTPS Port:     ${BLUE}443${NC}"
    echo -e "Config file:    ${BLUE}/etc/nginx/nginx.conf${NC}"
    echo -e "Snippets:       ${BLUE}/etc/nginx/snippets/${NC}"
    echo -e "Site configs:   ${BLUE}/etc/nginx/conf.d/${NC}"
    echo -e "Document root:  ${BLUE}/usr/share/nginx/html${NC}"
    echo -e "Log files:      ${BLUE}/var/log/nginx/${NC}"
    echo -e "Backup:         ${BLUE}$BACKUP_DIR${NC}"
    
    # Show server IP addresses
    if command -v hostname >/dev/null 2>&1; then
        echo -e "Server IPs:     ${BLUE}$(hostname -I 2>/dev/null | tr ' ' '\n' | head -3 | tr '\n' ' ')${NC}"
    fi
    echo
    echo -e "${BOLD}Security Notes${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "• Modern SSL/TLS configuration with TLS 1.2/1.3"
    echo -e "• HTTP/3 support with QUIC protocol enabled"
    echo -e "• Security headers configured (X-Frame-Options, X-Content-Type-Options)"
    echo -e "• Zstd, and as fallback Gzip compression enabled for better performance"
    echo -e "• Built with latest OpenSSL libraries for enhanced security and performance"
    echo -e "• Strong TLS ciphers and protocols enforced"
    echo
    echo -e "${YELLOW}Connect with:${NC} ${BLUE}http://$(primary_ip)${NC}"
    echo
}

# Compile and install NGINX with hardened configuration
cmd_install() {
    log_info "Starting NGINX ${NGINX_VERSION} installation with OpenSSL ${OPENSSL_VERSION}"
    
    # Safety check for SSH sessions
    if [[ -n "${SSH_CONNECTION:-}" ]] && [[ "${FORCE_SSH_INSTALL:-}" != "1" ]]; then
        log_error "Running in SSH session! This will affect web services."
        log_warn "If you have console access, run: FORCE_SSH_INSTALL=1 $0 install"
        log_warn "Or use 'screen' or 'tmux' to maintain session during restart"
        exit 1
    fi
    
    # Confirm installation
    confirm_or_exit "Proceed with NGINX installation? This will compile and install NGINX with OpenSSL." "CONFIRM"
    
    check_root
    require_cmds
    print_header
    
    backup_existing
    install_dependencies
    download_sources
    build_openssl
    build_nginx
    install_nginx
    test_configuration
    
    # Enable and start NGINX service
    if has_systemd; then
        systemctl enable nginx
        systemctl restart nginx
    else
        log_warn "Systemd not available; nginx not started automatically. Use /usr/sbin/nginx to start."
    fi
    
    show_summary
    
    log_success "NGINX installation completed successfully!"
}

# Remove NGINX installation and restore original configuration
cmd_remove() {
    log_info "Removing NGINX installation..."
    
    # Confirm removal
    confirm_or_exit "Remove NGINX installation? This will uninstall NGINX and clean up all files." "CONFIRM"
    
    # Stop NGINX service if running
    if has_systemd && systemctl is-active --quiet nginx 2>/dev/null; then
        log_info "Stopping NGINX service..."
        systemctl stop nginx
    fi
    
    # Disable service
    if has_systemd && systemctl is-enabled --quiet nginx 2>/dev/null; then
        log_info "Disabling NGINX service..."
        systemctl disable nginx
    fi
    
    # Remove systemd service file
    if has_systemd && [[ -f /etc/systemd/system/nginx.service ]]; then
        rm -f /etc/systemd/system/nginx.service
        systemctl daemon-reload
        log_info "Removed systemd service"
    fi
    
    # Remove NGINX files and directories
    rm -rf "$PREFIX"
    rm -f /usr/sbin/nginx
    rm -rf /etc/nginx
    rm -rf /var/log/nginx
    rm -rf /var/cache/nginx
    rm -rf /usr/share/nginx
    
    # Remove nginx user
    if id nginx >/dev/null 2>&1; then
        userdel nginx 2>/dev/null || true
        log_info "Removed nginx user"
    fi
    
    log_success "NGINX installation removed successfully"
    log_warn "NGINX service has been stopped and disabled"
    log_info "Configuration backup remains in: $BACKUP_DIR"
}

# Verify NGINX installation and configuration
cmd_verify() {
    log_info "Verifying NGINX installation..."
    
    local issues=0
    local nv=""; local nv_ok=0
    if command -v nginx &>/dev/null; then
        nv=$(nginx -V 2>&1 || true); nv_ok=1
    fi
    
    # Check if NGINX binary exists and is executable
    if [[ -x /usr/sbin/nginx ]]; then
        local nginx_version=$(nginx -v 2>&1 | grep -o 'nginx/[0-9.]*' || echo "Unknown")
        log_success "NGINX binary installed: $nginx_version"
    else
        log_error "NGINX binary not found or not executable"
        ((issues++))
    fi
    
    # Check configuration file
    if [[ -f /etc/nginx/nginx.conf ]]; then
        log_success "NGINX configuration file exists: /etc/nginx/nginx.conf"
        
        # Test configuration
        if nginx -t 2>/dev/null; then
            log_success "NGINX configuration syntax is valid"
        else
            log_error "NGINX configuration has syntax errors"
            ((issues++))
        fi
    else
        log_error "NGINX configuration file not found"
        ((issues++))
    fi
    
    # Check service status
    if has_systemd && systemctl is-active --quiet nginx 2>/dev/null; then
        log_success "NGINX service is running"
    else
        log_warn "NGINX service is not running"
    fi
    
    if has_systemd && systemctl is-enabled --quiet nginx 2>/dev/null; then
        log_success "NGINX service is enabled"
    else
        log_warn "NGINX service is not enabled"
    fi
    
    # Check OpenSSL integration
    if [ "$nv_ok" -eq 1 ] && grep -q "built with OpenSSL" <<<"$nv"; then
        local openssl_version=$(grep -o 'built with OpenSSL [0-9.]*' <<<"$nv" | cut -d' ' -f4 || echo "Unknown")
        log_success "OpenSSL integration: $openssl_version"
    else
        log_error "OpenSSL integration not found"
        ((issues++))
    fi
    
    # Check HTTP/3 support
    if [ "$nv_ok" -eq 1 ] && grep -q "http_v3_module" <<<"$nv"; then
        log_success "HTTP/3 support: enabled"
    else
        log_warn "HTTP/3 support: not enabled"
    fi

    # Check stream support when requested
    if is_enabled ENABLE_STREAM auto; then
    if [ "$nv_ok" -eq 1 ] && grep -q "--with-stream" <<<"$nv"; then
            log_success "Stream core: enabled"
        else
            log_warn "Stream core: not enabled"
        fi
    fi

    # Verify dynamic module files exist in /etc/nginx/modules (only for enabled modules)
    if [ -d "/etc/nginx/modules" ]; then
        local missing=0
        declare -A optmods=(
            [ngx_http_headers_more_filter_module.so]=ENABLE_HEADERS_MORE
            [ngx_http_zstd_filter_module.so]=ENABLE_ZSTD
            [ngx_http_zstd_static_module.so]=ENABLE_ZSTD
        )
        for so in "${!optmods[@]}"; do
            local flag="${optmods[$so]}"
            if is_enabled "$flag" auto; then
                if [ -f "/etc/nginx/modules/$so" ]; then
                    log_success "Module present: $so"
                else
                    log_warn "Module missing: $so"; missing=$((missing+1))
                fi
            fi
        done
        [ "$missing" -gt 0 ] && log_warn "$missing expected enabled module(s) were not found in /etc/nginx/modules"
    else
        log_warn "/etc/nginx/modules directory not found"
    fi

    # Check third-party dynamic modules (only when enabled)
    if is_enabled ENABLE_HEADERS_MORE auto; then
        grep -q "--add-dynamic-module=.*headers-more" <<<"$nv" && \
            log_success "headers-more module compiled" || log_warn "headers-more module not found in build flags"
    fi
    if is_enabled ENABLE_ZSTD auto; then
        if grep -qE "--add-(dynamic-)?module=.*zstd" <<<"$nv"; then
            grep -q "--add-dynamic-module=.*zstd" <<<"$nv" && \
                log_success "Zstandard module compiled (dynamic)" || log_success "Zstandard module compiled (static)"
        else
            log_warn "Zstandard module not found in build flags"
        fi
    fi

    
    # Check directories and permissions
    local dirs=("/var/log/nginx" "/var/cache/nginx" "/etc/nginx" "/usr/share/nginx/html")
    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            log_success "Directory exists: $dir"
        else
            log_error "Directory missing: $dir"
            ((issues++))
        fi
    done
    
    # Check nginx user
    if id nginx >/dev/null 2>&1; then
        log_success "NGINX user exists"
    else
        log_error "NGINX user missing"
        ((issues++))
    fi
    
    # Check listening ports
    if command -v ss &>/dev/null; then
        local http_ports=$(ss -tlnp | grep :80 | wc -l)
        if [ "$http_ports" -gt 0 ]; then
            log_success "NGINX is listening on port 80"
        else
            log_warn "NGINX is not listening on port 80"
        fi
    fi
    
    echo
    if [[ $issues -eq 0 ]]; then
        log_success "NGINX installation verification passed!"
        return 0
    else
        log_error "NGINX installation verification failed with $issues issues"
        return 1
    fi
}

# Main function
main() {
    # Validate environment configuration up-front
    validate_env

    case "${1:-help}" in
        install)
            cmd_install
            ;;
        remove)
            check_root
            cmd_remove
            ;;
        verify)
            cmd_verify
            ;;
        *)
            if [ -n "${1-}" ] && [ "${1}" != "help" ]; then
                log_error "Unknown command: '${1}'"
                echo "Valid commands: install | remove | verify"
            fi
            print_usage
            ;;
    esac
}

# Run main function
main "$@"
