# Common functions and utilities for NGINX installer

# Color definitions
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# Global state
CURRENT_STEP=""
EFFECTIVE_CHECKSUM_POLICY=""
ZSTD_BUILD_MODE="dynamic"

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_step() { CURRENT_STEP="$1"; echo -e "${PURPLE}[→]${NC} ${BOLD}$1${NC}"; }

# Helper functions
die() { log_error "$1"; exit 1; }
lc() { echo "$1" | tr 'A-Z' 'a-z'; }

# Error handling
on_err() {
    local exit_code=$?
    local src_line=${BASH_LINENO[0]:-unknown}
    log_error "An error occurred (exit=$exit_code) at line: $src_line"
    [ -n "${CURRENT_STEP:-}" ] && log_info "While: ${CURRENT_STEP}"
    [ -d "${LOG_DIR:-}" ] && log_info "Logs are under: ${LOG_DIR}"
}
trap on_err ERR

# Cleanup function
cleanup() {
    local exit_code=$?
    if [ -n "$BUILD_DIR" ] && [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
    fi
    if [ -n "$LOG_DIR" ] && [ -d "$LOG_DIR" ]; then
        if [ $exit_code -eq 0 ]; then
            rm -rf "$LOG_DIR"
        else
            log_warn "Build failed. Logs preserved in: $LOG_DIR"
        fi
    fi
}
trap cleanup EXIT INT TERM

# System checks
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        echo -e "Usage: sudo $0"
        exit 1
    fi
}

has_systemd() {
    command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]
}

# Environment validation
validate_env() {
    local policy="${CHECKSUM_POLICY:-strict}"
    policy=$(lc "$policy")
    case "$policy" in
        strict|allow-missing|skip)
            EFFECTIVE_CHECKSUM_POLICY="$policy" ;;
        *)
            die "Invalid CHECKSUM_POLICY: '${policy}'. Use: strict, allow-missing, or skip" ;;
    esac
}

# Feature enablement check
is_enabled() {
    local var_name="$1"
    local fallback="${2:-auto}"
    local val
    
    val=$( (set +u; printf '%s' "${!var_name-}") )
    [ -z "$val" ] && val="$fallback"
    
    case "${val,,}" in
        0|no|false|off|disable|disabled) return 1 ;;
        *) return 0 ;;
    esac
}

# Confirmation
confirm_or_exit() {
    local prompt_msg="$1"
    local envvar_name="${2:-CONFIRM}"
    local envval
    
    envval=$( (set +u; printf '%s' "${!envvar_name-}") )
    
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

# Safety checks
safety_checks() {
    if [[ -n "${SSH_CONNECTION:-}" ]] && [[ "${FORCE_SSH_INSTALL:-}" != "1" ]]; then
        log_error "Running in SSH session! This will affect web services."
        log_warn "If you have console access, run: FORCE_SSH_INSTALL=1 $0 install"
        exit 1
    fi
}

# Required commands check
require_cmds() {
    local missing=()
    local cmds=(curl make tar perl awk sed grep)
    
    for c in "${cmds[@]}"; do
        if ! command -v "$c" >/dev/null 2>&1; then
            missing+=("$c")
        fi
    done
    
    if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
        missing+=("sha256sum or shasum")
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        die "Missing required commands: ${missing[*]}"
    fi
}

# Utility functions
num_procs() {
    local n
    n=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo "2")
    echo "$n"
}

primary_ip() {
    local ip=""
    if command -v hostname >/dev/null 2>&1; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}' | head -n1 || true)
    fi
    if [[ -z "$ip" ]] && command -v ip >/dev/null 2>&1; then
        ip=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)
    fi
    echo "${ip:-unknown}"
}

detect_openssl_target() {
    local arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) echo "linux-x86_64" ;;
        aarch64|arm64) echo "linux-aarch64" ;;
        armv7l|armv6l|armhf) echo "linux-armv4" ;;
        *) echo "linux-generic64" ;;
    esac
}

# Print header
print_header() {
    echo
    echo -e "${BOLD}NGINX Compiler and Installer${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Compiling NGINX ${NGINX_VERSION} with OpenSSL ${OPENSSL_VERSION}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    log_info "Build dir: ${BUILD_DIR}"
    log_info "Logs dir:  ${LOG_DIR}"
}

# Usage information
print_usage() {
    echo
    echo -e "${BOLD}NGINX Compiler and Installer${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Usage: $0 {install|remove|verify}"
    echo
    echo "Commands:"
    echo "  install - Build and install NGINX with OpenSSL from source"
    echo "  remove  - Remove NGINX installation and clean up"
    echo "  verify  - Check current installation"
    echo
    echo "Environment variables:"
    echo "  CONFIRM=yes         # skip prompts"
    echo "  FORCE_SSH_INSTALL=1 # allow SSH installs"
    echo "  ENABLE_HEADERS_MORE=1|0 (default on)"
    echo "  ENABLE_ZSTD=1|0     (default on)"
    echo "  ENABLE_STREAM=1|0   (default on)"
    echo "  CHECKSUM_POLICY=strict|allow-missing|skip (default strict)"
    echo
    echo "Features:"
    echo "  • NGINX from source + OpenSSL"
    echo "  • HTTP/3 (QUIC), modern TLS"
    echo "  • Systemd integration"
    echo "  • Modular configs and verification"
}
