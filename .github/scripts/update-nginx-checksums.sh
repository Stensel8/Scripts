#!/usr/bin/env bash
#
# Recalculate and optionally apply SHA256 checksums for nginx installer dependencies.
#
# Usage:
#   .github/scripts/update-nginx-checksums.sh
#   .github/scripts/update-nginx-checksums.sh --apply
#

set -euo pipefail

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }

usage() {
    cat <<'EOF'
Usage: update-nginx-checksums.sh [--apply]

Options:
  --apply   Apply calculated checksums to nginx/nginx_installer.sh and nginx/nginx_installer.ps1 without prompting
  -h, --help  Show this help
EOF
}

APPLY=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --apply)
            APPLY=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            log_error "Unknown argument: $1"
            usage
            exit 1
            ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT
readonly BASH_INSTALLER="$REPO_ROOT/nginx/nginx_installer.sh"
readonly PS_INSTALLER="$REPO_ROOT/nginx/nginx_installer.ps1"

cd "$REPO_ROOT"

read_sh_var() {
    local key=$1
    sed -n "s/^${key}=\"\\([^\"]*\\)\"$/\\1/p" "$BASH_INSTALLER" | head -n1
}

update_bash_var() {
    local key=$1
    local value=$2
    sed -i "s/^${key}=\"[^\"]*\"$/${key}=\"${value}\"/" "$BASH_INSTALLER"
}

update_ps_var() {
    local key=$1
    local value=$2
    sed -i "s#^\\(\\\$Script:${key}[[:space:]]*=[[:space:]]*'\\)[^']*'#\\1${value}'#" "$PS_INSTALLER"
}

download_and_hash() {
    local url=$1
    local file=$2
    curl -fsSL "$url" -o "$file"
    sha256sum "$file" | awk '{print $1}'
}

NGINX_VERSION="$(read_sh_var NGINX_VERSION)"
PCRE2_VERSION="$(read_sh_var PCRE2_VERSION)"
ZLIB_VERSION="$(read_sh_var ZLIB_VERSION)"
HEADERS_MORE_VERSION="$(read_sh_var HEADERS_MORE_VERSION)"
ZSTD_MODULE_VERSION="$(read_sh_var ZSTD_MODULE_VERSION)"
ACME_MODULE_VERSION="$(read_sh_var ACME_MODULE_VERSION)"

required_values=(
    "$NGINX_VERSION"
    "$PCRE2_VERSION"
    "$ZLIB_VERSION"
    "$HEADERS_MORE_VERSION"
    "$ZSTD_MODULE_VERSION"
    "$ACME_MODULE_VERSION"
)
for value in "${required_values[@]}"; do
    [[ -n "$value" ]] || { log_error "Failed to read one or more versions from $BASH_INSTALLER"; exit 1; }
done

log_info "Versions to recalculate:"
echo "  NGINX:         $NGINX_VERSION"
echo "  PCRE2:         $PCRE2_VERSION"
echo "  Zlib:          $ZLIB_VERSION"
echo "  headers-more:  $HEADERS_MORE_VERSION"
echo "  zstd-module:   $ZSTD_MODULE_VERSION"
echo "  nginx-acme:    $ACME_MODULE_VERSION"
echo

TEMP_DIR=$(mktemp -d)
trap 'rm -rf -- "$TEMP_DIR"' EXIT
cd "$TEMP_DIR"

log_info "Downloading and hashing release tarballs..."

NGINX_SHA256="$(download_and_hash "https://github.com/nginx/nginx/releases/download/release-${NGINX_VERSION}/nginx-${NGINX_VERSION}.tar.gz" "nginx.tar.gz")"
log_success "NGINX_SHA256: $NGINX_SHA256"

PCRE2_SHA256="$(download_and_hash "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/pcre2-${PCRE2_VERSION}.tar.gz" "pcre2.tar.gz")"
log_success "PCRE2_SHA256: $PCRE2_SHA256"

ZLIB_SHA256="$(download_and_hash "https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/zlib-${ZLIB_VERSION}.tar.gz" "zlib.tar.gz")"
log_success "ZLIB_SHA256: $ZLIB_SHA256"

HEADERS_MORE_SHA256="$(download_and_hash "https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v${HEADERS_MORE_VERSION}.tar.gz" "headers-more.tar.gz")"
log_success "HEADERS_MORE_SHA256: $HEADERS_MORE_SHA256"

ZSTD_MODULE_SHA256="$(download_and_hash "https://github.com/tokers/zstd-nginx-module/archive/refs/tags/${ZSTD_MODULE_VERSION}.tar.gz" "zstd-module.tar.gz")"
log_success "ZSTD_MODULE_SHA256: $ZSTD_MODULE_SHA256"

ACME_MODULE_SHA256="$(download_and_hash "https://github.com/nginx/nginx-acme/releases/download/v${ACME_MODULE_VERSION}/nginx-acme-${ACME_MODULE_VERSION}.tar.gz" "nginx-acme.tar.gz")"
log_success "ACME_MODULE_SHA256: $ACME_MODULE_SHA256"

echo
log_info "Calculated checksums:"
echo "  NGINX_SHA256:         $NGINX_SHA256"
echo "  PCRE2_SHA256:         $PCRE2_SHA256"
echo "  ZLIB_SHA256:          $ZLIB_SHA256"
echo "  HEADERS_MORE_SHA256:  $HEADERS_MORE_SHA256"
echo "  ZSTD_MODULE_SHA256:   $ZSTD_MODULE_SHA256"
echo "  ACME_MODULE_SHA256:   $ACME_MODULE_SHA256"
echo

if [[ "$APPLY" != true ]]; then
    read -rp "Apply these checksums to installer files? [y/N] " response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        log_info "No changes made"
        exit 0
    fi
fi

cd "$REPO_ROOT"

update_bash_var NGINX_SHA256 "$NGINX_SHA256"
update_bash_var PCRE2_SHA256 "$PCRE2_SHA256"
update_bash_var ZLIB_SHA256 "$ZLIB_SHA256"
update_bash_var HEADERS_MORE_SHA256 "$HEADERS_MORE_SHA256"
update_bash_var ZSTD_MODULE_SHA256 "$ZSTD_MODULE_SHA256"
update_bash_var ACME_MODULE_SHA256 "$ACME_MODULE_SHA256"

update_ps_var NGINX_SHA256 "$NGINX_SHA256"
update_ps_var PCRE2_SHA256 "$PCRE2_SHA256"
update_ps_var ZLIB_SHA256 "$ZLIB_SHA256"
update_ps_var HEADERS_MORE_SHA256 "$HEADERS_MORE_SHA256"
update_ps_var ZSTD_MODULE_SHA256 "$ZSTD_MODULE_SHA256"
update_ps_var ACME_MODULE_SHA256 "$ACME_MODULE_SHA256"

log_success "Updated checksums in:"
echo "  - nginx/nginx_installer.sh"
echo "  - nginx/nginx_installer.ps1"
