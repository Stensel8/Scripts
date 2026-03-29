#!/usr/bin/env bash
#
# Helper script to calculate and update SHA256 checksums for NGINX dependencies
# This script downloads the dependencies and updates the checksums in installer files
#
# Usage: ./update-nginx-checksums.sh [nginx_version] [openssl_version] [pcre2_version] [zlib_version]
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

# Get versions from arguments or read from installer files
NGINX_VERSION="${1:-$(grep -oP 'NGINX_VERSION="\K[^"]+' nginx/nginx_installer.sh)}"
OPENSSL_VERSION="${2:-$(grep -oP 'OPENSSL_VERSION="\K[^"]+' nginx/nginx_installer.sh)}"
PCRE2_VERSION="${3:-$(grep -oP 'PCRE2_VERSION="\K[^"]+' nginx/nginx_installer.sh)}"
ZLIB_VERSION="${4:-$(grep -oP 'ZLIB_VERSION="\K[^"]+' nginx/nginx_installer.sh)}"

log_info "Versions to check:"
echo "  NGINX:   $NGINX_VERSION"
echo "  OpenSSL: $OPENSSL_VERSION"
echo "  PCRE2:   $PCRE2_VERSION"
echo "  Zlib:    $ZLIB_VERSION"
echo

# Create temp directory
TEMP_DIR=$(mktemp -d)
trap 'rm -rf -- "$TEMP_DIR"' EXIT

cd "$TEMP_DIR"

# Download and calculate checksums
log_info "Downloading NGINX $NGINX_VERSION..."
if wget -q "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"; then
    NGINX_SHA256=$(sha256sum "nginx-${NGINX_VERSION}.tar.gz" | awk '{print $1}')
    log_success "NGINX SHA256: $NGINX_SHA256"
else
    log_error "Failed to download NGINX $NGINX_VERSION"
    NGINX_SHA256=""
fi

log_info "Downloading OpenSSL $OPENSSL_VERSION..."
if wget -q "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"; then
    OPENSSL_SHA256=$(sha256sum "openssl-${OPENSSL_VERSION}.tar.gz" | awk '{print $1}')
    log_success "OpenSSL SHA256: $OPENSSL_SHA256"
else
    log_error "Failed to download OpenSSL $OPENSSL_VERSION"
    OPENSSL_SHA256=""
fi

log_info "Downloading PCRE2 $PCRE2_VERSION..."
if wget -q "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/pcre2-${PCRE2_VERSION}.tar.gz"; then
    PCRE2_SHA256=$(sha256sum "pcre2-${PCRE2_VERSION}.tar.gz" | awk '{print $1}')
    log_success "PCRE2 SHA256: $PCRE2_SHA256"
else
    log_error "Failed to download PCRE2 $PCRE2_VERSION"
    PCRE2_SHA256=""
fi

log_info "Downloading Zlib $ZLIB_VERSION..."
if wget -q "https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/zlib-${ZLIB_VERSION}.tar.gz"; then
    ZLIB_SHA256=$(sha256sum "zlib-${ZLIB_VERSION}.tar.gz" | awk '{print $1}')
    log_success "Zlib SHA256: $ZLIB_SHA256"
else
    log_error "Failed to download Zlib $ZLIB_VERSION"
    ZLIB_SHA256=""
fi

echo
log_info "SHA256 Checksums:"
echo "===================="
[ -n "$NGINX_SHA256" ] && echo "NGINX:   $NGINX_SHA256"
[ -n "$OPENSSL_SHA256" ] && echo "OpenSSL: $OPENSSL_SHA256"
[ -n "$PCRE2_SHA256" ] && echo "PCRE2:   $PCRE2_SHA256"
[ -n "$ZLIB_SHA256" ] && echo "Zlib:    $ZLIB_SHA256"
echo

# Ask if user wants to update the files
read -rp "Update installer files with these checksums? [y/N] " response
if [[ "$response" =~ ^[Yy]$ ]]; then
    cd "$OLDPWD"

    # Update Bash installer
    if [ -n "$NGINX_SHA256" ]; then
        sed -i "s/NGINX_SHA256=\"[^\"]*\"/NGINX_SHA256=\"$NGINX_SHA256\"/" nginx/nginx_installer.sh
        log_success "Updated NGINX SHA256 in nginx_installer.sh"
    fi

    if [ -n "$OPENSSL_SHA256" ]; then
        sed -i "s/OPENSSL_SHA256=\"[^\"]*\"/OPENSSL_SHA256=\"$OPENSSL_SHA256\"/" nginx/nginx_installer.sh
        log_success "Updated OpenSSL SHA256 in nginx_installer.sh"
    fi

    if [ -n "$PCRE2_SHA256" ]; then
        sed -i "s/PCRE2_SHA256=\"[^\"]*\"/PCRE2_SHA256=\"$PCRE2_SHA256\"/" nginx/nginx_installer.sh
        log_success "Updated PCRE2 SHA256 in nginx_installer.sh"
    fi

    if [ -n "$ZLIB_SHA256" ]; then
        sed -i "s/ZLIB_SHA256=\"[^\"]*\"/ZLIB_SHA256=\"$ZLIB_SHA256\"/" nginx/nginx_installer.sh
        log_success "Updated Zlib SHA256 in nginx_installer.sh"
    fi

    # Update PowerShell installer
    if [ -n "$NGINX_SHA256" ]; then
        sed -i "s/\$NGINX_SHA256 = \"[^\"]*\"/\$NGINX_SHA256 = \"$NGINX_SHA256\"/" nginx/nginx_installer.ps1
        log_success "Updated NGINX SHA256 in nginx_installer.ps1"
    fi

    if [ -n "$OPENSSL_SHA256" ]; then
        sed -i "s/\$OPENSSL_SHA256 = \"[^\"]*\"/\$OPENSSL_SHA256 = \"$OPENSSL_SHA256\"/" nginx/nginx_installer.ps1
        log_success "Updated OpenSSL SHA256 in nginx_installer.ps1"
    fi

    if [ -n "$PCRE2_SHA256" ]; then
        sed -i "s/\$PCRE2_SHA256 = \"[^\"]*\"/\$PCRE2_SHA256 = \"$PCRE2_SHA256\"/" nginx/nginx_installer.ps1
        log_success "Updated PCRE2 SHA256 in nginx_installer.ps1"
    fi

    if [ -n "$ZLIB_SHA256" ]; then
        sed -i "s/\$ZLIB_SHA256 = \"[^\"]*\"/\$ZLIB_SHA256 = \"$ZLIB_SHA256\"/" nginx/nginx_installer.ps1
        log_success "Updated Zlib SHA256 in nginx_installer.ps1"
    fi

    echo
    log_success "All checksums updated in installer files!"
    log_info "Review the changes with: git diff nginx/"
else
    log_info "No changes made to installer files"
fi
