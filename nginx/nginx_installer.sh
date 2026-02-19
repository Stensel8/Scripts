#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# NGINX Installer Script for Linux (Bash)
# ============================================================================
#
# Description:
#   Builds and installs NGINX with OpenSSL 3.6, HTTP/3, zstd compression,
#   and ACME support on Linux.
#
# Usage:
#   ./nginx_installer.sh install    - Build and install NGINX
#   ./nginx_installer.sh remove     - Uninstall NGINX
#
# ============================================================================

# Early syntax check
if ! bash -n "$0" >/dev/null 2>&1; then
    echo "ERROR: Syntax check failed for $0" >&2
    exit 1
fi

# ============================================================================
# Version Configuration
# ============================================================================

# NGINX
NGINX_VERSION="1.29.5"
NGINX_SHA256="6744768a4114880f37b13a0443244e731bcb3130c0a065d7e37d8fd589ade374"

# OpenSSL
OPENSSL_VERSION="3.6.1"
OPENSSL_SHA256="b1bfedcd5b289ff22aee87c9d600f515767ebf45f77168cb6d64f231f518a82e"

# PCRE2
PCRE2_VERSION="10.47"
PCRE2_SHA256="c08ae2388ef333e8403e670ad70c0a11f1eed021fd88308d7e02f596fcd9dc16"

# Zlib
ZLIB_VERSION="1.3.2"
ZLIB_SHA256="bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16"

# Headers-More Module
HEADERS_MORE_VERSION="0.39"
HEADERS_MORE_SHA256="dde68d3fa2a9fc7f52e436d2edc53c6d703dcd911283965d889102d3a877c778"

# Zstd Module
ZSTD_MODULE_VERSION="0.1.1"
ZSTD_MODULE_SHA256="707d534f8ca4263ff043066db15eac284632aea875f9fe98c96cea9529e15f41"

# ACME Module
ACME_MODULE_VERSION="0.3.1"
ACME_MODULE_SHA256="be3d3d10f042930a3bf348731698eadb7003d224a863c53b719ccd28721572c3"

# ============================================================================
# Static Configuration
# ============================================================================

BUILD_DIR="/root/nginx-build-$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/root/nginx-backup-$(date +%Y%m%d-%H%M%S)"
LOG_FILE="/var/log/nginx-installer-$(date +%Y%m%d-%H%M%S).log"

# Download URLs
NGINX_URL="https://github.com/nginx/nginx/releases/download/release-${NGINX_VERSION}/nginx-${NGINX_VERSION}.tar.gz"
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
PCRE2_URL="https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/pcre2-${PCRE2_VERSION}.tar.gz"
ZLIB_URL="https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/zlib-${ZLIB_VERSION}.tar.gz"
HEADERS_MORE_URL="https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v${HEADERS_MORE_VERSION}.tar.gz"
ZSTD_MODULE_URL="https://github.com/tokers/zstd-nginx-module/archive/refs/tags/${ZSTD_MODULE_VERSION}.tar.gz"
ACME_MODULE_URL="https://github.com/nginx/nginx-acme/releases/download/v${ACME_MODULE_VERSION}/nginx-acme-${ACME_MODULE_VERSION}.tar.gz"

# Initialize logging
mkdir -p "$(dirname "$LOG_FILE")" "$BUILD_DIR"
exec > >(tee -a "$LOG_FILE")
exec 2>&1

# ============================================================================
# Helper Functions
# ============================================================================

Write-Log() {
    local level=$1
    local msg=$2
    echo "[$level] $msg" >&2
}

Stop-Script() {
    Write-Log ERROR "$1"
    exit 1
}

Test-Hash() {
    local file=$1
    local expected=$2
    local actual
    actual=$(sha256sum "$file" | awk '{print $1}')
    [[ "$actual" == "$expected" ]] || Stop-Script "Checksum failed: $file"
}

Get-File() {
    local url=$1
    local file=$2
    local sha=$3
    
    if [[ -f "$file" ]]; then
        Test-Hash "$file" "$sha"
        return 0
    fi
    
    Write-Log INFO "Downloading $(basename "$file")..."
    curl -fsSL "$url" -o "$file" || Stop-Script "Download failed: $url"
    Test-Hash "$file" "$sha"
}

Detect-PkgMgr() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    else
        echo "unknown"
    fi
}

# ============================================================================
# System Dependencies
# ============================================================================

Install-Dependencies() {
    [[ $EUID -eq 0 ]] || Stop-Script "Run as root"
    command -v curl >/dev/null 2>&1 || Stop-Script "curl required"
    
    Write-Log INFO "Installing build dependencies"
    
    local mgr
    mgr=$(Detect-PkgMgr)
    
    case $mgr in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq >/dev/null 2>&1
            apt-get install -y build-essential libpcre2-dev zlib1g-dev libzstd-dev curl gcc make cargo pkg-config clang gawk cmake >/dev/null 2>&1
            ;;
        dnf)
            dnf install -y -q gcc gcc-c++ make pcre2-devel zlib-devel libzstd-devel curl perl cargo pkgconf-pkg-config clang gawk cmake >/dev/null 2>&1
            ;;
        *)
            Stop-Script "Unsupported package manager. Only apt and dnf are supported."
            ;;
    esac
    
    # Verify cargo availability
    if ! command -v cargo >/dev/null 2>&1; then
        Write-Log WARN "Cargo not found. Installing rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi
    
    Write-Log INFO "Dependencies installed"
}

Update-SystemPackages() {
    [[ $EUID -eq 0 ]] || Stop-Script "Run as root"
    
    Write-Log INFO "Updating system packages"
    
    local mgr
    mgr=$(Detect-PkgMgr)
    
    case $mgr in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq || Write-Log WARN "apt-get update failed"
            apt-get upgrade -y -q || Stop-Script "apt-get upgrade failed"
            ;;
        dnf)
            dnf upgrade -y -q || Stop-Script "dnf upgrade failed"
            ;;
        *)
            Write-Log WARN "Unable to detect package manager"
            ;;
    esac
    
    Write-Log INFO "System packages updated"
}

# ============================================================================
# Download Sources
# ============================================================================

Get-Sources() {
    cd "$BUILD_DIR" || Stop-Script "Cannot cd to BUILD_DIR: $BUILD_DIR"
    
    Write-Log INFO "Downloading sources"
    
    Get-File "$NGINX_URL" "nginx.tgz" "$NGINX_SHA256"
    Get-File "$OPENSSL_URL" "openssl.tgz" "$OPENSSL_SHA256"
    Get-File "$PCRE2_URL" "pcre2.tgz" "$PCRE2_SHA256"
    Get-File "$ZLIB_URL" "zlib.tgz" "$ZLIB_SHA256"
    Get-File "$HEADERS_MORE_URL" "headers.tgz" "$HEADERS_MORE_SHA256"
    Get-File "$ZSTD_MODULE_URL" "zstd.tgz" "$ZSTD_MODULE_SHA256"
    Get-File "$ACME_MODULE_URL" "acme.tgz" "$ACME_MODULE_SHA256"
    
    Write-Log INFO "Extracting archives"
    
    # Clean previous extractions
    rm -rf nginx openssl pcre2 zlib headers-more zstd-module nginx-acme 2>/dev/null || true
    
    tar xzf nginx.tgz && mv "nginx-${NGINX_VERSION}" nginx
    tar xzf openssl.tgz && mv "openssl-${OPENSSL_VERSION}" openssl
    tar xzf pcre2.tgz && mv "pcre2-${PCRE2_VERSION}" pcre2
    tar xzf zlib.tgz && mv "zlib-${ZLIB_VERSION}" zlib
    tar xzf headers.tgz && mv "headers-more-nginx-module-${HEADERS_MORE_VERSION}" headers-more
    tar xzf zstd.tgz && mv "zstd-nginx-module-${ZSTD_MODULE_VERSION}" zstd-module
    tar xzf acme.tgz && mv "nginx-acme-${ACME_MODULE_VERSION}" nginx-acme
    
    Write-Log INFO "Sources ready"
}

# ============================================================================
# Build Functions
# ============================================================================

Build-Nginx() {
    local use_system_ssl=false
    local ssl_opt=""
    
    # Detect WSL ARM64 and fall back to system OpenSSL
    if [[ $(uname -r) =~ microsoft ]] && [[ $(uname -m) == aarch64 ]]; then
        Write-Log WARN "WSL ARM64 detected - using system OpenSSL"
        use_system_ssl=true
    fi
    
    # Clean temporary files
    rm -rf /tmp/cc* /tmp/tmp.* /tmp/nginx-build-* 2>/dev/null || true
    
    # Check disk space in /tmp
    local tmp_space
    tmp_space=$(df /tmp | tail -1 | awk '{print $4}')
    if [[ $tmp_space -lt 1048576 ]]; then
        Write-Log WARN "Low disk space in /tmp, using build directory"
        export TMPDIR="$BUILD_DIR"
    fi
    
    # Ensure cc symlink exists
    if ! command -v cc >/dev/null 2>&1; then
        ln -sf /usr/bin/gcc /usr/local/bin/cc 2>/dev/null || true
        export PATH="/usr/local/bin:$PATH"
    fi
    
    # Build OpenSSL standalone for ACME module
    if [[ $use_system_ssl == false ]]; then
        Write-Log INFO "Building OpenSSL ${OPENSSL_VERSION} (Standalone)"
        cd "$BUILD_DIR/openssl" || Stop-Script "OpenSSL source missing"
        
        local arch
        arch=$(uname -m)
        case $arch in
            x86_64)  arch="linux-x86_64" ;;
            aarch64) arch="linux-aarch64" ;;
            armv7l)  arch="linux-armv4" ;;
            *)       arch="linux-generic64" ;;
        esac
        
        export TMPDIR="$BUILD_DIR"
        export CC=gcc
        
        local output configure_exit
        output=$(./Configure "$arch" \
            --prefix="$(pwd)/../openssl-install" \
            --openssldir="$(pwd)/../openssl-install/ssl" \
            enable-tls1_3 shared -fPIC 2>&1) && configure_exit=0 || configure_exit=$?
        output=$(printf '%s\n' "$output" | grep -v '^DEBUG:' | grep -v '^No value given' || true)
        if [[ $configure_exit -ne 0 ]]; then
            use_system_ssl=true
            Write-Log WARN "OpenSSL configure failed"
        else
            local make_exit
            output=$(make -j"$(nproc)" 2>&1) && make_exit=0 || make_exit=$?
            output=$(printf '%s\n' "$output" | grep -v '^DEBUG:' || true)
            if [[ $make_exit -ne 0 ]]; then
                use_system_ssl=true
                Write-Log WARN "OpenSSL build failed"
            else
                make install_sw 2>&1 | grep -v '^DEBUG:' || true
                ssl_opt="--with-openssl=$BUILD_DIR/openssl"
                Write-Log INFO "OpenSSL built successfully"
            fi
        fi
    fi
    
    # Fallback to system OpenSSL
    if [[ $use_system_ssl == true ]]; then
        local mgr
        mgr=$(Detect-PkgMgr)
        case $mgr in
            apt) apt-get install -y libssl-dev >/dev/null 2>&1 ;;
            dnf) dnf install -y openssl-devel >/dev/null 2>&1 ;;
        esac
        Write-Log INFO "Using system OpenSSL"
    fi
    
    # Build NGINX
    Write-Log INFO "Building Nginx ${NGINX_VERSION}"
    cd "$BUILD_DIR/nginx" || Stop-Script "Nginx source missing"
    
    export TMPDIR="$BUILD_DIR"
    export CC=gcc
    
    # Verify libzstd availability
    if command -v ldconfig >/dev/null 2>&1; then
        if ! ldconfig -p 2>/dev/null | grep -q "libzstd.so"; then
            Stop-Script "Shared libzstd not found. Install libzstd-dev/devel"
        fi
    else
        if [[ ! -f /usr/lib/libzstd.so && ! -f /usr/lib64/libzstd.so && ! -f /usr/local/lib/libzstd.so ]]; then
            Stop-Script "Shared libzstd not found"
        fi
    fi
    
    export LDFLAGS="-lzstd"
    
    local output
    if ! output=$(./configure \
        --with-compat \
        --prefix=/usr/local/nginx \
        --sbin-path=/usr/sbin/nginx \
        --conf-path=/etc/nginx/nginx.conf \
        --http-log-path=/var/log/nginx/access.log \
        --error-log-path=/var/log/nginx/error.log \
        --pid-path=/run/nginx.pid \
        --lock-path=/var/lock/nginx.lock \
        $ssl_opt \
        --with-pcre="$BUILD_DIR/pcre2" \
        --with-zlib="$BUILD_DIR/zlib" \
        --with-pcre-jit \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-http_v3_module \
        --with-http_gzip_static_module \
        --with-http_stub_status_module \
        --with-http_realip_module \
        --with-http_sub_module \
        --with-http_secure_link_module \
        --with-stream \
        --with-stream_ssl_module \
        --with-stream_ssl_preread_module \
        --with-stream_realip_module \
        --with-file-aio \
        --with-threads \
        --modules-path=/etc/nginx/modules \
        --add-dynamic-module="$BUILD_DIR/headers-more" \
        --add-dynamic-module="$BUILD_DIR/zstd-module" \
        2>&1); then
        Write-Log ERROR "Configure output: $(echo "$output" | tail -20)"
        Stop-Script "Configure failed"
    fi
    
    # Patch Makefile for shared libzstd
    if [[ -f "objs/Makefile" ]]; then
        Write-Log INFO "Patching nginx Makefile for shared libzstd"
        sed -i 's/-l:libzstd\.a/-lzstd/g' "objs/Makefile"
    fi
    
    if ! output=$(make -j"$(nproc)" 2>&1); then
        Write-Log ERROR "Make output: $(echo "$output" | tail -20)"
        Stop-Script "Build failed"
    fi
    
    # Build ACME Module
    Write-Log INFO "Building ACME module ${ACME_MODULE_VERSION}"
    cd "$BUILD_DIR/nginx-acme" || Stop-Script "ACME source missing"
    
    export NGINX_BUILD_DIR="$BUILD_DIR/nginx/objs"
    export NGX_ACME_STATE_PREFIX="/var/cache/nginx"
    
    if [[ -f "$HOME/.cargo/env" ]]; then
        source "$HOME/.cargo/env"
    fi
    
    # Verify Rust toolchain
    if ! command -v rustc >/dev/null 2>&1; then
        Write-Log WARN "rustc not found, installing rustup"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi
    
    # Setup OpenSSL for Rust
    if [[ -d "$BUILD_DIR/openssl-install" ]]; then
        export OPENSSL_DIR="$BUILD_DIR/openssl-install"
        if [[ -d "$BUILD_DIR/openssl-install/lib64" ]]; then
            export OPENSSL_LIB_DIR="$BUILD_DIR/openssl-install/lib64"
        else
            export OPENSSL_LIB_DIR="$BUILD_DIR/openssl-install/lib"
        fi
        export OPENSSL_INCLUDE_DIR="$BUILD_DIR/openssl-install/include"
        export OPENSSL_STATIC=1
        Write-Log INFO "Using custom OpenSSL for ACME (Static Link): $OPENSSL_DIR"
    fi
    
    local cargo_output
    if ! cargo_output=$(cargo build --release 2>&1); then
        Write-Log ERROR "ACME build failed: $(echo "$cargo_output" | tail -20)"
        Stop-Script "ACME module build failed"
    fi
    
    mkdir -p "$BUILD_DIR/nginx-acme/objs"
    cp target/release/libnginx_acme.so "$BUILD_DIR/nginx-acme/objs/ngx_http_acme_module.so" || true
    
    Write-Log INFO "ACME module built successfully"
    Write-Log INFO "Build complete"
}

# ============================================================================
# Configuration Functions
# ============================================================================

Install-HtmlFiles() {
    Write-Log INFO "Installing HTML files"
    mkdir -p /usr/share/nginx/html
    
    cat > /usr/share/nginx/html/index.html <<'EOF'
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>
</body>
</html>
EOF
    
    chmod 0644 /usr/share/nginx/html/*.html 2>/dev/null || true
}

New-SelfSignedCertificate() {
    Write-Log INFO "Generating self-signed TLS certificate"
    mkdir -p /etc/nginx/ssl
    
    local ssl_bin
    ssl_bin=$(command -v openssl || true)
    
    # Prefer built OpenSSL binary
    if [[ -x "${BUILD_DIR}/openssl-install/bin/openssl" ]]; then
        ssl_bin="${BUILD_DIR}/openssl-install/bin/openssl"
    fi
    
    # Fallback: install openssl
    if [[ -z "$ssl_bin" ]]; then
        local mgr
        mgr=$(Detect-PkgMgr)
        case $mgr in
            apt) apt-get install -y openssl >/dev/null 2>&1 ;;
            dnf) dnf install -y openssl >/dev/null 2>&1 ;;
        esac
        ssl_bin=$(command -v openssl || true)
    fi
    
    [[ -n "$ssl_bin" ]] || Stop-Script "openssl not found"
    
    local output
    
    # Setup library path for custom OpenSSL
    if [[ "$ssl_bin" == *"/openssl-install/bin/openssl" ]]; then
        local openssl_libdir="${BUILD_DIR}/openssl-install/lib"
        if [[ -d "${BUILD_DIR}/openssl-install/lib64" ]]; then
            openssl_libdir="${BUILD_DIR}/openssl-install/lib64"
        fi
        
        if ! output=$(LD_LIBRARY_PATH="$openssl_libdir:${LD_LIBRARY_PATH:-}" OPENSSL_CONF=/dev/null "$ssl_bin" req -x509 -newkey ec \
            -pkeyopt ec_paramgen_curve:secp384r1 \
            -days 365 -nodes \
            -keyout /etc/nginx/ssl/nginx.key \
            -out /etc/nginx/ssl/nginx.crt \
            -subj '/CN=localhost' \
            -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' 2>&1); then
            Write-Log ERROR "OpenSSL output: $output"
            Stop-Script "Certificate generation failed"
        fi
    else
        if ! output=$(OPENSSL_CONF=/dev/null "$ssl_bin" req -x509 -newkey ec \
            -pkeyopt ec_paramgen_curve:secp384r1 \
            -days 365 -nodes \
            -keyout /etc/nginx/ssl/nginx.key \
            -out /etc/nginx/ssl/nginx.crt \
            -subj '/CN=localhost' \
            -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' 2>&1); then
            Write-Log ERROR "OpenSSL output: $output"
            Stop-Script "Certificate generation failed"
        fi
    fi
    
    chmod 600 /etc/nginx/ssl/nginx.key
    chmod 644 /etc/nginx/ssl/nginx.crt
}

New-NginxConfig() {
    Write-Log INFO "Creating nginx configuration"
    
    cat > /etc/nginx/nginx.conf <<'EOF'
load_module /etc/nginx/modules/ngx_http_zstd_filter_module.so;
load_module /etc/nginx/modules/ngx_http_zstd_static_module.so;
load_module /etc/nginx/modules/ngx_http_headers_more_filter_module.so;
load_module /etc/nginx/modules/ngx_http_acme_module.so;

user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    server_tokens off;
    more_set_headers 'Server: nginx';

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    tcp_nopush      on;
    tcp_nodelay     on;
    keepalive_timeout  65;
    types_hash_max_size 2048;

    # Gzip compression
    gzip  on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss application/rss+xml font/truetype font/opentype application/vnd.ms-fontobject image/svg+xml;

    # Zstd compression
    zstd on;
    zstd_comp_level 6;
    zstd_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss application/rss+xml font/truetype font/opentype application/vnd.ms-fontobject image/svg+xml;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;

    # QUIC configuration
    quic_retry on;
    ssl_early_data on;

    server {
        listen 80;
        listen [::]:80;
        server_name _;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl;
        listen [::]:443 ssl;
        listen 443 quic reuseport;
        listen [::]:443 quic reuseport;

        http2 on;
        http3 on;

        server_name localhost;

        ssl_certificate /etc/nginx/ssl/nginx.crt;
        ssl_certificate_key /etc/nginx/ssl/nginx.key;

        add_header Alt-Svc 'h3=":443"; ma=86400' always;
        add_header X-Protocol $server_protocol always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

        location / {
            root   /usr/share/nginx/html;
            index  index.html index.htm;
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   /usr/share/nginx/html;
        }
    }
}
EOF
}

# ============================================================================
# Install/Remove Functions
# ============================================================================

Install-Nginx() {
    Write-Log INFO "Installing Nginx"
    
    # Backup existing configuration
    if [[ -d /etc/nginx ]]; then
        mkdir -p "$BACKUP_DIR"
        cp -a /etc/nginx "$BACKUP_DIR/" || true
    fi
    
    # Install binaries
    cd "$BUILD_DIR/nginx"
    local output
    if ! output=$(make install 2>&1); then
        Write-Log ERROR "Install output: $(echo "$output" | tail -10)"
        Stop-Script "Nginx install failed"
    fi
    
    # Create directories
    mkdir -p /etc/nginx/{conf.d,modules,sites-available,sites-enabled}
    mkdir -p /var/log/nginx /var/cache/nginx /usr/share/nginx/html
    
    # Install dynamic modules
    cp objs/*.so /etc/nginx/modules/ 2>/dev/null || true
    cp "$BUILD_DIR/nginx-acme/objs/ngx_http_acme_module.so" /etc/nginx/modules/ 2>/dev/null || true
    
    # Install configuration files
    Install-HtmlFiles
    New-SelfSignedCertificate
    New-NginxConfig
    
    # Create nginx user
    if ! id nginx >/dev/null 2>&1; then
        useradd -r -s /sbin/nologin nginx || true
    fi
    
    chown -R nginx:nginx /var/log/nginx /var/cache/nginx
    chmod 755 /etc/nginx/{conf.d,modules}
    
    # Create systemd service
    cat > /etc/systemd/system/nginx.service <<'EOF'
[Unit]
Description=Nginx HTTP Server
After=network.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable nginx >/dev/null 2>&1
    nginx -t && systemctl start nginx
    
    Write-Log INFO "Nginx ${NGINX_VERSION} with OpenSSL ${OPENSSL_VERSION} installed"
    Write-Log INFO "Access: https://localhost"
    nginx -V 2>&1 | head -n1 || true
    
    Test-NginxInstallation || Write-Log WARN "Post-install checks detected issues"
}

Test-NginxInstallation() {
    Write-Log INFO "Running post-install checks"
    
    [[ -f /etc/nginx/ssl/nginx.crt && -f /etc/nginx/ssl/nginx.key ]] || {
        Write-Log ERROR "SSL certificates missing"
        return 1
    }
    
    if [[ ! -f /etc/nginx/modules/ngx_http_acme_module.so ]]; then
        Write-Log WARN "ACME module not found"
    else
        Write-Log INFO "ACME module present"
    fi
    
    if ! nginx -t >/dev/null 2>&1; then
        Write-Log ERROR "nginx -t failed"
        return 1
    fi
    
    if ! systemctl is-active --quiet nginx 2>/dev/null; then
        Write-Log WARN "Nginx service not active"
    fi
    
    if systemctl is-active --quiet nginx 2>/dev/null; then
        Write-Log INFO "Nginx service is active"
    fi

    curl -k https://localhost -I >/dev/null 2>&1 || Write-Log WARN "curl to https://localhost failed"

    return 0
}

Remove-Nginx() {
    Write-Log INFO "Removing Nginx"
    
    systemctl stop nginx 2>/dev/null || true
    rm -rf /usr/sbin/nginx /etc/nginx /var/log/nginx /var/cache/nginx
    userdel nginx 2>/dev/null || true
    
    Write-Log INFO "Nginx removed"
}

Test-RunningWebServers() {
    local port443
    port443=$(lsof -ti :443 2>/dev/null | head -n1 || true)
    
    if [[ -n "$port443" ]]; then
        local proc
        proc=$(ps -p "$port443" -o comm= 2>/dev/null || true)
        Write-Log WARN "Port 443 in use by: $proc"
        
        read -r -p "Stop conflicting services? [y/N]: " response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            systemctl stop apache2 2>/dev/null || true
            systemctl stop httpd 2>/dev/null || true
            systemctl stop nginx 2>/dev/null || true
            Write-Log INFO "Services stopped"
        else
            Stop-Script "Cannot proceed with port 443 in use"
        fi
    fi
}

# ============================================================================
# Main Entry Point
# ============================================================================

trap 'rm -rf "$BUILD_DIR"' EXIT

case "${1:-install}" in
    install)
        Update-SystemPackages
        Test-RunningWebServers
        Install-Dependencies
        Get-Sources
        Build-Nginx
        Install-Nginx
        echo
        echo "Installation log: $LOG_FILE"
        ;;
    remove)
        Remove-Nginx
        echo
        echo "Removal log: $LOG_FILE"
        ;;
    *)
        echo "Usage: $0 {install|remove}"
        exit 1
        ;;
esac
