#!/usr/bin/env bash
#########################################################################
# NGINX Compiler and Installer
# 
# This script compiles and installs NGINX with OpenSSL from source
# 
# NGINX releases repository: https://github.com/nginx/nginx/releases
# 
# Version information:
# - 1.29.x: mainline branch (newer features, less stable) - using 1.29.0
# - 1.28.x: stable branch (recommended for production)
# 
# OpenSSL releases repository: https://github.com/openssl/openssl/releases
# - Latest stable: 3.5.1
# 
# This script downloads source code, verifies checksums, compiles, and
# installs NGINX with the latest OpenSSL for HTTP/3 support.
#########################################################################

# Safer error handling
set -euo pipefail

# Version definitions
NGINX_VERSION="1.29.0"
OPENSSL_VERSION="3.5.1"
PCRE2_VERSION="10.45"
ZLIB_VERSION="1.3.1"

# SHA256 checksums for verification
# These are the actual checksums for the specified versions
NGINX_SHA256="109754dfe8e5169a7a0cf0db6718e7da2db495753308f933f161e525a579a664"
OPENSSL_SHA256="529043b15cffa5f36077a4d0af83f3de399807181d607441d734196d889b641f"

# Build configuration
BUILD_DIR="/tmp/nginx-build-$$"
PREFIX="/usr/local/nginx"
LOG_DIR="/tmp/nginx-build-logs-$$"

# Color definitions
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly NC='\033[0m' # No Color
readonly BOLD='\033[1m'

# Create directories
mkdir -p "$BUILD_DIR" "$LOG_DIR"

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_step() { echo -e "${PURPLE}[→]${NC} ${BOLD}$1${NC}"; }

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

# Print header
print_header() {
    echo
    echo -e "${BOLD}NGINX Compiler and Installer${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "NGINX ${NGINX_VERSION} with OpenSSL ${OPENSSL_VERSION}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
}

# Verify file checksums
verify_checksum() {
    local file="$1"
    local expected_sha="$2"
    
    if [ -z "$expected_sha" ]; then
        log_warn "No checksum available for $file - skipping verification"
        return 0
    fi
    
    local actual_sha
    actual_sha=$(sha256sum "$file" | cut -d' ' -f1)
    
    if [ "$actual_sha" = "$expected_sha" ]; then
        log_success "Checksum verified for $file"
        return 0
    else
        log_error "Checksum mismatch for $file"
        log_error "Expected: $expected_sha"
        log_error "Actual:   $actual_sha"
        return 1
    fi
}

# Install dependencies
install_dependencies() {
    log_step "Installing build dependencies"
    
    if command -v dnf >/dev/null 2>&1; then
        log_info "Detected Fedora/RHEL system"
        if dnf --version 2>/dev/null | grep -q "dnf5"; then
            dnf install -y @development-tools
        else
            dnf groupinstall -y "Development Tools"
        fi
        dnf install -y pcre2-devel zlib-devel perl wget gcc make
    elif command -v apt >/dev/null 2>&1; then
        log_info "Detected Ubuntu/Debian system"
        export DEBIAN_FRONTEND=noninteractive
        apt update
        apt install -y build-essential libpcre2-dev zlib1g-dev perl wget gcc make
    else
        log_error "Unsupported package manager"
        exit 1
    fi
    
    log_success "Dependencies installed"
}

# Download and verify sources
download_sources() {
    log_step "Downloading source files"
    
    cd "$BUILD_DIR" || exit 1
    
    # Download sources
    log_info "Downloading NGINX ${NGINX_VERSION}"
    wget -q "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" -O "nginx-${NGINX_VERSION}.tar.gz"
    
    log_info "Downloading OpenSSL ${OPENSSL_VERSION}"
    wget -q "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
    
    log_info "Downloading PCRE2 ${PCRE2_VERSION}"
    wget -q "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/pcre2-${PCRE2_VERSION}.tar.gz"
    
    log_info "Downloading zlib ${ZLIB_VERSION}"
    wget -q "https://zlib.net/zlib-${ZLIB_VERSION}.tar.gz"
    
    # Verify checksums
    log_info "Verifying checksums"
    verify_checksum "nginx-${NGINX_VERSION}.tar.gz" "$NGINX_SHA256" || exit 1
    verify_checksum "openssl-${OPENSSL_VERSION}.tar.gz" "$OPENSSL_SHA256" || exit 1
    
    # Extract sources
    log_info "Extracting source files"
    tar xf "nginx-${NGINX_VERSION}.tar.gz" || exit 1
    tar xf "openssl-${OPENSSL_VERSION}.tar.gz" || exit 1
    tar xf "pcre2-${PCRE2_VERSION}.tar.gz" || exit 1
    tar xf "zlib-${ZLIB_VERSION}.tar.gz" || exit 1
    
    log_success "Source files downloaded and extracted"
}

# Build OpenSSL
build_openssl() {
    log_step "Building OpenSSL ${OPENSSL_VERSION}"
    
    cd "$BUILD_DIR/openssl-${OPENSSL_VERSION}" || exit 1
    
    ./Configure linux-x86_64 \
        --prefix="$BUILD_DIR/openssl-install" \
        --openssldir="$BUILD_DIR/openssl-install/ssl" \
        enable-tls1_3 \
        no-shared \
        no-tests \
        -fPIC \
        -O3 &>"$LOG_DIR/openssl-build.log"
    
    make -j"$(nproc)" &>"$LOG_DIR/openssl-make.log"
    make install_sw &>"$LOG_DIR/openssl-install.log"
    
    if [ $? -eq 0 ]; then
        log_success "OpenSSL built successfully"
    else
        log_error "OpenSSL build failed. Check logs in $LOG_DIR"
        exit 1
    fi
    
    cd "$BUILD_DIR" || exit 1
}

# Configure and build NGINX
build_nginx() {
    log_step "Configuring NGINX ${NGINX_VERSION}"
    
    cd "$BUILD_DIR/nginx-${NGINX_VERSION}" || exit 1
    
    # Set build flags
    export CFLAGS="-I${BUILD_DIR}/openssl-install/include -O3"
    export LDFLAGS="-L${BUILD_DIR}/openssl-install/lib64 -L${BUILD_DIR}/openssl-install/lib"
    
    ./configure \
        --prefix="$PREFIX" \
        --sbin-path=/usr/sbin/nginx \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --http-log-path=/var/log/nginx/access.log \
        --pid-path=/run/nginx.pid \
        --lock-path=/run/nginx.lock \
        --http-client-body-temp-path=/var/cache/nginx/client_temp \
        --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
        --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
        --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
        --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
        --user=nginx \
        --group=nginx \
        --with-openssl="$BUILD_DIR/openssl-${OPENSSL_VERSION}" \
        --with-pcre="$BUILD_DIR/pcre2-${PCRE2_VERSION}" \
        --with-pcre-jit \
        --with-zlib="$BUILD_DIR/zlib-${ZLIB_VERSION}" \
        --with-compat \
        --with-file-aio \
        --with-threads \
        --with-http_addition_module \
        --with-http_auth_request_module \
        --with-http_dav_module \
        --with-http_flv_module \
        --with-http_gunzip_module \
        --with-http_gzip_static_module \
        --with-http_mp4_module \
        --with-http_random_index_module \
        --with-http_realip_module \
        --with-http_secure_link_module \
        --with-http_slice_module \
        --with-http_ssl_module \
        --with-http_stub_status_module \
        --with-http_sub_module \
        --with-http_v2_module \
        --with-http_v3_module \
        --with-ld-opt="$LDFLAGS" &>"$LOG_DIR/nginx-configure.log"
    
    if [ $? -ne 0 ]; then
        log_error "NGINX configuration failed. Check $LOG_DIR/nginx-configure.log"
        exit 1
    fi
    
    log_step "Building NGINX"
    make -j"$(nproc)" &>"$LOG_DIR/nginx-build.log"
    
    if [ $? -eq 0 ]; then
        log_success "NGINX built successfully"
    else
        log_error "NGINX build failed. Check $LOG_DIR/nginx-build.log"
        exit 1
    fi
}

# Install NGINX files and configure system
install_nginx() {
    log_step "Installing NGINX"
    
    # Create nginx user
    if ! id nginx >/dev/null 2>&1; then
        useradd --system --home /var/cache/nginx --shell /sbin/nologin --comment "nginx user" nginx
        log_info "Created nginx user"
    fi
    
    # Create directories
    mkdir -p /var/cache/nginx/{client_temp,proxy_temp,fastcgi_temp,uwsgi_temp,scgi_temp}
    mkdir -p /var/log/nginx
    mkdir -p /etc/nginx/conf.d
    
    # Install NGINX
    cd "$BUILD_DIR/nginx-${NGINX_VERSION}" || exit 1
    make install &>"$LOG_DIR/nginx-install.log"
    
    if [ $? -eq 0 ]; then
        log_success "NGINX installed successfully"
    else
        log_error "NGINX installation failed. Check $LOG_DIR/nginx-install.log"
        exit 1
    fi
    
    # Set permissions
    chown -R nginx:nginx /var/cache/nginx /var/log/nginx
    chmod 755 /var/cache/nginx /var/log/nginx
    
    # Create basic configuration
    create_basic_config
    
    # Create mime.types file
    create_mime_types
    
    # Create systemd service
    create_systemd_service
    
    log_success "NGINX installation completed"
}

# Create basic NGINX configuration
create_basic_config() {
    cat > /etc/nginx/nginx.conf << 'EOF'
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    
    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:50m;
    ssl_session_timeout 1d;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript 
               application/xml+rss application/atom+xml image/svg+xml;
    
    # Include additional configurations
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
EOF

    # Create default index.html
    mkdir -p /usr/share/nginx/html
    cat > /usr/share/nginx/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to NGINX</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
    </style>
</head>
<body>
    <h1>Welcome to NGINX!</h1>
    <p>If you see this page, the web server is successfully installed and working.</p>
    <p>NGINX has been compiled with OpenSSL for HTTP/3 support.</p>
</body>
</html>
EOF
}

# Create mime.types file
create_mime_types() {
    cat > /etc/nginx/mime.types << 'EOF'
types {
    text/html                             html htm shtml;
    text/css                              css;
    text/xml                              xml;
    image/gif                             gif;
    image/jpeg                            jpeg jpg;
    application/javascript                js;
    application/atom+xml                  atom;
    application/rss+xml                   rss;

    text/mathml                           mml;
    text/plain                            txt;
    text/vnd.sun.j2me.app-descriptor      jad;
    text/vnd.wap.wml                      wml;
    text/x-component                      htc;

    image/avif                            avif;
    image/png                             png;
    image/svg+xml                         svg svgz;
    image/tiff                            tif tiff;
    image/vnd.wap.wbmp                    wbmp;
    image/webp                            webp;
    image/x-icon                          ico;
    image/x-jng                           jng;
    image/x-ms-bmp                        bmp;

    font/woff                             woff;
    font/woff2                            woff2;

    application/java-archive              jar war ear;
    application/json                      json;
    application/mac-binhex40              hqx;
    application/msword                    doc;
    application/pdf                       pdf;
    application/postscript                ps eps ai;
    application/rtf                       rtf;
    application/vnd.apple.mpegurl         m3u8;
    application/vnd.google-earth.kml+xml  kml;
    application/vnd.google-earth.kmz      kmz;
    application/vnd.ms-excel              xls;
    application/vnd.ms-fontobject         eot;
    application/vnd.ms-powerpoint         ppt;
    application/vnd.oasis.opendocument.graphics        odg;
    application/vnd.oasis.opendocument.presentation    odp;
    application/vnd.oasis.opendocument.spreadsheet     ods;
    application/vnd.oasis.opendocument.text            odt;
    application/vnd.openxmlformats-officedocument.presentationml.presentation    pptx;
    application/vnd.openxmlformats-officedocument.spreadsheetml.sheet             xlsx;
    application/vnd.openxmlformats-officedocument.wordprocessingml.document       docx;
    application/vnd.wap.wmlc              wmlc;
    application/wasm                      wasm;
    application/x-7z-compressed           7z;
    application/x-cocoa                   cco;
    application/x-java-archive-diff       jardiff;
    application/x-java-jnlp-file          jnlp;
    application/x-makeself                run;
    application/x-perl                    pl pm;
    application/x-pilot                   prc pdb;
    application/x-rar-compressed          rar;
    application/x-redhat-package-manager  rpm;
    application/x-sea                     sea;
    application/x-shockwave-flash         swf;
    application/x-stuffit                 sit;
    application/x-tcl                     tcl tk;
    application/x-x509-ca-cert            der pem crt;
    application/x-xpinstall               xpi;
    application/xhtml+xml                 xhtml;
    application/xspf+xml                  xspf;
    application/zip                       zip;

    application/octet-stream              bin exe dll;
    application/octet-stream              deb;
    application/octet-stream              dmg;
    application/octet-stream              iso img;
    application/octet-stream              msi msp msm;

    audio/midi                            mid midi kar;
    audio/mpeg                            mp3;
    audio/ogg                             ogg;
    audio/x-m4a                           m4a;
    audio/x-realaudio                     ra;

    video/3gpp                            3gpp 3gp;
    video/mp2t                            ts;
    video/mp4                             mp4;
    video/mpeg                            mpeg mpg;
    video/quicktime                       mov;
    video/webm                            webm;
    video/x-flv                           flv;
    video/x-m4v                           m4v;
    video/x-mng                           mng;
    video/x-ms-asf                        asx asf;
    video/x-ms-wmv                        wmv;
    video/x-msvideo                       avi;
}
EOF
}

# Create systemd service
create_systemd_service() {
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
    log_info "Created systemd service"
}

# Show installation summary
show_summary() {
    echo
    echo -e "${BOLD}Installation Summary${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if command -v nginx >/dev/null 2>&1; then
        local nginx_version=$(nginx -v 2>&1 | grep -o 'nginx/[0-9.]*')
        local openssl_version=$(nginx -V 2>&1 | grep -o 'built with OpenSSL [0-9.]*' | cut -d' ' -f4)
        
        echo -e "${GREEN}✓${NC} NGINX ${nginx_version} installed"
        echo -e "${GREEN}✓${NC} OpenSSL ${openssl_version} with HTTP/3 support"
        echo -e "${GREEN}✓${NC} Systemd service created"
    else
        echo -e "${RED}✗${NC} NGINX installation may have failed"
    fi
    
    echo
    echo -e "${BOLD}Quick Start${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Start NGINX:    ${BLUE}sudo systemctl start nginx${NC}"
    echo -e "Stop NGINX:     ${BLUE}sudo systemctl stop nginx${NC}"
    echo -e "Restart NGINX:  ${BLUE}sudo systemctl restart nginx${NC}"
    echo -e "Test config:    ${BLUE}sudo nginx -t${NC}"
    echo -e "View logs:      ${BLUE}sudo tail -f /var/log/nginx/error.log${NC}"
    echo
    echo -e "Configuration:  ${BLUE}/etc/nginx/nginx.conf${NC}"
    echo -e "Site configs:   ${BLUE}/etc/nginx/conf.d/${NC}"
    echo
}

# Install NGINX
install() {
    log_info "Starting NGINX ${NGINX_VERSION} installation with OpenSSL ${OPENSSL_VERSION}"
    
    # Safety check for SSH sessions
    if [[ -n "${SSH_CONNECTION:-}" ]] && [[ "${FORCE_SSH_INSTALL:-}" != "1" ]]; then
        log_error "Running in SSH session! This will affect web services."
        log_warn "If you have console access, run: FORCE_SSH_INSTALL=1 $0 install"
        exit 1
    fi
    
    # Confirm installation
    if [[ "${CONFIRM:-}" != "yes" ]]; then
        if [[ -t 0 ]]; then
            # Interactive mode
            read -rp "Proceed with NGINX installation? This will compile and install NGINX. [y/N] " answer
            [[ "${answer,,}" != "y" ]] && { log_error "Installation cancelled"; exit 0; }
        else
            # Non-interactive mode (piped)
            log_error "Non-interactive mode detected. Use: curl ... | CONFIRM=yes sudo bash -s install"
            exit 0
        fi
    fi
    
    check_root
    print_header
    
    install_dependencies
    download_sources
    build_openssl
    build_nginx
    install_nginx
    
    show_summary
    
    log_success "NGINX installation completed successfully!"
}

# Remove NGINX installation
remove() {
    log_info "Removing NGINX installation..."
    
    # Stop NGINX service if running
    if systemctl is-active --quiet nginx 2>/dev/null; then
        log_info "Stopping NGINX service..."
        systemctl stop nginx
    fi
    
    # Disable service
    if systemctl is-enabled --quiet nginx 2>/dev/null; then
        log_info "Disabling NGINX service..."
        systemctl disable nginx
    fi
    
    # Remove systemd service file
    if [[ -f /etc/systemd/system/nginx.service ]]; then
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
}

# Verify NGINX installation
verify() {
    log_info "Verifying NGINX installation..."
    
    local issues=0
    
    # Check if NGINX binary exists and is executable
    if [[ -x /usr/sbin/nginx ]]; then
        local nginx_version=$(nginx -v 2>&1 | grep -o 'nginx/[0-9.]*' || echo "unknown")
        log_success "NGINX binary: ${nginx_version}"
    else
        log_error "NGINX binary not found or not executable"
        ((issues++))
    fi
    
    # Check configuration file
    if [[ -f /etc/nginx/nginx.conf ]]; then
        if nginx -t >/dev/null 2>&1; then
            log_success "NGINX configuration is valid"
        else
            log_error "NGINX configuration has errors:"
            nginx -t
            ((issues++))
        fi
    else
        log_error "NGINX configuration file not found"
        ((issues++))
    fi
    
    # Check systemd service
    if [[ -f /etc/systemd/system/nginx.service ]]; then
        if systemctl is-enabled --quiet nginx 2>/dev/null; then
            log_success "NGINX service is enabled"
        else
            log_warn "NGINX service is not enabled"
        fi
        
        if systemctl is-active --quiet nginx 2>/dev/null; then
            log_success "NGINX service is running"
        else
            log_warn "NGINX service is not running"
        fi
    else
        log_error "NGINX systemd service not found"
        ((issues++))
    fi
    
    # Check OpenSSL integration
    if nginx -V 2>&1 | grep -q "built with OpenSSL"; then
        local openssl_version=$(nginx -V 2>&1 | grep -o 'built with OpenSSL [0-9.]*' | cut -d' ' -f4)
        log_success "OpenSSL integration: ${openssl_version}"
    else
        log_error "OpenSSL integration not found"
        ((issues++))
    fi
    
    # Check HTTP/3 support
    if nginx -V 2>&1 | grep -q "http_v3_module"; then
        log_success "HTTP/3 support: enabled"
    else
        log_warn "HTTP/3 support: not enabled"
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
    case "${1:-help}" in
        install)
            install
            ;;
        remove)
            check_root
            remove
            ;;
        verify)
            verify
            ;;
        *)
            echo
            echo -e "${BOLD}NGINX Compiler and Installer${NC}"
            echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "Usage: $0 {install|remove|verify}"
            echo
            echo "  install - Build and install NGINX with OpenSSL from source"
            echo "  remove  - Remove NGINX installation and clean up system"
            echo "  verify  - Check current NGINX installation status"
            echo
            echo "Environment variables:"
            echo "  CONFIRM=yes         - Skip installation confirmation"
            echo "  FORCE_SSH_INSTALL=1 - Allow installation over SSH (risky!)"
            echo "  NGINX_VERSION       - NGINX version (default: $NGINX_VERSION)"
            echo "  OPENSSL_VERSION     - OpenSSL version (default: $OPENSSL_VERSION)"
            echo "  PCRE2_VERSION       - PCRE2 version (default: $PCRE2_VERSION)"
            echo "  ZLIB_VERSION        - zlib version (default: $ZLIB_VERSION)"
            echo
            echo "Examples:"
            echo "  $0 install                    # Interactive installation"
            echo "  CONFIRM=yes $0 install       # Non-interactive installation"
            echo "  $0 verify                     # Check installation"
            echo "  $0 remove                     # Remove installation"
            echo
            ;;
    esac
}

# Run main function
main "$@"
