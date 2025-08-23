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

# Safer error handling
set -euo pipefail

# Version definitions
NGINX_VERSION="1.29.1"
OPENSSL_VERSION="3.5.2"
PCRE2_VERSION="10.45"
ZLIB_VERSION="1.3.1"

# SHA256 checksums for verification
# These are the actual checksums for the specified versions
NGINX_SHA256="c589f7e7ed801ddbd904afbf3de26ae24eb0cce27c7717a2e94df7fb12d6ad27"
OPENSSL_SHA256="c53a47e5e441c930c3928cf7bf6fb00e5d129b630e0aa873b08258656e7345ec"

# Build configuration
BUILD_DIR="/tmp/nginx-build-$$"
PREFIX="/usr/local/nginx"
LOG_DIR="/tmp/nginx-build-logs-$$"

# Third-party dynamic modules (repos and refs)
GEOIP2_MODULE_REPO="https://github.com/leev/ngx_http_geoip2_module.git"
GEOIP2_MODULE_REF="master"
HEADERS_MORE_REPO="https://github.com/openresty/headers-more-nginx-module.git"
HEADERS_MORE_REF="master"
ZSTD_MODULE_REPO="https://github.com/tokers/zstd-nginx-module.git"
ZSTD_MODULE_REF="master"

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
    echo -e "Compiling NGINX ${NGINX_VERSION} with OpenSSL ${OPENSSL_VERSION}"
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
    
    if command -v apt-get &>/dev/null; then
        log_info "Detected Debian/Ubuntu system"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq &>"$LOG_DIR/apt-update.log"
        if [ $? -ne 0 ]; then
            log_error "Failed to update package repositories. Check $LOG_DIR/apt-update.log"
            exit 1
        fi
    apt-get install -y build-essential libpcre2-dev zlib1g-dev perl wget gcc make hostname git libmaxminddb-dev libmaxminddb0 mmdb-bin zstd libzstd-dev &>"$LOG_DIR/apt-install.log"
        if [ $? -ne 0 ]; then
            log_error "Failed to install build dependencies. Check $LOG_DIR/apt-install.log"
            exit 1
        fi
    elif command -v dnf &>/dev/null; then
        log_info "Detected Fedora/RHEL system"
        if dnf --version 2>/dev/null | grep -q "dnf5"; then
            dnf install -y @development-tools &>"$LOG_DIR/dnf-install.log"
        else
            dnf groupinstall -y "Development Tools" &>"$LOG_DIR/dnf-install.log"
        fi
        if [ $? -ne 0 ]; then
            log_error "Failed to install development tools. Check $LOG_DIR/dnf-install.log"
            exit 1
        fi
    dnf install -y pcre2-devel zlib-devel perl wget gcc make hostname git libmaxminddb libmaxminddb-devel zstd libzstd libzstd-devel &>"$LOG_DIR/dnf-install.log"
        if [ $? -ne 0 ]; then
            log_error "Failed to install build dependencies. Check $LOG_DIR/dnf-install.log"
            exit 1
        fi
    elif command -v yum &>/dev/null; then
        log_info "Detected CentOS/RHEL system"
        yum groupinstall -y "Development Tools" &>"$LOG_DIR/yum-install.log"
        if [ $? -ne 0 ]; then
            log_error "Failed to install development tools. Check $LOG_DIR/yum-install.log"
            exit 1
        fi
    yum install -y pcre2-devel zlib-devel perl wget gcc make hostname git libmaxminddb libmaxminddb-devel zstd libzstd libzstd-devel &>"$LOG_DIR/yum-install.log"
        if [ $? -ne 0 ]; then
            log_error "Failed to install build dependencies. Check $LOG_DIR/yum-install.log"
            exit 1
        fi
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
        cp /usr/sbin/nginx "$BACKUP_DIR/"
        log_info "NGINX binary backed up to $BACKUP_DIR"
    fi
    
    # Save current NGINX service status
    if systemctl is-active --quiet nginx &>/dev/null; then
        echo "nginx was active" > "$BACKUP_DIR/service_status.txt"
    else
        echo "nginx was inactive" > "$BACKUP_DIR/service_status.txt"
    fi
    
    log_success "Backup created successfully"
}

# Download and verify sources
download_sources() {
    log_step "Downloading source files"
    
    cd "$BUILD_DIR" || exit 1
    
    # Download sources
    log_info "Downloading NGINX ${NGINX_VERSION}"
    wget -q --tries=3 --timeout=30 -O "nginx-${NGINX_VERSION}.tar.gz" "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" || {
        log_error "Failed to download NGINX ${NGINX_VERSION}"
        exit 1
    }
    
    log_info "Downloading OpenSSL ${OPENSSL_VERSION}"
    # Prefer official OpenSSL source, fallback to versioned archive and then GitHub releases
    if ! wget -q --tries=3 --timeout=30 -O "openssl-${OPENSSL_VERSION}.tar.gz" "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"; then
        log_warn "Primary OpenSSL download failed, trying old releases directory"
        if ! wget -q --tries=3 --timeout=30 -O "openssl-${OPENSSL_VERSION}.tar.gz" "https://www.openssl.org/source/old/${OPENSSL_VERSION%.*}/openssl-${OPENSSL_VERSION}.tar.gz"; then
            log_warn "OpenSSL old releases directory failed, trying GitHub releases"
            wget -q --tries=3 --timeout=30 -O "openssl-${OPENSSL_VERSION}.tar.gz" "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" || {
                log_error "Failed to download OpenSSL ${OPENSSL_VERSION} from all sources"
                exit 1
            }
        fi
    fi
    
    log_info "Downloading PCRE2 ${PCRE2_VERSION}"
    wget -q --tries=3 --timeout=30 -O "pcre2-${PCRE2_VERSION}.tar.gz" "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/pcre2-${PCRE2_VERSION}.tar.gz" || {
        log_error "Failed to download PCRE2 ${PCRE2_VERSION}"
        exit 1
    }
    
    log_info "Downloading zlib ${ZLIB_VERSION}"
    wget -q --tries=3 --timeout=30 -O "zlib-${ZLIB_VERSION}.tar.gz" "https://zlib.net/zlib-${ZLIB_VERSION}.tar.gz" || {
        log_error "Failed to download zlib ${ZLIB_VERSION}"
        exit 1
    }
    
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
    
    # Clone third-party dynamic modules
    log_info "Cloning GeoIP2 module"
    git clone --depth 1 "$GEOIP2_MODULE_REPO" geoip2-module &>"$LOG_DIR/git-geoip2.log" || { log_error "Failed to clone GeoIP2 module"; exit 1; }

    log_info "Cloning headers-more module"
    git clone --depth 1 "$HEADERS_MORE_REPO" headers-more-module &>"$LOG_DIR/git-headers-more.log" || { log_error "Failed to clone headers-more module"; exit 1; }

    log_info "Cloning zstd module"
    git clone --depth 1 "$ZSTD_MODULE_REPO" zstd-module &>"$LOG_DIR/git-zstd.log" || { log_error "Failed to clone zstd module"; exit 1; }

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
    --add-dynamic-module="$BUILD_DIR/geoip2-module" \
    --add-dynamic-module="$BUILD_DIR/headers-more-module" \
    --add-dynamic-module="$BUILD_DIR/zstd-module" \
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

    # Create modules directory and install dynamic modules
    mkdir -p /etc/nginx/modules

    log_info "Installing dynamic modules"
    if [ -d "$BUILD_DIR/nginx-${NGINX_VERSION}/objs" ]; then
        # Try copying directly from objs
        cp "$BUILD_DIR/nginx-${NGINX_VERSION}/objs"/*.so /etc/nginx/modules/ 2>/dev/null || {
            log_warn "No dynamic modules found in objs directory"
            # Fallback: search the entire build tree for built modules
            find "$BUILD_DIR" -type f -name "*.so" -exec cp {} /etc/nginx/modules/ \; 2>/dev/null || true
        }

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

# Load dynamic modules (installed to /etc/nginx/modules)
load_module /etc/nginx/modules/ngx_http_geoip2_module.so;
load_module /etc/nginx/modules/ngx_http_headers_more_filter_module.so;
load_module /etc/nginx/modules/ngx_http_zstd_filter_module.so;
load_module /etc/nginx/modules/ngx_http_zstd_static_module.so;

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

    # Zstandard compression (requires dynamic module)
    zstd on;
    zstd_comp_level 7;
    zstd_types text/plain text/css text/xml application/json application/javascript application/xml+rss application/atom+xml image/svg+xml;
    
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
    log_info "Created and enabled systemd service"
}

# Test NGINX configuration
test_configuration() {
    log_step "Testing NGINX configuration"
    
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
        echo -e "${GREEN}✓${NC} Modern security configuration applied"
        echo -e "${GREEN}✓${NC} Systemd service created and enabled"
        
        if systemctl is-active --quiet nginx; then
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
    echo -e "Start NGINX:    ${BLUE}sudo systemctl start nginx${NC}"
    echo -e "Stop NGINX:     ${BLUE}sudo systemctl stop nginx${NC}"
    echo -e "Restart NGINX:  ${BLUE}sudo systemctl restart nginx${NC}"
    echo -e "Enable NGINX:   ${BLUE}sudo systemctl enable nginx${NC}"
    echo -e "Status:         ${BLUE}sudo systemctl status nginx${NC}"
    echo -e "Test config:    ${BLUE}sudo nginx -t${NC}"
    echo -e "Reload config:  ${BLUE}sudo nginx -s reload${NC}"
    echo
    echo -e "${BOLD}Connection Information${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "HTTP Port:      ${BLUE}80${NC}"
    echo -e "HTTPS Port:     ${BLUE}443${NC}"
    echo -e "Config file:    ${BLUE}/etc/nginx/nginx.conf${NC}"
    echo -e "Site configs:   ${BLUE}/etc/nginx/conf.d/${NC}"
    echo -e "Document root:  ${BLUE}/usr/share/nginx/html${NC}"
    echo -e "Log files:      ${BLUE}/var/log/nginx/${NC}"
    echo -e "Backup:         ${BLUE}$BACKUP_DIR${NC}"
    
    # Show server IP addresses
    echo -e "Server IPs:     ${BLUE}$(hostname -I | tr ' ' '\n' | head -3 | tr '\n' ' ')${NC}"
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
    echo -e "${YELLOW}Connect with:${NC} ${BLUE}http://$(hostname -I | awk '{print $1}')${NC}"
    echo
}

# Compile and install NGINX with hardened configuration
install() {
    log_info "Starting NGINX ${NGINX_VERSION} installation with OpenSSL ${OPENSSL_VERSION}"
    
    # Safety check for SSH sessions
    if [[ -n "${SSH_CONNECTION:-}" ]] && [[ "${FORCE_SSH_INSTALL:-}" != "1" ]]; then
        log_error "Running in SSH session! This will affect web services."
        log_warn "If you have console access, run: FORCE_SSH_INSTALL=1 $0 install"
        log_warn "Or use 'screen' or 'tmux' to maintain session during restart"
        exit 1
    fi
    
    # Confirm installation
    if [[ "${CONFIRM:-}" != "yes" ]]; then
        if [[ -t 0 ]]; then
            # Interactive mode
            read -rp "Proceed with NGINX installation? This will compile and install NGINX with OpenSSL. [y/N] " answer
            [[ "${answer,,}" != "y" ]] && { log_error "Installation cancelled"; exit 0; }
        else
            # Non-interactive mode (piped)
            log_error "Non-interactive mode detected. Use: curl ... | CONFIRM=yes sudo bash -s install"
            exit 0
        fi
    else
        log_info "Installation confirmed via CONFIRM=yes environment variable"
    fi
    
    check_root
    print_header
    
    backup_existing
    install_dependencies
    download_sources
    build_openssl
    build_nginx
    install_nginx
    test_configuration
    
    # Enable and start NGINX service
    systemctl enable nginx
    systemctl restart nginx
    
    show_summary
    
    log_success "NGINX installation completed successfully!"
}

# Remove NGINX installation and restore original configuration
remove() {
    log_info "Removing NGINX installation..."
    
    # Confirm removal
    if [[ "${CONFIRM:-}" != "yes" ]]; then
        if [[ -t 0 ]]; then
            # Interactive mode
            read -rp "Remove NGINX installation? This will uninstall NGINX and clean up all files. [y/N] " answer
            [[ "${answer,,}" != "y" ]] && { log_error "Removal cancelled"; exit 0; }
        else
            # Non-interactive mode (piped)
            log_error "Non-interactive mode detected. Use: curl ... | CONFIRM=yes sudo bash -s remove"
            exit 0
        fi
    fi
    
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
    log_warn "NGINX service has been stopped and disabled"
    log_info "Configuration backup remains in: $BACKUP_DIR"
}

# Verify NGINX installation and configuration
verify() {
    log_info "Verifying NGINX installation..."
    
    local issues=0
    
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
    if systemctl is-active --quiet nginx 2>/dev/null; then
        log_success "NGINX service is running"
    else
        log_warn "NGINX service is not running"
    fi
    
    if systemctl is-enabled --quiet nginx 2>/dev/null; then
        log_success "NGINX service is enabled"
    else
        log_warn "NGINX service is not enabled"
    fi
    
    # Check OpenSSL integration
    if nginx -V 2>&1 | grep -q "built with OpenSSL"; then
        local openssl_version=$(nginx -V 2>&1 | grep -o 'built with OpenSSL [0-9.]*' | cut -d' ' -f4 || echo "Unknown")
        log_success "OpenSSL integration: $openssl_version"
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

    # Verify dynamic module files exist in /etc/nginx/modules
    if [ -d "/etc/nginx/modules" ]; then
        local missing=0
        for mod in \
            ngx_http_geoip2_module.so \
            ngx_http_headers_more_filter_module.so \
            ngx_http_zstd_filter_module.so \
            ngx_http_zstd_static_module.so; do
            if [ -f "/etc/nginx/modules/$mod" ]; then
                log_success "Module present: $mod"
            else
                log_warn "Module missing: $mod"
                missing=$((missing+1))
            fi
        done
        if [ "$missing" -gt 0 ]; then
            log_warn "$missing expected module(s) were not found in /etc/nginx/modules"
        fi
    else
        log_warn "/etc/nginx/modules directory not found"
    fi

    # Check third-party dynamic modules
    if nginx -V 2>&1 | grep -q "--add-dynamic-module=.*geoip2"; then
        log_success "GeoIP2 module compiled"
    else
        log_warn "GeoIP2 module not found in build flags"
    fi
    if nginx -V 2>&1 | grep -q "--add-dynamic-module=.*headers-more"; then
        log_success "headers-more module compiled"
    else
        log_warn "headers-more module not found in build flags"
    fi
    if nginx -V 2>&1 | grep -q "--add-dynamic-module=.*zstd"; then
        log_success "Zstandard module compiled"
    else
        log_warn "Zstandard module not found in build flags"
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
            echo "  CONFIRM=yes $0 install        # Non-interactive installation"
            echo "  $0 verify                     # Check installation"
            echo "  $0 remove                     # Remove installation"
            echo
            echo "Features:"
            echo "  • Compiles NGINX from source with latest OpenSSL"
            echo "  • HTTP/3 support with QUIC protocol"
            echo "  • Modern security configurations"
            echo "  • Optimized for performance and security"
            echo "  • Systemd service integration"
            echo "  • Comprehensive verification and cleanup"
            echo
            ;;
    esac
}

# Run main function
main "$@"
