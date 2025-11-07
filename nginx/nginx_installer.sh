#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/config"
BUILD_DIR="/root/nginx-build-$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/root/nginx-backup-$(date +%Y%m%d-%H%M%S)"
GITHUB_RAW="https://raw.githubusercontent.com/Stensel8/Scripts/refs/heads/main/nginx/config"
LOG_FILE="/var/log/nginx-installer-$(date +%Y%m%d-%H%M%S).log"

# Redirect all output to log file and terminal (for debugging)
exec > >(tee -a "$LOG_FILE")
exec 2>&1

# Ensure directories exist
mkdir -p "${CONFIG_DIR}" "$BUILD_DIR"

# Download .env from GitHub if not found locally
if [[ ! -f "${CONFIG_DIR}/.env" ]]; then
  echo "Config file not found locally, downloading from GitHub..." >&2
  curl -fsSL "${GITHUB_RAW}/.env" -o "${CONFIG_DIR}/.env" || {
    echo "ERROR: Could not download .env from GitHub" >&2
    exit 1
  }
fi

# Download index.html from GitHub if not found locally
if [[ ! -f "${CONFIG_DIR}/index.html" ]]; then
  echo "HTML template not found locally, downloading from GitHub..." >&2
  curl -fsSL "${GITHUB_RAW}/index.html" -o "${CONFIG_DIR}/index.html" || {
    echo "WARN: Could not download index.html from GitHub, will use fallback" >&2
  }
fi

# Load versions and checksums from .env
source <(tr -d '\r' < "${CONFIG_DIR}/.env")
# Use PREFIX from .env, fallback to default
PREFIX="${PREFIX:-/usr/local/nginx}"
SERVICE_NAME="${SERVICE_NAME:-nginx}"

# Build download URLs from versions
NGINX_URL="https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
PCRE2_URL="https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/pcre2-${PCRE2_VERSION}.tar.gz"
ZLIB_URL="https://zlib.net/zlib-${ZLIB_VERSION}.tar.gz"
HEADERS_MORE_URL="https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v${HEADERS_MORE_VERSION}.tar.gz"
ZSTD_MODULE_URL="https://github.com/tokers/zstd-nginx-module/archive/refs/tags/${ZSTD_MODULE_VERSION}.tar.gz"

# ============================================================================
# Helpers
# ============================================================================
Write-Log() {
  local level=$1 msg=$2
  echo "[$level] $msg" >&2
}

Stop-Script() { Write-Log ERROR "$1"; exit 1; }

Test-Hash() {
  local file=$1 expected=$2
  local actual=$(sha256sum "$file" | awk '{print $1}')
  [[ "$actual" == "$expected" ]] || Stop-Script "Checksum failed: $file"
}

Get-File() {
  local url=$1 file=$2 sha=$3
  [[ -f "$file" ]] && Test-Hash "$file" "$sha" && return 0
  Write-Log INFO "Downloading $(basename $file)..."
  curl -fsSL "$url" -o "$file" || Stop-Script "Download failed: $url"
  Test-Hash "$file" "$sha"
}

# ============================================================================
# Dependencies
# ============================================================================
Install-Dependencies() {
  [[ $EUID -eq 0 ]] || Stop-Script "Run as root"
  command -v curl >/dev/null || Stop-Script "curl required"
  
  Write-Log INFO "Installing build dependencies"
  if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y build-essential libpcre2-dev zlib1g-dev libzstd-dev curl gcc make >/dev/null 2>&1
  elif command -v dnf >/dev/null; then
    dnf install -y -q gcc gcc-c++ make pcre2-devel zlib-devel libzstd-devel curl perl >/dev/null 2>&1
  elif command -v yum >/dev/null; then
    yum install -y -q gcc gcc-c++ make pcre2-devel zlib-devel libzstd-devel curl perl >/dev/null 2>&1
  else
    Stop-Script "Unsupported package manager"
  fi
  Write-Log INFO "Dependencies installed"
}

# ============================================================================
# Download
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
  
  Write-Log INFO "Extracting archives"
  tar xzf nginx.tgz && mv nginx-${NGINX_VERSION} nginx
  tar xzf openssl.tgz && mv openssl-${OPENSSL_VERSION} openssl
  tar xzf pcre2.tgz && mv pcre2-${PCRE2_VERSION} pcre2
  tar xzf zlib.tgz && mv zlib-${ZLIB_VERSION} zlib
  tar xzf headers.tgz && mv headers-more-nginx-module-${HEADERS_MORE_VERSION} headers-more
  tar xzf zstd.tgz && mv zstd-nginx-module-${ZSTD_MODULE_VERSION} zstd-module
  
  Write-Log INFO "Sources ready"
}

# ============================================================================
# Build
# ============================================================================
Build-Nginx() {
  local use_system_ssl=false ssl_opt=""
  
  # Check WSL ARM64
  if [[ $(uname -r) =~ microsoft ]] && [[ $(uname -m) == aarch64 ]]; then
    Write-Log WARN "WSL ARM64 detected - using system OpenSSL"
    use_system_ssl=true
  fi
  
  # Clean up /tmp
  rm -rf /tmp/cc* /tmp/tmp.* /tmp/nginx-build-* /tmp/nginx-logs-* 2>/dev/null || true
  
  # Check disk space in /tmp
  local tmp_space=$(df /tmp | tail -1 | awk '{print $4}')
  if [[ $tmp_space -lt 1048576 ]]; then
    Write-Log WARN "Low disk space in /tmp, using build directory for temp files"
    export TMPDIR="$BUILD_DIR"
  fi
  
  # Ensure cc symlink exists
  if ! command -v cc >/dev/null 2>&1; then
    ln -sf /usr/bin/gcc /usr/local/bin/cc 2>/dev/null || true
    export PATH="/usr/local/bin:$PATH"
  fi
  
  # Build OpenSSL
  if [[ $use_system_ssl == false ]]; then
    Write-Log INFO "Building OpenSSL ${OPENSSL_VERSION}"
    cd "$BUILD_DIR/openssl"
    
    local arch=$(uname -m)
    case $arch in
      x86_64) arch=linux-x86_64 ;;
      aarch64) arch=linux-aarch64 ;;
      armv7l) arch=linux-armv4 ;;
      *) arch=linux-generic64 ;;
    esac
    
    export TMPDIR="$BUILD_DIR" CC=gcc
    
    if ! output=$(./Configure "$arch" --prefix="$(pwd)/../openssl-install" \
      --openssldir="$(pwd)/../openssl-install/ssl" \
      enable-tls1_3 no-shared -fPIC 2>&1 | grep -v '^DEBUG:' | grep -v '^No value given'); then
      use_system_ssl=true
      Write-Log WARN "OpenSSL configure failed: $(echo "$output" | tail -10)"
    fi
    
    if [[ $use_system_ssl == false ]]; then
      if ! output=$(make -j$(nproc) 2>&1 | grep -v '^DEBUG:'); then
        use_system_ssl=true
        Write-Log WARN "OpenSSL build failed: $(echo "$output" | tail -10)"
      else
        make install_sw 2>&1 | grep -v '^DEBUG:'
      fi
    fi
    
    [[ $use_system_ssl == false ]] && ssl_opt="--with-openssl=$BUILD_DIR/openssl" && Write-Log INFO "OpenSSL built"
  fi
  
  # Install system OpenSSL if needed
  if [[ $use_system_ssl == true ]]; then
    if command -v apt-get >/dev/null; then
      apt-get install -y libssl-dev >/dev/null
    elif command -v dnf >/dev/null; then
      dnf install -y openssl-devel >/dev/null
    elif command -v yum >/dev/null; then
      yum install -y openssl-devel >/dev/null
    fi
    Write-Log INFO "Using system OpenSSL"
  fi
  
  # Build Nginx
  Write-Log INFO "Building Nginx ${NGINX_VERSION}"
  cd "$BUILD_DIR/nginx"
  
  export TMPDIR="$BUILD_DIR" CC=gcc
  
  if ! output=$(./configure \
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
    --add-dynamic-module="$BUILD_DIR/zstd-module" 2>&1); then
    Write-Log ERROR "Configure output: $(echo "$output" | tail -20)"
    Stop-Script "Configure failed"
  fi
  
  if ! output=$(make -j$(nproc) 2>&1); then
    Write-Log ERROR "Make output: $(echo "$output" | tail -20)"
    Stop-Script "Build failed"
  fi
  Write-Log INFO "Build complete"
}

# ============================================================================
# Install
# ============================================================================
Install-HtmlFiles() {
  Write-Log INFO "Installing HTML files"
  mkdir -p /usr/share/nginx/html
  
  if [[ -f "${CONFIG_DIR}/index.html" ]]; then
    cd "$SCRIPT_DIR"
    source "${CONFIG_DIR}/index.html" 2>/dev/null && create_html_files 2>/dev/null || true
  fi
  
  # Verify or create basic HTML
  if [[ ! -f /usr/share/nginx/html/index.html ]] || [[ $(stat -c%s /usr/share/nginx/html/index.html) -lt 100 ]]; then
    cat > /usr/share/nginx/html/index.html <<'EOF'
<!doctype html>
<html><head><title>Welcome to NGINX</title></head>
<body><h1>NGINX is running</h1><p>Server successfully installed.</p></body>
</html>
EOF
  fi
  chmod 0644 /usr/share/nginx/html/*.html 2>/dev/null || true
}

New-SelfSignedCertificate() {
  Write-Log INFO "Generating self-signed TLS certificate"
  mkdir -p /etc/nginx/ssl
  
  # Find openssl binary
  local ssl_bin=$(command -v openssl || true)
  if [[ -z "$ssl_bin" ]] && [[ -x "${BUILD_DIR}/openssl-install/bin/openssl" ]]; then
    ssl_bin="${BUILD_DIR}/openssl-install/bin/openssl"
  elif [[ -z "$ssl_bin" ]] && [[ -x "${BUILD_DIR}/openssl/apps/openssl" ]]; then
    ssl_bin="${BUILD_DIR}/openssl/apps/openssl"
  fi

  if [[ -z "$ssl_bin" ]]; then
    if command -v apt-get >/dev/null; then
      apt-get update -qq >/dev/null 2>&1 && apt-get install -y openssl >/dev/null 2>&1
    elif command -v dnf >/dev/null; then
      dnf install -y openssl >/dev/null 2>&1
    elif command -v yum >/dev/null; then
      yum install -y openssl >/dev/null 2>&1
    fi
    ssl_bin=$(command -v openssl || true)
  fi

  [[ -n "$ssl_bin" ]] || Stop-Script "openssl not found"

  local output
  if ! output=$(OPENSSL_CONF=/dev/null "$ssl_bin" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 365 -nodes \
    -keyout /etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt \
    -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    2>&1); then
      Write-Log ERROR "OpenSSL output: $output"
      Stop-Script "Certificate generation failed"
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

user nobody;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /run/nginx.pid;

events {
    worker_connections 1024;
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
    types_hash_max_size 2048;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss 
               application/rss+xml font/truetype font/opentype 
               application/vnd.ms-fontobject image/svg+xml;

    # Zstd compression (better than gzip)
    zstd on;
    zstd_comp_level 6;
    zstd_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss 
               application/rss+xml font/truetype font/opentype 
               application/vnd.ms-fontobject image/svg+xml;

    # SSL/TLS settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;
    
    # HTTP/3 QUIC settings
    quic_retry on;
    ssl_early_data on;

    server {
        listen 80;
        listen [::]:80;
        server_name _;
        return 301 https://\$host\$request_uri;
    }

    server {
        # HTTP/1.1 and HTTP/2 over TCP
        listen 443 ssl;
        listen [::]:443 ssl;
        
        # HTTP/3 over QUIC (UDP)
        listen 443 quic reuseport;
        listen [::]:443 quic reuseport;
        
        http2 on;
        http3 on;
        
        server_name localhost;
        ssl_certificate /etc/nginx/ssl/nginx.crt;
        ssl_certificate_key /etc/nginx/ssl/nginx.key;
        
        # Advertise HTTP/3 support
        add_header Alt-Svc 'h3=":443"; ma=86400' always;
        add_header X-Protocol \$server_protocol always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

        location / {
            root /usr/share/nginx/html;
            index index.html index.htm;
        }

        error_page 500 502 503 504 /50x.html;
        location = /50x.html {
            root /usr/share/nginx/html;
        }
    }
}
EOF
}

install() {
  Write-Log INFO "Installing Nginx"
  
  # Backup existing config
  if [[ -d /etc/nginx ]]; then
    mkdir -p "$BACKUP_DIR"
    cp -a /etc/nginx "$BACKUP_DIR/"
  fi
  
  # Install
  cd "$BUILD_DIR/nginx"
  if ! output=$(make install 2>&1); then
    Write-Log ERROR "Install output: $(echo "$output" | tail -10)"
    Stop-Script "Nginx install failed"
  fi
  
  # Setup directories
  mkdir -p /etc/nginx/{conf.d,modules,sites-available,sites-enabled}
  mkdir -p /var/log/nginx /var/cache/nginx /usr/share/nginx/html
  cp objs/*.so /etc/nginx/modules/ 2>/dev/null || true
  
  # Install HTML, certs, and config
  Install-HtmlFiles
  New-SelfSignedCertificate
  New-NginxConfig
  
  # Create user
  id nginx >/dev/null 2>&1 || useradd -r -s /sbin/nologin nginx
  chown -R nginx:nginx /var/log/nginx /var/cache/nginx
  chmod 755 /etc/nginx/{conf.d,modules}
  
  # Systemd service
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
  nginx -V 2>&1 | head -n1
  
  # Run post-install checks
  Test-NginxInstallation || Write-Log WARN "Post-install checks detected issues"
}

Test-NginxInstallation() {
  Write-Log INFO "Running post-install checks"
  
  # Check cert
  if [[ ! -f /etc/nginx/ssl/nginx.crt ]] || [[ ! -f /etc/nginx/ssl/nginx.key ]]; then
    Write-Log ERROR "SSL certificates missing"
    return 1
  fi
  
  # Check nginx -t
  if ! nginx -t >/dev/null 2>&1; then
    Write-Log ERROR "nginx -t failed"
    return 1
  fi
  
  # Check service
  if systemctl is-active --quiet nginx; then
    :
  else
    Write-Log WARN "Nginx service not active"
  fi
  
  # Check https://localhost
  if command -v curl >/dev/null 2>&1; then
    if curl -sk https://localhost -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q '^200$'; then
      Write-Log INFO "All checks passed"
    else
      Write-Log WARN "Unable to verify https://localhost response"
    fi
  fi
  
  return 0
}

# ============================================================================
# Remove
# ============================================================================
Remove-Nginx() {
  Write-Log INFO "Removing Nginx"
  systemctl stop nginx 2>/dev/null || true
  rm -rf /usr/sbin/nginx /etc/nginx /var/log/nginx /var/cache/nginx
  userdel nginx 2>/dev/null || true
  Write-Log INFO "Nginx removed"
}

# ============================================================================
# Pre-flight checks
# ============================================================================
Test-RunningWebServers() {
  local port443=$(lsof -ti :443 2>/dev/null | head -n1)
  if [[ -n "$port443" ]]; then
    local proc=$(ps -p "$port443" -o comm= 2>/dev/null)
    Write-Log WARN "Port 443 in use by: $proc"
    echo -n "Stop conflicting services? [y/N]: "
    read -r response
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
# Main
# ============================================================================
trap 'rm -rf "$BUILD_DIR"' EXIT

case "${1:-install}" in
  install) 
    Test-RunningWebServers && Install-Dependencies && Get-Sources && Build-Nginx && install
    echo ""
    echo "Installation log: $LOG_FILE"
    ;;
  remove) 
    Remove-Nginx
    echo ""
    echo "Removal log: $LOG_FILE"
    ;;
  *) echo "Usage: $0 {install|remove}"; exit 1 ;;
esac
