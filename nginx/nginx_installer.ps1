<#
.SYNOPSIS
    NGINX Installer Script for Linux (PowerShell)

.DESCRIPTION
    Builds and installs NGINX with OpenSSL 3.6, HTTP/3, zstd compression,
    and ACME support on Linux.

.PARAMETER Command
    install - Build and install NGINX
    remove  - Uninstall NGINX

.EXAMPLE
    ./nginx_installer.ps1 -Command install
#>

#!/usr/bin/env pwsh
#Requires -Version 7.0

param(
    [ValidateSet('install','remove')]
    [string]$Command = 'install'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Linux only check
if (-not $IsLinux) {
    Write-Host "ERROR: This script is for Linux only." -ForegroundColor Red
    exit 1
}

# ============================================================================
# Version Configuration
# ============================================================================

# NGINX
$Script:NGINX_VERSION  = '1.29.3'
$Script:NGINX_SHA256   = '9befcced12ee09c2f4e1385d7e8e21c91f1a5a63b196f78f897c2d044b8c9312'

# OpenSSL
$Script:OPENSSL_VERSION = '3.6.0'
$Script:OPENSSL_SHA256  = 'b6a5f44b7eb69e3fa35dbf15524405b44837a481d43d81daddde3ff21fcbb8e9'

# PCRE2
$Script:PCRE2_VERSION = '10.47'
$Script:PCRE2_SHA256  = 'c08ae2388ef333e8403e670ad70c0a11f1eed021fd88308d7e02f596fcd9dc16'

# Zlib
$Script:ZLIB_VERSION = '1.3.1'
$Script:ZLIB_SHA256  = '9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23'

# Headers-More Module
$Script:HEADERS_MORE_VERSION = '0.39'
$Script:HEADERS_MORE_SHA256  = 'dde68d3fa2a9fc7f52e436d2edc53c6d703dcd911283965d889102d3a877c778'

# Zstd Module
$Script:ZSTD_MODULE_VERSION = '0.1.1'
$Script:ZSTD_MODULE_SHA256  = '707d534f8ca4263ff043066db15eac284632aea875f9fe98c96cea9529e15f41'

# ACME Module
$Script:ACME_MODULE_VERSION = '0.3.0'
$Script:ACME_MODULE_SHA256  = '1fa2b29d6e84e8aeffa15e91841f5a521a7537a8ce30321e56f4c1cb06d15440'

# ============================================================================
# Static Configuration
# ============================================================================

$Script:BUILD_DIR  = "/root/nginx-build-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$Script:BACKUP_DIR = "/root/nginx-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$Script:LOG_FILE   = "/var/log/nginx-installer-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Ensure directories exist
$null = New-Item -ItemType Directory -Path $Script:BUILD_DIR -Force -ErrorAction SilentlyContinue
$null = New-Item -ItemType Directory -Path (Split-Path $Script:LOG_FILE -Parent) -Force -ErrorAction SilentlyContinue

# Download URLs
$Script:NGINX_URL        = "https://nginx.org/download/nginx-$($Script:NGINX_VERSION).tar.gz"
$Script:OPENSSL_URL      = "https://github.com/openssl/openssl/releases/download/openssl-$($Script:OPENSSL_VERSION)/openssl-$($Script:OPENSSL_VERSION).tar.gz"
$Script:PCRE2_URL        = "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-$($Script:PCRE2_VERSION)/pcre2-$($Script:PCRE2_VERSION).tar.gz"
$Script:ZLIB_URL         = "https://zlib.net/zlib-$($Script:ZLIB_VERSION).tar.gz"
$Script:HEADERS_MORE_URL = "https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v$($Script:HEADERS_MORE_VERSION).tar.gz"
$Script:ZSTD_MODULE_URL  = "https://github.com/tokers/zstd-nginx-module/archive/refs/tags/$($Script:ZSTD_MODULE_VERSION).tar.gz"
$Script:ACME_MODULE_URL  = "https://github.com/nginx/nginx-acme/releases/download/v$($Script:ACME_MODULE_VERSION)/nginx-acme-$($Script:ACME_MODULE_VERSION).tar.gz"

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )
    $logMessage = "[$Level] $Message"
    Write-Host $logMessage
    Add-Content -Path $Script:LOG_FILE -Value $logMessage -ErrorAction SilentlyContinue
}

function Stop-Script {
    param([string]$Message)
    Write-Log 'ERROR' $Message
    exit 1
}

function Test-Hash {
    param(
        [string]$File,
        [string]$Expected
    )
    $actual = (Get-FileHash -Path $File -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $Expected.ToLower()) {
        Stop-Script "Checksum failed: $File"
    }
}

function Get-File {
    param(
        [string]$Url,
        [string]$OutFile,
        [string]$Hash
    )

    $fullPath = Join-Path $Script:BUILD_DIR $OutFile

    if (Test-Path $fullPath) {
        Test-Hash -File $fullPath -Expected $Hash
        return
    }

    Write-Log 'INFO' "Downloading $(Split-Path -Leaf $OutFile)..."

    try {
        Push-Location $Script:BUILD_DIR
        & curl -fsSL $Url -o $OutFile
        if ($LASTEXITCODE -ne 0) { throw "Download failed" }
        Pop-Location
    } catch {
        Pop-Location -ErrorAction SilentlyContinue
        Stop-Script "Download failed: $Url"
    }

    Test-Hash -File $fullPath -Expected $Hash
}

function Detect-PkgMgr {
    if (Get-Command apt-get -ErrorAction SilentlyContinue) {
        return "apt"
    } elseif (Get-Command dnf -ErrorAction SilentlyContinue) {
        return "dnf"
    } elseif (Get-Command yum -ErrorAction SilentlyContinue) {
        return "yum"
    } else {
        return "unknown"
    }
}

# ============================================================================
# System Dependencies
# ============================================================================

function Install-Dependencies {
    try {
        $uid = & id -u 2>$null
        if ($uid -ne 0) { Stop-Script "Run as root" }
    } catch {
        Stop-Script "Cannot determine user ID; run as root"
    }

    if (-not (Get-Command curl -ErrorAction SilentlyContinue)) {
        Stop-Script "curl required"
    }

    Write-Log 'INFO' 'Installing build dependencies'

    $mgr = Detect-PkgMgr

    switch ($mgr) {
        'apt' {
            $env:DEBIAN_FRONTEND = 'noninteractive'
            & apt-get update -qq 2>&1 | Out-Null
            & apt-get install -y build-essential libpcre2-dev zlib1g-dev libzstd-dev curl gcc make cargo pkg-config clang gawk cmake 2>&1 | Out-Null
        }
        'dnf' {
            & dnf install -y -q gcc gcc-c++ make pcre2-devel zlib-devel libzstd-devel curl perl cargo pkgconf-pkg-config clang gawk cmake 2>&1 | Out-Null
        }
        'yum' {
            & yum install -y -q gcc gcc-c++ make pcre2-devel zlib-devel libzstd-devel curl perl cargo pkgconfig clang gawk cmake 2>&1 | Out-Null
        }
        default {
            Stop-Script "Unsupported package manager"
        }
    }

    # Verify cargo availability
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Log 'WARN' 'Cargo not found. Installing rustup...'
        bash -lc "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y" | Out-Null
    }
    Write-Log 'INFO' 'Dependencies installed'
}

function Update-SystemPackages {
    try {
        $uid = & id -u 2>$null
        if ($uid -ne 0) { Stop-Script "Run as root" }
    } catch {
        Stop-Script "Cannot determine user ID; run as root"
    }

    Write-Log 'INFO' 'Updating system packages'

    $mgr = Detect-PkgMgr

    switch ($mgr) {
        'apt' {
            $env:DEBIAN_FRONTEND = 'noninteractive'
            & apt-get update -qq 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { Write-Log 'WARN' 'apt-get update failed' }
            & apt-get upgrade -y -q 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { Stop-Script 'apt-get upgrade failed' }
        }
        'dnf' {
            & dnf upgrade -y -q 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { Stop-Script 'dnf upgrade failed' }
        }
        'yum' {
            & yum update -y -q 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { Stop-Script 'yum update failed' }
        }
        default {
            Write-Log 'WARN' 'Unable to detect package manager'
        }
    }

    Write-Log 'INFO' 'System packages updated'
}

# ============================================================================
# Download Sources
# ============================================================================

function Get-Sources {
    Push-Location $Script:BUILD_DIR
    Write-Log 'INFO' 'Downloading sources'

    Get-File $Script:NGINX_URL        "nginx.tgz"   $Script:NGINX_SHA256
    Get-File $Script:OPENSSL_URL      "openssl.tgz" $Script:OPENSSL_SHA256
    Get-File $Script:PCRE2_URL        "pcre2.tgz"   $Script:PCRE2_SHA256
    Get-File $Script:ZLIB_URL         "zlib.tgz"    $Script:ZLIB_SHA256
    Get-File $Script:HEADERS_MORE_URL "headers.tgz" $Script:HEADERS_MORE_SHA256
    Get-File $Script:ZSTD_MODULE_URL  "zstd.tgz"    $Script:ZSTD_MODULE_SHA256
    Get-File $Script:ACME_MODULE_URL  "acme.tgz"    $Script:ACME_MODULE_SHA256

    Write-Log 'INFO' 'Extracting archives'
    
    # Cleanup previous extractions
    Remove-Item nginx, openssl, pcre2, zlib, headers-more, zstd-module, nginx-acme -Recurse -Force -ErrorAction SilentlyContinue

    & tar xzf nginx.tgz
    Move-Item "nginx-$Script:NGINX_VERSION" nginx -Force

    & tar xzf openssl.tgz
    Move-Item "openssl-$Script:OPENSSL_VERSION" openssl -Force

    & tar xzf pcre2.tgz
    Move-Item "pcre2-$Script:PCRE2_VERSION" pcre2 -Force

    & tar xzf zlib.tgz
    Move-Item "zlib-$Script:ZLIB_VERSION" zlib -Force

    & tar xzf headers.tgz
    Move-Item "headers-more-nginx-module-$Script:HEADERS_MORE_VERSION" headers-more -Force

    & tar xzf zstd.tgz
    Move-Item "zstd-nginx-module-$Script:ZSTD_MODULE_VERSION" zstd-module -Force

    & tar xzf acme.tgz
    Move-Item "nginx-acme-$Script:ACME_MODULE_VERSION" nginx-acme -Force

    Pop-Location
    Write-Log 'INFO' 'Sources ready'
}

# ============================================================================
# Build Functions
# ============================================================================

function Build-Nginx {
    $useSystemSsl = $false
    $sslOpt       = ""

    # WSL ARM64 check
    $kernelInfo = & uname -r
    $arch       = & uname -m
    if ($kernelInfo -match 'microsoft' -and $arch -eq 'aarch64') {
        Write-Log 'WARN' 'WSL ARM64 detected - using system OpenSSL'
        $useSystemSsl = $true
    }

    # Clean temporary files
    Get-ChildItem /tmp -Filter 'cc*'            -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem /tmp -Filter 'tmp.*'          -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem /tmp -Filter 'nginx-build-*'  -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    # Check disk space in /tmp
    $tmpSpace = (& df /tmp | Select-Object -Skip 1 | ForEach-Object {
        $_.Split([char[]]@(' ', "`t"), [System.StringSplitOptions]::RemoveEmptyEntries)[3]
    })
    if ([int]$tmpSpace -lt 1048576) {
        Write-Log 'WARN' "Low disk space in /tmp, using build directory"
        $env:TMPDIR = $Script:BUILD_DIR
    }

    # Ensure cc symlink exists
    $ccPath = Get-Command cc -ErrorAction SilentlyContinue
    if (-not $ccPath) {
        $gccPath = Get-Command gcc -ErrorAction SilentlyContinue
        if ($gccPath -and (Test-Path '/usr/local/bin')) {
            New-Item -ItemType SymbolicLink -Path '/usr/local/bin/cc' -Target $gccPath.Source -Force -ErrorAction SilentlyContinue | Out-Null
            $env:PATH = "/usr/local/bin:$($env:PATH)"
        }
    }

    # Build OpenSSL standalone for ACME module
    if (-not $useSystemSsl) {
        Write-Log 'INFO' "Building OpenSSL $Script:OPENSSL_VERSION (Standalone)"
        Push-Location (Join-Path $Script:BUILD_DIR 'openssl')

        $archConfig = switch ($arch) {
            'x86_64'  { 'linux-x86_64' }
            'aarch64' { 'linux-aarch64' }
            'armv7l'  { 'linux-armv4' }
            Default   { 'linux-generic64' }
        }

        $configOutput = bash -c "export TMPDIR='$Script:BUILD_DIR' && ./Configure $archConfig --prefix=`$(pwd)/../openssl-install --openssldir=`$(pwd)/../openssl-install/ssl enable-tls1_3 shared -fPIC 2>&1 | grep -v '^DEBUG:' | grep -v '^No value given'"
        if ($LASTEXITCODE -ne 0) {
            Write-Log 'WARN' "OpenSSL configure failed"
            Write-Log 'WARN' 'Using system OpenSSL'
            $useSystemSsl = $true
        } else {
            $makeOutput = bash -c "export TMPDIR='$Script:BUILD_DIR' && make -j`$(nproc) 2>&1 | grep -v '^DEBUG:'"
            if ($LASTEXITCODE -ne 0) {
                Write-Log 'WARN' "OpenSSL build failed"
                Write-Log 'WARN' 'Using system OpenSSL'
                $useSystemSsl = $true
            } else {
                bash -c "make install_sw 2>&1 | grep -v '^DEBUG:'" | Out-Host
                $sslOpt = "--with-openssl=$(Join-Path $Script:BUILD_DIR 'openssl')"
                Write-Log 'INFO' 'OpenSSL built successfully'
            }
        }
        Pop-Location
    }

    # Fallback to system OpenSSL
    if ($useSystemSsl) {
        $mgr = Detect-PkgMgr
        switch ($mgr) {
            'apt' { & apt-get install -y libssl-dev | Out-Null }
            'dnf' { & dnf install -y openssl-devel | Out-Null }
            'yum' { & yum install -y openssl-devel | Out-Null }
        }
        Write-Log 'INFO' 'Using system OpenSSL'
    }

    # Build NGINX
    Write-Log 'INFO' "Building Nginx $Script:NGINX_VERSION"
    Push-Location (Join-Path $Script:BUILD_DIR 'nginx')

    # Verify libzstd availability
    $ldconfigOut = bash -lc 'ldconfig -p 2>/dev/null || true'
    if (-not ($ldconfigOut -match 'libzstd.so')) {
        $paths = @('/usr/lib/libzstd.so','/usr/lib64/libzstd.so','/usr/local/lib/libzstd.so')
        $found = $false
        foreach ($p in $paths) { if (Test-Path $p) { $found = $true; break } }
        if (-not $found) {
            Stop-Script 'Shared libzstd not found. Install libzstd-dev/devel'
        }
    }

    $pcre2Path   = Join-Path $Script:BUILD_DIR 'pcre2'
    $zlibPath    = Join-Path $Script:BUILD_DIR 'zlib'
    $headersPath = Join-Path $Script:BUILD_DIR 'headers-more'
    $zstdPath    = Join-Path $Script:BUILD_DIR 'zstd-module'

    $configCmd = @"
export TMPDIR='$Script:BUILD_DIR'
export CC=gcc
export LDFLAGS='-lzstd'
./configure \
  --with-compat \
  --prefix=/usr/local/nginx \
  --sbin-path=/usr/sbin/nginx \
  --conf-path=/etc/nginx/nginx.conf \
  --http-log-path=/var/log/nginx/access.log \
  --error-log-path=/var/log/nginx/error.log \
  --pid-path=/run/nginx.pid \
  --lock-path=/var/lock/nginx.lock \
  $sslOpt \
  --with-pcre=$pcre2Path \
  --with-zlib=$zlibPath \
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
  --add-dynamic-module=$headersPath \
  --add-dynamic-module=$zstdPath
"@

    $configOutput = bash -c "$configCmd 2>&1"
    if ($LASTEXITCODE -ne 0) {
        Write-Log 'ERROR' "Configure output: $($configOutput | Select-Object -Last 20)"
        Stop-Script 'Nginx configure failed'
    }

    # Patch Makefile for shared libzstd
    if (Test-Path "objs/Makefile") {
        Write-Log 'INFO' 'Patching nginx Makefile for shared libzstd'
        bash -c "sed -i 's/-l:libzstd\.a/-lzstd/g' objs/Makefile" | Out-Null
    }

    $makeOutput = bash -c "export TMPDIR='$Script:BUILD_DIR' && make -j`$(nproc) 2>&1"
    if ($LASTEXITCODE -ne 0) {
        Write-Log 'ERROR' "Make output: $($makeOutput | Select-Object -Last 20)"
        Stop-Script 'Nginx build failed'
    }

    # Build ACME Module
    Write-Log 'INFO' "Building ACME module $Script:ACME_MODULE_VERSION"
    Push-Location (Join-Path $Script:BUILD_DIR 'nginx-acme')

    $env:NGINX_BUILD_DIR = Join-Path $Script:BUILD_DIR 'nginx/objs'
    $env:NGX_ACME_STATE_PREFIX = '/var/cache/nginx'

    # Source cargo env helper
    $sourceCargo = 'if [ -f "$HOME/.cargo/env" ]; then source "$HOME/.cargo/env"; fi'

    # Verify Rust toolchain
    $rustcVer = bash -lc "$sourceCargo && rustc --version 2>/dev/null"
    if (-not $rustcVer) {
        Write-Log 'WARN' 'rustc not found, installing rustup...'
        bash -lc "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y" | Out-Null
    }

    $opensslInstall = Join-Path $Script:BUILD_DIR 'openssl-install'
    $acmeEnv = ""
    if (Test-Path $opensslInstall) {
        $lib64 = Join-Path $opensslInstall 'lib64'
        $libDir = if (Test-Path $lib64) { $lib64 } else { Join-Path $opensslInstall 'lib' }
        
        Write-Log 'INFO' "Using OpenSSL install for ACME (Static Link): $opensslInstall"
        $acmeEnv = "export OPENSSL_DIR='$opensslInstall' && export OPENSSL_LIB_DIR='$libDir' && export OPENSSL_INCLUDE_DIR='$opensslInstall/include' && export OPENSSL_STATIC=1"
    }

    $cmd = "$sourceCargo && $acmeEnv && cargo build --release 2>&1"
    $acmeOutput = bash -lc $cmd
    if ($LASTEXITCODE -ne 0) {
        Write-Log 'ERROR' "ACME build failed: $($acmeOutput | Select-Object -Last 20)"
        Stop-Script 'ACME module build failed'
    }

    New-Item -ItemType Directory -Path "$($Script:BUILD_DIR)/nginx-acme/objs" -Force | Out-Null
    Copy-Item 'target/release/libnginx_acme.so' -Destination "$($Script:BUILD_DIR)/nginx-acme/objs/ngx_http_acme_module.so" -Force

    Pop-Location # nginx-acme
    Pop-Location # nginx
    Write-Log 'INFO' 'ACME module built successfully'
    Write-Log 'INFO' 'Build complete'
}

# ============================================================================
# Configuration Functions
# ============================================================================

function Install-HtmlFiles {
    Write-Log 'INFO' "Installing HTML files"
    $htmlDir = '/usr/share/nginx/html'
    New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null

    $indexContent = @'
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
'@
    $indexContent | Out-File (Join-Path $htmlDir 'index.html') -Encoding utf8 -Force

    bash -c "chmod 0644 $htmlDir/*.html 2>/dev/null || true" | Out-Null
}

function New-SelfSignedCertificate {
    Write-Log 'INFO' 'Generating self-signed TLS certificate'
    $sslDir = '/etc/nginx/ssl'
    New-Item -ItemType Directory -Path $sslDir -Force | Out-Null

    # Prefer built OpenSSL binary
    $opensslBin = Join-Path $Script:BUILD_DIR 'openssl-install/bin/openssl'
    if (-not (Test-Path $opensslBin)) {
         $opensslBin = (Get-Command openssl -ErrorAction SilentlyContinue)?.Source
    }
    
    # Fallback: install openssl
    if (-not $opensslBin) {
        $mgr = Detect-PkgMgr
        switch ($mgr) {
            'apt' { & apt-get install -y openssl | Out-Null }
            'dnf' { & dnf install -y openssl | Out-Null }
            'yum' { & yum install -y openssl | Out-Null }
        }
        $opensslBin = (Get-Command openssl -ErrorAction SilentlyContinue)?.Source
    }

    if (-not $opensslBin) { Stop-Script 'openssl not found' }

    $keyPath = "$sslDir/nginx.key"
    $crtPath = "$sslDir/nginx.crt"
    
    # Setup library path for custom OpenSSL
    $envPrefix = ""
    if ($opensslBin -match 'openssl-install') {
        $libDir = Join-Path $Script:BUILD_DIR 'openssl-install/lib64'
        if (-not (Test-Path $libDir)) { $libDir = Join-Path $Script:BUILD_DIR 'openssl-install/lib' }
        $envPrefix = "LD_LIBRARY_PATH='$libDir':`$LD_LIBRARY_PATH"
        Write-Log 'INFO' "Using built openssl: $opensslBin"
    }

    $cmd = "$envPrefix OPENSSL_CONF=/dev/null '$opensslBin' req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 365 -nodes -keyout '$keyPath' -out '$crtPath' -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' 2>&1"
    $output = bash -c $cmd
    
    if ($LASTEXITCODE -ne 0) {
        Write-Log 'ERROR' "OpenSSL output: $output"
        Stop-Script 'Certificate generation failed'
    }

    bash -c "chmod 600 '$keyPath' && chmod 644 '$crtPath'" | Out-Null
}

function New-NginxConfig {
    Write-Log 'INFO' 'Creating nginx configuration'
    $conf = @'
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
'@
    $conf | Out-File '/etc/nginx/nginx.conf' -Encoding utf8 -Force
}

# ============================================================================
# Install/Remove Functions
# ============================================================================

function Install-Nginx {
    Write-Log 'INFO' 'Installing Nginx'
    
    # Backup existing configuration
    if (Test-Path '/etc/nginx') {
        New-Item -ItemType Directory -Path $Script:BACKUP_DIR -Force | Out-Null
        Copy-Item '/etc/nginx' "$Script:BACKUP_DIR/" -Recurse -Force
    }

    Push-Location (Join-Path $Script:BUILD_DIR 'nginx')
    $out = bash -c 'make install 2>&1'
    if ($LASTEXITCODE -ne 0) {
        Write-Log 'ERROR' "Install output: $out"
        Stop-Script 'Nginx install failed'
    }
    Pop-Location

    # Create directories
    New-Item -ItemType Directory -Force -Path '/etc/nginx/conf.d','/etc/nginx/modules','/etc/nginx/sites-available','/etc/nginx/sites-enabled','/var/log/nginx','/var/cache/nginx','/usr/share/nginx/html' | Out-Null

    # Install dynamic modules
    Copy-Item "$Script:BUILD_DIR/nginx/objs/*.so" -Destination '/etc/nginx/modules/' -Force
    Copy-Item "$Script:BUILD_DIR/nginx-acme/objs/ngx_http_acme_module.so" -Destination '/etc/nginx/modules/' -Force

    # Install configuration files
    Install-HtmlFiles
    New-SelfSignedCertificate
    New-NginxConfig

    # Create nginx user
    bash -c 'id nginx 2>/dev/null || useradd -r -s /sbin/nologin nginx' | Out-Null
    bash -c 'chown -R nginx:nginx /var/log/nginx /var/cache/nginx' | Out-Null
    bash -c 'chmod 755 /etc/nginx/conf.d /etc/nginx/modules' | Out-Null

    # Create systemd service
    $svc = @'
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
'@
    $svc | Out-File '/etc/systemd/system/nginx.service' -Encoding utf8 -Force

    bash -c 'systemctl daemon-reload && systemctl enable nginx && nginx -t && systemctl start nginx' 2>&1 | Out-Null

    Write-Log 'INFO' "Nginx $Script:NGINX_VERSION with OpenSSL $Script:OPENSSL_VERSION installed"
    Write-Log 'INFO' "Access: https://localhost"
    bash -c 'nginx -V 2>&1 | head -n1'
    Test-NginxInstallation
}

function Test-NginxInstallation {
    Write-Log 'INFO' 'Running post-install checks'
    
    if (-not (Test-Path '/etc/nginx/ssl/nginx.crt')) {
        Write-Log 'ERROR' 'SSL certificates missing'
        return
    }
    
    if (-not (Test-Path '/etc/nginx/modules/ngx_http_acme_module.so')) {
        Write-Log 'WARN' 'ACME module not found'
    } else {
        Write-Log 'INFO' 'ACME module present'
    }

    $t = bash -c 'nginx -t 2>&1'
    if ($LASTEXITCODE -ne 0) {
        Write-Log 'ERROR' "nginx -t failed: $t"
    }

    bash -c 'curl -k https://localhost -I' 2>&1 | Out-Null
}

function Remove-Nginx {
    Write-Log 'INFO' 'Removing Nginx'
    
    bash -c 'systemctl stop nginx 2>/dev/null || true' | Out-Null
    Remove-Item '/usr/sbin/nginx','/etc/nginx','/var/log/nginx','/var/cache/nginx' -Recurse -Force -ErrorAction SilentlyContinue
    bash -c 'userdel nginx 2>/dev/null || true' | Out-Null
    
    Write-Log 'INFO' 'Nginx removed'
}

function Test-RunningWebServers {
    $port443 = bash -c "lsof -ti :443 2>/dev/null | head -n1"
    if ($port443) {
        $proc = bash -c "ps -p $port443 -o comm= 2>/dev/null"
        Write-Log 'WARN' "Port 443 in use by: $proc"
        $response = Read-Host 'Stop conflicting services? [y/N]'
        if ($response -match '^[Yy]') {
            bash -c 'systemctl stop apache2 httpd nginx 2>/dev/null || true' | Out-Null
            Write-Log 'INFO' 'Services stopped'
        } else {
            Stop-Script 'Port 443 in use'
        }
    }
}

# ============================================================================
# Main Entry Point
# ============================================================================

try {
    switch ($Command) {
        'install' {
            Update-SystemPackages
            Test-RunningWebServers
            Install-Dependencies
            Get-Sources
            Build-Nginx
            Install-Nginx
            Write-Host "`nInstallation log: $Script:LOG_FILE"
        }
        'remove' {
            Remove-Nginx
            Write-Host "`nRemoval log: $Script:LOG_FILE"
        }
    }
}
finally {
    Remove-Item $Script:BUILD_DIR -Recurse -Force -ErrorAction SilentlyContinue
}
