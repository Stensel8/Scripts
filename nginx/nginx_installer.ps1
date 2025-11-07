#!/usr/bin/env pwsh
#Requires -Version 7.0

param([ValidateSet('install','remove')][string]$Command = 'install')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Linux only
if (-not $IsLinux -and -not ($PSVersionTable.PSVersion.Major -ge 6 -and $PSVersionTable.Platform -eq 'Unix')) {
    Write-Host "ERROR: This script is for Linux only." -ForegroundColor Red
    exit 1
}

# ============================================================================
# Configuration
# ============================================================================
$Script:SCRIPT_DIR = $PSScriptRoot
$Script:CONFIG_DIR = Join-Path $Script:SCRIPT_DIR 'config'
$Script:BUILD_DIR = "/root/nginx-build-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$Script:BACKUP_DIR = "/root/nginx-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$Script:GITHUB_RAW = "https://raw.githubusercontent.com/Stensel8/Scripts/refs/heads/main/nginx/config"
$Script:LOG_FILE = "/var/log/nginx-installer-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Ensure directories exist
$null = New-Item -ItemType Directory -Path $Script:CONFIG_DIR -Force -ErrorAction SilentlyContinue
$null = New-Item -ItemType Directory -Path $Script:BUILD_DIR -Force -ErrorAction SilentlyContinue
$null = New-Item -ItemType Directory -Path (Split-Path $Script:LOG_FILE -Parent) -Force -ErrorAction SilentlyContinue

# Download .env from GitHub if not found locally
$envFile = Join-Path $Script:CONFIG_DIR '.env'
if (-not (Test-Path $envFile)) {
    Write-Host "Config file not found locally, downloading from GitHub..." -ForegroundColor Yellow
    try {
        $null = bash -c "/usr/bin/curl -fsSL '$Script:GITHUB_RAW/.env' -o '$envFile'"
        if ($LASTEXITCODE -ne 0) {
            throw "Download failed"
        }
    } catch {
        Write-Host "ERROR: Could not download .env from GitHub" -ForegroundColor Red
        exit 1
    }
}

# Download index.html from GitHub if not found locally
$indexHtmlFile = Join-Path $Script:CONFIG_DIR 'index.html'
if (-not (Test-Path $indexHtmlFile)) {
    Write-Host "HTML template not found locally, downloading from GitHub..." -ForegroundColor Yellow
    try {
        $null = bash -c "/usr/bin/curl -fsSL '$Script:GITHUB_RAW/index.html' -o '$indexHtmlFile'"
        if ($LASTEXITCODE -ne 0) {
            throw "Download failed"
        }
    } catch {
        Write-Host "WARN: Could not download index.html from GitHub, will use fallback" -ForegroundColor Yellow
    }
}

# Load versions and checksums from .env
Get-Content $envFile | Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') {
        $varName = $Matches[1].Trim()
        $varValue = $Matches[2].Trim().Trim('"').Trim("'")
        Set-Variable -Name $varName -Value $varValue -Scope Script
    }
}

# Use PREFIX and SERVICE_NAME from .env, with fallbacks
$Script:PREFIX = if ($PREFIX) { $PREFIX -replace '^"|"$','' } else { '/usr/local/nginx' }
$Script:SERVICE_NAME = if ($SERVICE_NAME) { $SERVICE_NAME } else { 'nginx' }

# Build download URLs from versions
$Script:NGINX_URL = "https://nginx.org/download/nginx-$Script:NGINX_VERSION.tar.gz"
$Script:OPENSSL_URL = "https://github.com/openssl/openssl/releases/download/openssl-$Script:OPENSSL_VERSION/openssl-$Script:OPENSSL_VERSION.tar.gz"
$Script:PCRE2_URL = "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-$Script:PCRE2_VERSION/pcre2-$Script:PCRE2_VERSION.tar.gz"
$Script:ZLIB_URL = "https://zlib.net/zlib-$Script:ZLIB_VERSION.tar.gz"
$Script:HEADERS_MORE_URL = "https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v$Script:HEADERS_MORE_VERSION.tar.gz"
$Script:ZSTD_MODULE_URL = "https://github.com/tokers/zstd-nginx-module/archive/refs/tags/$Script:ZSTD_MODULE_VERSION.tar.gz"

# ============================================================================
# Helpers
# ============================================================================
function Write-Log {
    param([string]$Level, [string]$Message)
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
    param([string]$File, [string]$Expected)
    $actual = (Get-FileHash -Path $File -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $Expected.ToLower()) {
        Stop-Script "Checksum failed: $File"
    }
}

function Get-File {
    param([string]$Url, [string]$OutFile, [string]$Hash)
    
    $fullPath = Join-Path $Script:BUILD_DIR $OutFile
    
    if (Test-Path $fullPath) {
        Test-Hash -File $fullPath -Expected $Hash
        return
    }
    Write-Log 'INFO' "Downloading $(Split-Path -Leaf $OutFile)"
    
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

# ============================================================================
# Dependencies
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
    
    if (Get-Command apt-get -ErrorAction SilentlyContinue) {
        $env:DEBIAN_FRONTEND = 'noninteractive'
        & apt-get update -qq 2>&1 | Out-Null
        & apt-get install -y build-essential libpcre2-dev zlib1g-dev libzstd-dev curl gcc make 2>&1 | Out-Null
    } elseif (Get-Command dnf -ErrorAction SilentlyContinue) {
        & dnf install -y -q gcc gcc-c++ make pcre2-devel zlib-devel libzstd-devel curl perl 2>&1 | Out-Null
    } elseif (Get-Command yum -ErrorAction SilentlyContinue) {
        & yum install -y -q gcc gcc-c++ make pcre2-devel zlib-devel libzstd-devel curl perl 2>&1 | Out-Null
    } else {
        Stop-Script "Unsupported package manager"
    }
    
    Write-Log 'INFO' 'Dependencies installed'
}

# ============================================================================
# Download
# ============================================================================
function Get-Sources {
    Push-Location $Script:BUILD_DIR
    Write-Log 'INFO' 'Downloading sources'
    
    Get-File $Script:NGINX_URL "nginx.tgz" $Script:NGINX_SHA256
    Get-File $Script:OPENSSL_URL "openssl.tgz" $Script:OPENSSL_SHA256
    Get-File $Script:PCRE2_URL "pcre2.tgz" $Script:PCRE2_SHA256
    Get-File $Script:ZLIB_URL "zlib.tgz" $Script:ZLIB_SHA256
    Get-File $Script:HEADERS_MORE_URL "headers.tgz" $Script:HEADERS_MORE_SHA256
    Get-File $Script:ZSTD_MODULE_URL "zstd.tgz" $Script:ZSTD_MODULE_SHA256
    
    Write-Log 'INFO' 'Extracting archives'
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
    
    Pop-Location
    Write-Log 'INFO' 'Sources ready'
}

# ============================================================================
# Build
# ============================================================================
function Build-Nginx {
    $useSystemSsl = $false
    $sslOpt = ""
    
    # Check WSL ARM64
    $kernelInfo = & uname -r
    $arch = & uname -m
    if ($kernelInfo -match 'microsoft' -and $arch -eq 'aarch64') {
        Write-Log 'WARN' 'WSL ARM64 detected - using system OpenSSL'
        $useSystemSsl = $true
    }
    
    # Clean up /tmp
    Get-ChildItem /tmp -Filter 'cc*' -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem /tmp -Filter 'tmp.*' -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem /tmp -Filter 'nginx-build-*' -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem /tmp -Filter 'nginx-logs-*' -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    
    # Check disk space in /tmp
    $tmpSpace = (& df /tmp | Select-Object -Skip 1 | ForEach-Object { $_.Split([char[]]@(' ', "`t"), [System.StringSplitOptions]::RemoveEmptyEntries)[3] })
    if ([int]$tmpSpace -lt 1048576) {
        Write-Log 'WARN' "Low disk space in /tmp, using build directory for temp files"
        $env:TMPDIR = $Script:BUILD_DIR
    }
    
    # Ensure cc symlink exists
    $ccPath = Get-Command cc -ErrorAction SilentlyContinue
    if (-not $ccPath) {
        $gccPath = Get-Command gcc -ErrorAction SilentlyContinue
        if ($gccPath -and (Test-Path '/usr/local/bin')) {
            New-Item -ItemType SymbolicLink -Path '/usr/local/bin/cc' -Target $gccPath.Source -Force -ErrorAction SilentlyContinue | Out-Null
            $env:PATH = "/usr/local/bin:$env:PATH"
        }
    }
    
    # Build OpenSSL
    if (-not $useSystemSsl) {
        Write-Log 'INFO' "Building OpenSSL $Script:OPENSSL_VERSION"
        Push-Location (Join-Path $Script:BUILD_DIR 'openssl')
        
        $archConfig = switch ($arch) {
            'x86_64' { 'linux-x86_64' }
            'aarch64' { 'linux-aarch64' }
            'armv7l' { 'linux-armv4' }
            default { 'linux-generic64' }
        }
        
        $configOutput = bash -c "export TMPDIR='$Script:BUILD_DIR' && ./Configure $archConfig --prefix=`$(pwd)/../openssl-install --openssldir=`$(pwd)/../openssl-install/ssl enable-tls1_3 no-shared -fPIC 2>&1 | grep -v '^DEBUG:' | grep -v '^No value given'"
        if ($LASTEXITCODE -ne 0) {
            Write-Log 'WARN' "OpenSSL configure failed: $configOutput"
            Write-Log 'WARN' 'Using system OpenSSL'
            $useSystemSsl = $true
        } else {
            $makeOutput = bash -c "export TMPDIR='$Script:BUILD_DIR' && make -j`$(nproc) 2>&1 | grep -v '^DEBUG:'"
            if ($LASTEXITCODE -ne 0) {
                Write-Log 'WARN' "OpenSSL build failed: $($makeOutput | Select-Object -Last 10)"
                Write-Log 'WARN' 'Using system OpenSSL'
                $useSystemSsl = $true
            } else {
                bash -c "make install_sw 2>&1 | grep -v '^DEBUG:'" | Out-Host
                $sslOpt = "--with-openssl=$(Join-Path $Script:BUILD_DIR 'openssl')"
                Write-Log 'INFO' 'OpenSSL built'
            }
        }
        Pop-Location
    }
    
    # Install system OpenSSL if needed
    if ($useSystemSsl) {
        if (Get-Command apt-get -ErrorAction SilentlyContinue) {
            & apt-get install -y libssl-dev | Out-Null
        } elseif (Get-Command dnf -ErrorAction SilentlyContinue) {
            & dnf install -y openssl-devel | Out-Null
        } elseif (Get-Command yum -ErrorAction SilentlyContinue) {
            & yum install -y openssl-devel | Out-Null
        }
        Write-Log 'INFO' 'Using system OpenSSL'
    }
    
    # Build Nginx
    Write-Log 'INFO' "Building Nginx $Script:NGINX_VERSION"
    Push-Location (Join-Path $Script:BUILD_DIR 'nginx')
    
    $pcre2Path = Join-Path $Script:BUILD_DIR 'pcre2'
    $zlibPath = Join-Path $Script:BUILD_DIR 'zlib'
    $headersPath = Join-Path $Script:BUILD_DIR 'headers-more'
    $zstdPath = Join-Path $Script:BUILD_DIR 'zstd-module'
    
    $configCmd = "export TMPDIR='$Script:BUILD_DIR' && export CC=gcc && ./configure --prefix=/usr/local/nginx --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf --http-log-path=/var/log/nginx/access.log --error-log-path=/var/log/nginx/error.log --pid-path=/run/nginx.pid --lock-path=/var/lock/nginx.lock $sslOpt --with-pcre=$pcre2Path --with-zlib=$zlibPath --with-pcre-jit --with-http_ssl_module --with-http_v2_module --with-http_v3_module --with-http_gzip_static_module --with-http_stub_status_module --with-http_realip_module --with-http_sub_module --with-http_secure_link_module --with-stream --with-stream_ssl_module --with-stream_ssl_preread_module --with-stream_realip_module --with-file-aio --with-threads --modules-path=/etc/nginx/modules --add-dynamic-module=$headersPath --add-dynamic-module=$zstdPath"
    
    $configOutput = bash -c "$configCmd 2>&1"
    if ($LASTEXITCODE -ne 0) { 
        Write-Log 'ERROR' "Configure output: $($configOutput | Select-Object -Last 20)"
        Stop-Script 'Nginx configure failed' 
    }
    
    $makeOutput = bash -c "export TMPDIR='$Script:BUILD_DIR' && make -j`$(nproc) 2>&1"
    if ($LASTEXITCODE -ne 0) { 
        Write-Log 'ERROR' "Make output: $($makeOutput | Select-Object -Last 20)"
        Stop-Script 'Nginx build failed' 
    }
    
    Pop-Location
    Write-Log 'INFO' 'Build complete'
}

# ============================================================================
# Install
# ============================================================================
function Install-HtmlFiles {
    Write-Log 'INFO' "Installing HTML files"
    $htmlDir = '/usr/share/nginx/html'
    if (-not (Test-Path $htmlDir)) {
        New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null
    }
    
    $indexHtmlPath = Join-Path $Script:CONFIG_DIR 'index.html'
    if (Test-Path $indexHtmlPath) {
        bash -c "cd '$Script:SCRIPT_DIR' && source '$indexHtmlPath' 2>/dev/null && create_html_files 2>/dev/null || true" | Out-Null
    }
    
    # Verify or create basic HTML
    $indexFile = Join-Path $htmlDir 'index.html'
    if (-not (Test-Path $indexFile) -or (Get-Item $indexFile).Length -lt 100) {
        @'
<!doctype html>
<html><head><title>Welcome to NGINX</title></head>
<body><h1>NGINX is running</h1><p>Server successfully installed.</p></body>
</html>
'@ | Out-File -FilePath $indexFile -Encoding utf8 -NoNewline
    }
    bash -c "chmod 0644 $htmlDir/*.html 2>/dev/null || true" | Out-Null
}

function New-SelfSignedCertificate {
    Write-Log 'INFO' 'Generating self-signed TLS certificate'
    
    $sslDir = '/etc/nginx/ssl'
    if (-not (Test-Path $sslDir)) {
        New-Item -ItemType Directory -Path $sslDir -Force | Out-Null
    }
    
    # Find openssl binary
    $opensslPath = (Get-Command openssl -ErrorAction SilentlyContinue)?.Source
    if (-not $opensslPath) {
        $candidate1 = Join-Path $Script:BUILD_DIR 'openssl-install/bin/openssl'
        $candidate2 = Join-Path $Script:BUILD_DIR 'openssl/apps/openssl'
        if (Test-Path $candidate1) { $opensslPath = $candidate1 }
        elseif (Test-Path $candidate2) { $opensslPath = $candidate2 }
    }

    if (-not $opensslPath) {
        if (Get-Command apt-get -ErrorAction SilentlyContinue) {
            & apt-get update -qq 2>&1 | Out-Null
            & apt-get install -y openssl 2>&1 | Out-Null
        } elseif (Get-Command dnf -ErrorAction SilentlyContinue) {
            & dnf install -y openssl 2>&1 | Out-Null
        } elseif (Get-Command yum -ErrorAction SilentlyContinue) {
            & yum install -y openssl 2>&1 | Out-Null
        }
        $opensslPath = (Get-Command openssl -ErrorAction SilentlyContinue)?.Source
    }

    if (-not $opensslPath) { Stop-Script 'openssl not found' }

    $keyPath = "$sslDir/nginx.key"
    $crtPath = "$sslDir/nginx.crt"
    
    $output = bash -c "OPENSSL_CONF=/dev/null '$opensslPath' req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 365 -nodes -keyout '$keyPath' -out '$crtPath' -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' 2>&1"
    
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $crtPath)) {
        Write-Log 'ERROR' "OpenSSL output: $output"
        Stop-Script 'Certificate generation failed'
    }

    bash -c "chmod 600 '$keyPath' && chmod 644 '$crtPath'"
}

function New-NginxConfig {
    Write-Log 'INFO' 'Creating nginx configuration'
    
    $nginxConfig = @'
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
        return 301 https://$host$request_uri;
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
        add_header X-Protocol $server_protocol always;
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
'@
    
    $nginxConfig | Out-File -FilePath '/etc/nginx/nginx.conf' -Encoding utf8 -NoNewline
}

function Install-Nginx {
    Write-Log 'INFO' 'Installing Nginx'
    
    # Backup existing config
    if (Test-Path '/etc/nginx') {
        if (-not (Test-Path $Script:BACKUP_DIR)) {
            New-Item -ItemType Directory -Path $Script:BACKUP_DIR -Force | Out-Null
        }
        Copy-Item -Path '/etc/nginx' -Destination "$Script:BACKUP_DIR/" -Recurse -Force
    }
    
    # Install
    Push-Location (Join-Path $Script:BUILD_DIR 'nginx')
    $installOutput = bash -c 'make install 2>&1'
    if ($LASTEXITCODE -ne 0) {
        Pop-Location
        Write-Log 'ERROR' "Install output: $($installOutput | Select-Object -Last 10)"
        Stop-Script 'Nginx install failed'
    }
    Pop-Location
    
    # Setup directories
    $dirs = @('/etc/nginx/conf.d', '/etc/nginx/modules', '/etc/nginx/sites-available', 
              '/etc/nginx/sites-enabled', '/var/log/nginx', '/var/cache/nginx', '/usr/share/nginx/html')
    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
    
    # Copy modules
    $objsDir = Join-Path $Script:BUILD_DIR 'nginx/objs'
    Get-ChildItem $objsDir -Filter '*.so' -ErrorAction SilentlyContinue | ForEach-Object {
        Copy-Item $_.FullName -Destination '/etc/nginx/modules/' -Force
    }
    
    # Install HTML, certs, and config
    Install-HtmlFiles
    New-SelfSignedCertificate
    New-NginxConfig
    
    # Create user
    bash -c 'id nginx 2>/dev/null'
    if ($LASTEXITCODE -ne 0) {
        bash -c 'useradd -r -s /sbin/nologin nginx' | Out-Null
    }
    bash -c 'chown -R nginx:nginx /var/log/nginx /var/cache/nginx' | Out-Null
    bash -c 'chmod 755 /etc/nginx/conf.d /etc/nginx/modules' | Out-Null
    
    # Systemd service
    $serviceContent = @'
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
    $serviceContent | Out-File -FilePath '/etc/systemd/system/nginx.service' -Encoding utf8 -NoNewline
    
    bash -c 'systemctl daemon-reload' | Out-Null
    bash -c 'systemctl enable nginx' 2>&1 | Out-Null
    bash -c 'nginx -t && systemctl start nginx' | Out-Null
    
    Write-Log 'INFO' "Nginx $Script:NGINX_VERSION with OpenSSL $Script:OPENSSL_VERSION installed"
    Write-Log 'INFO' "Access: https://localhost"
    bash -c 'nginx -V 2>&1 | head -n1'
    
    # Run post-install checks
    if (-not (Test-NginxInstallation)) {
        Write-Log 'WARN' 'Post-install checks detected issues'
    }
}

function Test-NginxInstallation {
    Write-Log 'INFO' 'Running post-install checks'
    
    # Check cert
    if (-not (Test-Path '/etc/nginx/ssl/nginx.crt') -or -not (Test-Path '/etc/nginx/ssl/nginx.key')) {
        Write-Log 'ERROR' 'SSL certificates missing'
        return $false
    }
    
    # Check nginx -t
    $testResult = bash -c 'nginx -t 2>&1'
    if ($LASTEXITCODE -ne 0) {
        Write-Log 'ERROR' "nginx -t failed: $testResult"
        return $false
    }
    
    # Check service
    $serviceStatus = bash -c 'systemctl is-active nginx 2>/dev/null'
    if ($serviceStatus -ne 'active') {
        Write-Log 'WARN' "Nginx service not active (status: $serviceStatus)"
    }
    
    # Check https://localhost
    bash -c 'curl -sk https://localhost -o /dev/null -w "%{http_code}" 2>/dev/null' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Log 'WARN' 'Unable to verify https://localhost response'
    } else {
        Write-Log 'INFO' 'All checks passed'
    }
    
    return $true
}

# ============================================================================
# Remove
# ============================================================================
function Remove-Nginx {
    Write-Log 'INFO' 'Removing Nginx'
    bash -c 'systemctl stop nginx 2>/dev/null || true' | Out-Null
    $pathsToRemove = @('/usr/sbin/nginx', '/etc/nginx', '/var/log/nginx', '/var/cache/nginx')
    foreach ($path in $pathsToRemove) {
        if (Test-Path $path) {
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    bash -c 'userdel nginx 2>/dev/null || true' | Out-Null
    Write-Log 'INFO' 'Nginx removed'
}

# ============================================================================
# Pre-flight checks
# ============================================================================
function Test-RunningWebServers {
    $port443 = bash -c "lsof -ti :443 2>/dev/null | head -n1"
    if ($port443) {
        $proc = bash -c "ps -p $port443 -o comm= 2>/dev/null"
        Write-Log 'WARN' "Port 443 in use by: $proc"
        $response = Read-Host 'Stop conflicting services? [y/N]'
        if ($response -eq 'y' -or $response -eq 'Y') {
            bash -c 'systemctl stop apache2 2>/dev/null || true' | Out-Null
            bash -c 'systemctl stop httpd 2>/dev/null || true' | Out-Null
            bash -c 'systemctl stop nginx 2>/dev/null || true' | Out-Null
            Write-Log 'INFO' 'Services stopped'
        } else {
            Write-Log 'ERROR' 'Cannot proceed with port 443 in use'
            Stop-Script
        }
    }
}

# ============================================================================
# Main
# ============================================================================
try {
    switch ($Command) {
        'install' {
            Test-RunningWebServers
            Install-Dependencies
            Get-Sources
            Build-Nginx
            Install-Nginx
            Write-Host ""
            Write-Host "Installation log: $Script:LOG_FILE"
        }
        'remove' {
            Remove-Nginx
            Write-Host ""
            Write-Host "Removal log: $Script:LOG_FILE"
        }
    }
} finally {
    if (Test-Path $Script:BUILD_DIR) {
        Remove-Item -Path $Script:BUILD_DIR -Recurse -Force -ErrorAction SilentlyContinue
    }
}
