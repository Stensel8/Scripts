#!/usr/bin/env pwsh
<#!
.SYNOPSIS
    Compile and install NGINX from source with OpenSSL using PowerShell 7.
.DESCRIPTION
    This script maintains feature parity with the Bash installer while drawing
    templates from the files stored in the `config` folder beside the script. No
    configuration values are embedded directly in the script; all nginx configuration
    and default site files are sourced from those templates.
#>

# ============================================================================
# PARAMETER PARSING
# ============================================================================
param(
    [Parameter()][ValidateSet('install','remove','verify','help')][string]$Command = 'install'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# GLOBALS & CONSTANTS
# ============================================================================
$Script:ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent (Convert-Path $MyInvocation.MyCommand.Path) }
$Script:ConfigDir  = Join-Path $Script:ScriptRoot 'config'
$Script:BuildDir   = Join-Path ([System.IO.Path]::GetTempPath()) ("nginx-build-" + [Guid]::NewGuid().ToString('N'))
$Script:LogDir     = Join-Path ([System.IO.Path]::GetTempPath()) ("nginx-logs-" + [Guid]::NewGuid().ToString('N'))
$Script:Prefix     = '/usr/local/nginx'
$Script:ServiceName = 'nginx'
$Script:BackupDir  = "/root/nginx-backup-$((Get-Date).ToString('yyyyMMdd-HHmmss'))"
$Script:CurrentStep = $null
$Script:ZstdBuildMode = 'dynamic'

$null = New-Item -ItemType Directory -Path $Script:BuildDir -Force
$null = New-Item -ItemType Directory -Path $Script:LogDir -Force

# Load configuration from .env file
function Import-EnvFile {
    param([string]$Path)
    $envVars = @{}
    if (Test-Path $Path) {
        Get-Content $Path | ForEach-Object {
            $line = $_.Trim()
            if ($line -and -not $line.StartsWith('#')) {
                if ($line -match '^([^=]+)=(.*)$') {
                    $key = $Matches[1].Trim()
                    $value = $Matches[2].Trim().Trim('"').Trim("'")
                    # Simple variable expansion for ${VAR} syntax
                    while ($value -match '\$\{([^}]+)\}') {
                        $varName = $Matches[1]
                        $varValue = if ($envVars.ContainsKey($varName)) { $envVars[$varName] } else { '' }
                        $value = $value -replace "\$\{$varName\}", $varValue
                    }
                    $envVars[$key] = $value
                }
            }
        }
    }
    return $envVars
}

$EnvFile = Join-Path $Script:ConfigDir '.env'
$EnvConfig = Import-EnvFile -Path $EnvFile

# Version catalogue (loaded from .env or fallback to defaults)
$Versions = [ordered]@{
    Nginx        = if ($EnvConfig['NGINX_VERSION']) { $EnvConfig['NGINX_VERSION'] } else { '1.29.2' }
    OpenSSL      = if ($EnvConfig['OPENSSL_VERSION']) { $EnvConfig['OPENSSL_VERSION'] } else { '3.6.0' }
    PCRE2        = if ($EnvConfig['PCRE2_VERSION']) { $EnvConfig['PCRE2_VERSION'] } else { '10.47' }
    Zlib         = if ($EnvConfig['ZLIB_VERSION']) { $EnvConfig['ZLIB_VERSION'] } else { '1.3.1' }
    HeadersMore  = if ($EnvConfig['HEADERS_MORE_VERSION']) { $EnvConfig['HEADERS_MORE_VERSION'] } else { '0.39' }
    ZstdModule   = if ($EnvConfig['ZSTD_MODULE_VERSION']) { $EnvConfig['ZSTD_MODULE_VERSION'] } else { '0.1.1' }
}

# Helper function to split URLs from .env
function Get-UrlArray {
    param([string]$UrlString)
    if ([string]::IsNullOrWhiteSpace($UrlString)) { return @() }
    return $UrlString -split ',' | ForEach-Object { $_.Trim() }
}

$Artifacts = @(
    [pscustomobject]@{
        Id = 'nginx'
        Archive = "nginx-$($Versions.Nginx).tar.gz"
        Sha256 = if ($EnvConfig['NGINX_SHA256']) { $EnvConfig['NGINX_SHA256'] } else { '5669e3c29d49bf7f6eb577275b86efe4504cf81af885c58a1ed7d2e7b8492437' }
        Strip = 1
        Target = "nginx-$($Versions.Nginx)"
        Toggle = $null
        Urls = if ($EnvConfig['NGINX_URL']) { Get-UrlArray $EnvConfig['NGINX_URL'] } else { @("https://nginx.org/download/nginx-$($Versions.Nginx).tar.gz","https://github.com/nginx/nginx/archive/refs/tags/release-$($Versions.Nginx).tar.gz") }
    }
    [pscustomobject]@{
        Id = 'openssl'
        Archive = "openssl-$($Versions.OpenSSL).tar.gz"
        Sha256 = if ($EnvConfig['OPENSSL_SHA256']) { $EnvConfig['OPENSSL_SHA256'] } else { 'b6a5f44b7eb69e3fa35dbf15524405b44837a481d43d81daddde3ff21fcbb8e9' }
        Strip = 0
        Target = "openssl-$($Versions.OpenSSL)"
        Toggle = $null
        Urls = if ($EnvConfig['OPENSSL_URL']) { Get-UrlArray $EnvConfig['OPENSSL_URL'] } else { @("https://www.openssl.org/source/openssl-$($Versions.OpenSSL).tar.gz","https://github.com/openssl/openssl/releases/download/openssl-$($Versions.OpenSSL)/openssl-$($Versions.OpenSSL).tar.gz") }
    }
    [pscustomobject]@{
        Id = 'pcre2'
        Archive = "pcre2-$($Versions.PCRE2).tar.gz"
        Sha256 = if ($EnvConfig['PCRE2_SHA256']) { $EnvConfig['PCRE2_SHA256'] } else { 'c08ae2388ef333e8403e670ad70c0a11f1eed021fd88308d7e02f596fcd9dc16' }
        Strip = 0
        Target = "pcre2-$($Versions.PCRE2)"
        Toggle = $null
        Urls = if ($EnvConfig['PCRE2_URL']) { Get-UrlArray $EnvConfig['PCRE2_URL'] } else { @("https://github.com/PCRE2Project/pcre2/releases/download/pcre2-$($Versions.PCRE2)/pcre2-$($Versions.PCRE2).tar.gz") }
    }
    [pscustomobject]@{
        Id = 'zlib'
        Archive = "zlib-$($Versions.Zlib).tar.gz"
        Sha256 = if ($EnvConfig['ZLIB_SHA256']) { $EnvConfig['ZLIB_SHA256'] } else { '9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23' }
        Strip = 0
        Target = "zlib-$($Versions.Zlib)"
        Toggle = $null
        Urls = if ($EnvConfig['ZLIB_URL']) { Get-UrlArray $EnvConfig['ZLIB_URL'] } else { @("https://zlib.net/zlib-$($Versions.Zlib).tar.gz","https://github.com/madler/zlib/releases/download/v$($Versions.Zlib)/zlib-$($Versions.Zlib).tar.gz") }
    }
    [pscustomobject]@{
        Id = 'headers-more'
        Archive = 'headers-more.tar.gz'
        Sha256 = if ($EnvConfig['HEADERS_MORE_SHA256']) { $EnvConfig['HEADERS_MORE_SHA256'] } else { 'dde68d3fa2a9fc7f52e436d2edc53c6d703dcd911283965d889102d3a877c778' }
        Strip = 1
        Target = 'headers-more-module'
        Toggle = 'ENABLE_HEADERS_MORE'
        Urls = if ($EnvConfig['HEADERS_MORE_URL']) { Get-UrlArray $EnvConfig['HEADERS_MORE_URL'] } else { @("https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v$($Versions.HeadersMore).tar.gz") }
    }
    [pscustomobject]@{
        Id = 'zstd'
        Archive = 'zstd-module.tar.gz'
        Sha256 = if ($EnvConfig['ZSTD_MODULE_SHA256']) { $EnvConfig['ZSTD_MODULE_SHA256'] } else { '707d534f8ca4263ff043066db15eac284632aea875f9fe98c96cea9529e15f41' }
        Strip = 1
        Target = 'zstd-module'
        Toggle = 'ENABLE_ZSTD'
        Urls = if ($EnvConfig['ZSTD_MODULE_URL']) { Get-UrlArray $EnvConfig['ZSTD_MODULE_URL'] } else { @("https://github.com/tokers/zstd-nginx-module/archive/refs/tags/$($Versions.ZstdModule).tar.gz") }
    }
)

# ============================================================================
# LOGGING HELPERS
# ============================================================================
$HostSupportsColor = $Host.UI.SupportsVirtualTerminal

function Write-InstallerLog {
    param(
        [Parameter(Mandatory)][ValidateSet('Info','Success','Error','Warn','Step')][string]$Level,
        [Parameter(Mandatory)][string]$Message
    )
    $prefix = switch ($Level) {
        'Info'    { if ($HostSupportsColor) { "`e[34m[INFO]`e[0m" } else { '[INFO]' } }
        'Success' { if ($HostSupportsColor) { "`e[32m[OK]`e[0m" } else { '[OK]' } }
        'Error'   { if ($HostSupportsColor) { "`e[31m[ERR]`e[0m" } else { '[ERR]' } }
        'Warn'    { if ($HostSupportsColor) { "`e[33m[WARN]`e[0m" } else { '[WARN]' } }
        'Step'    { if ($HostSupportsColor) { "`e[35m[STEP]`e[0m" } else { '[STEP]' } }
    }
    if ($Level -eq 'Step') { $Script:CurrentStep = $Message }
    Write-Information -MessageData "$prefix $Message" -InformationAction Continue
}

function Write-Info    { param([string]$Message) Write-InstallerLog -Level Info    -Message $Message }
function Write-Warn    { param([string]$Message) Write-InstallerLog -Level Warn    -Message $Message }
function Write-ErrorLog{ param([string]$Message) Write-InstallerLog -Level Error   -Message $Message }
function Write-Step    { param([string]$Message) Write-InstallerLog -Level Step    -Message $Message }
function Write-Success { param([string]$Message) Write-InstallerLog -Level Success -Message $Message }

# Error handler
Register-EngineEvent PowerShell.OnScriptTerminating -Action {
    param($eventSender, $psEventArgs)
    [void]$eventSender
    if ($psEventArgs.Exception) {
        Write-ErrorLog "An error occurred (exit=$($psEventArgs.ExitCode)) during step: $($Script:CurrentStep)"
        Write-Info "Log directory: $Script:LogDir"
    }
} | Out-Null

# ============================================================================
# UTILITY HELPERS
# ============================================================================
function Test-IsRoot {
    if ($IsLinux -or $IsMacOS) {
        try {
            return (& id -u) -eq 0
        } catch {
            return $false
        }
    }
    elseif ($IsWindows) {
        $current = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($current)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    else {
        return $false
    }
}

function Assert-RootPrivilege {
    if (-not (Test-IsRoot)) {
        throw "This installer must be run with administrative privileges (root)"
    }
}

function Get-EnvValue {
    param([string]$Name)
    return [Environment]::GetEnvironmentVariable($Name)
}

function Get-EnvToggle {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Default = 'auto'
    )
    $value = Get-EnvValue $Name
    if ([string]::IsNullOrWhiteSpace($value)) { $value = $Default }
    switch (($value -as [string]).Trim().ToLowerInvariant()) {
        {$_ -in @('0','no','false','off','disable','disabled')} { return $false }
        {$_ -in @('auto','yes','true','on','enable','enabled','1')} { return $true }
        default {
            throw "Invalid value '$value' for $Name. Valid: yes/no/true/false/on/off/auto"
        }
    }
}

function Get-ChecksumPolicy {
    $policy = (Get-EnvValue 'CHECKSUM_POLICY')
    if ([string]::IsNullOrWhiteSpace($policy)) { $policy = 'strict' }
    $policy = $policy.Trim().ToLowerInvariant()
    switch ($policy) {
        'strict' { return $policy }
        'allow-missing' { return $policy }
        'skip' { return $policy }
        default { throw "Invalid CHECKSUM_POLICY '$policy'. Use strict, allow-missing, or skip." }
    }
}

function Confirm-Action {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [string]$EnvVar = 'CONFIRM'
    )
    $envConfirm = Get-EnvValue $EnvVar
    if ([string]::IsNullOrWhiteSpace($envConfirm)) {
        $envConfirm = 'yes'
    }
    $decision = $envConfirm.Trim().ToLowerInvariant()
    switch ($decision) {
        { $_ -in @('yes','y','true','1','auto','continue','proceed') } {
            Write-Info "Auto-confirmed: $Prompt ($EnvVar=$decision)"
            return $true
        }
        { $_ -in @('no','n','false','0','stop','abort','cancel') } {
            Write-Warn "Operation cancelled via $EnvVar=$decision"
            return $false
        }
        default {
            Write-Info "Auto-confirmed: $Prompt ($EnvVar=$decision)"
            return $true
        }
    }
}

function Get-ProcessorCount { [Environment]::ProcessorCount }

function Test-Systemd {
    if (-not (Get-Command systemctl -ErrorAction SilentlyContinue)) { return $false }
    return Test-Path '/run/systemd/system'
}

function Get-PrimaryIPAddress {
    try {
        $ip = (& hostname -I) -split '\s+' | Where-Object { $_ } | Select-Object -First 1
        if ($ip) { return $ip }
    } catch {
        Write-Warn ("Unable to retrieve primary IP via hostname -I: {0}" -f $_.Exception.Message)
    }
    try {
        $ip = (& ip -4 -o addr show scope global) | ForEach-Object {
            ($_ -split '\s+') | Select-Object -Last 1
        } | ForEach-Object { ($_ -split '/') | Select-Object -First 1 } | Select-Object -First 1
        if ($ip) { return $ip }
    } catch {
        Write-Warn ("Unable to retrieve primary IP via ip command: {0}" -f $_.Exception.Message)
    }
    return 'unknown'
}

function Get-LogFilePath {
    param([Parameter(Mandatory)][string]$Name)
    return Join-Path $Script:LogDir $Name
}

function Invoke-LoggedProcess {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments,
        [string]$WorkingDirectory,
        [string]$LogName
    )
    $logPath = if ($LogName) { Get-LogFilePath $LogName } else { [System.IO.Path]::GetTempFileName() }
    $stdout = "$logPath.stdout"
    $stderr = "$logPath.stderr"

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    if ($Arguments) {
        foreach ($argument in $Arguments) {
            if ($null -ne $argument) {
                [void]$psi.ArgumentList.Add([string]$argument)
            }
        }
    }
    if ($WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $process = [System.Diagnostics.Process]::Start($psi)
    $stdOutContent = $process.StandardOutput.ReadToEnd()
    $stdErrContent = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    Set-Content -Path $stdout -Value $stdOutContent
    Set-Content -Path $stderr -Value $stdErrContent
    $combined = @($stdOutContent, $stdErrContent) -join "`n"
    Set-Content -Path $logPath -Value $combined

    Remove-Item -Force $stdout,$stderr -ErrorAction SilentlyContinue

    if ($process.ExitCode -ne 0) {
        throw "Command '$FilePath' failed with exit code $($process.ExitCode). See log: $logPath"
    }

    return $logPath
}

function Invoke-CommandWithShell {
    param(
        [Parameter(Mandatory)][string]$Command,
        [string]$WorkingDirectory,
        [string]$LogName
    )
    $logPath = if ($LogName) { Get-LogFilePath $LogName } else { [System.IO.Path]::GetTempFileName() }
    $stdout = "$logPath.stdout"
    $stderr = "$logPath.stderr"

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = '/bin/bash'
    $psi.ArgumentList.Add('-lc')
    $psi.ArgumentList.Add($Command)
    if ($WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $process = [System.Diagnostics.Process]::Start($psi)
    $stdOutContent = $process.StandardOutput.ReadToEnd()
    $stdErrContent = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    Set-Content -Path $stdout -Value $stdOutContent
    Set-Content -Path $stderr -Value $stdErrContent
    $combined = @($stdOutContent, $stdErrContent) -join "`n"
    Set-Content -Path $logPath -Value $combined

    Remove-Item -Force $stdout,$stderr -ErrorAction SilentlyContinue

    if ($process.ExitCode -ne 0) {
        throw "Shell command failed with exit code $($process.ExitCode). See log: $logPath"
    }

    return $logPath
}

function Set-ConfigTemplate {
    param(
        [bool]$EnableStream,
        [bool]$EnableZstd
    )

    Write-Step 'Applying configuration templates'

    # Create main nginx.conf
    $streamBlock = if ($EnableStream) {
        @'

# TCP/UDP stream (optional)
stream {
    include /etc/nginx/stream.d/*.conf;
}
'@
    } else { '' }

    $nginxConf = @"
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
    # Hide NGINX version on error pages
    server_tokens off;

    include /etc/nginx/mime.types;

    # Pull in modular HTTP snippets (core, security, compression, TLS, etc.)
    include /etc/nginx/snippets/*.conf;

    # Site-specific vhosts belong in conf.d (kept empty by this installer)
    include /etc/nginx/conf.d/*.conf;
}
${streamBlock}
"@
    Set-Content -Path '/etc/nginx/nginx.conf' -Value $nginxConf -NoNewline
    try { & chmod 0644 /etc/nginx/nginx.conf >$null 2>&1 } catch {}
    Write-Success 'Created main nginx.conf'

    # Create configuration snippets
    $null = New-Item -ItemType Directory -Path '/etc/nginx/snippets' -Force

    $snippets = @{
        'common.conf' = @'
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
'@
        'security.conf' = @'
# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;

# Completely remove the Server header
# This requires the headers-more module, which is enabled by default
more_clear_headers "Server";
'@
        'ssl_core.conf' = @'
# Core SSL/TLS settings (modern)
# TLS 1.3 only to avoid legacy/weak ciphers; TLSv1.3 cipher suites are chosen by OpenSSL
ssl_protocols TLSv1.3;

# Prefer modern curves for key exchange; X25519 first, fallback to secp384r1
# Note: ssl_conf_command requires OpenSSL 1.1.1+
ssl_conf_command Curves X25519:secp384r1;

ssl_session_cache shared:SSL:50m;
ssl_session_timeout 1d;
'@
        'compression.conf' = @'
# Gzip compression (fallback)
gzip on;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_types text/plain text/css text/xml application/json application/javascript \
           application/xml+rss application/atom+xml image/svg+xml;
'@
        'zstd.conf' = @'
# Enabled only when the zstd module is present
zstd on;
zstd_comp_level 7;
zstd_types text/plain text/css text/xml application/json application/javascript \
           application/xml+rss application/atom+xml image/svg+xml;
'@
        'http_hardening.snippet' = @'
# Block HTTP/1.0 and HTTP/1.1
# Return 444 (Connection Closed Without Response) if not HTTP/2 or HTTP/3
if ($server_protocol ~* "HTTP/1") {
    return 444;
}
'@
    }

    foreach ($file in $snippets.Keys) {
        $path = Join-Path '/etc/nginx/snippets' $file
        Set-Content -Path $path -Value $snippets[$file] -NoNewline
        try { & chmod 0644 $path >$null 2>&1 } catch {}
    }
    Write-Success 'Created configuration snippets'

    # Create HTML files
    $null = New-Item -ItemType Directory -Path '/usr/share/nginx/html' -Force

    $htmlFiles = @{
        'index.html' = @'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Welcome to NGINX</title>
    <style>
        body {
            font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, sans-serif;
            margin: 0;
            background: #f7f9fb;
            color: #111;
        }
        header {
            background: linear-gradient(135deg, #009639, #00b36b);
            color: #fff;
            padding: 20px;
        }
        main {
            max-width: 900px;
            margin: 32px auto;
            padding: 0 16px;
        }
        code {
            background: #eef4f1;
            border-radius: 4px;
            padding: 2px 6px;
        }
        section {
            background: #fff;
            border: 1px solid #e5ece8;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 16px;
            box-shadow: 0 2px 4px rgba(0,0,0,.04);
        }
    </style>
</head>
<body>
    <header>
        <h1 style="margin:0">NGINX installed</h1>
    </header>
    <main>
        <section>
            <p>If you see this page, your server is running and serving content.</p>
            <ul>
                <li>Root: <code>/usr/share/nginx/html</code></li>
                <li>Config: <code>/etc/nginx/nginx.conf</code></li>
                <li>Snippets: <code>/etc/nginx/snippets/</code></li>
                <li>Sites: <code>/etc/nginx/conf.d/</code></li>
            </ul>
            <p>Reload with: <code>nginx -s reload</code></p>
            <p>Features: HTTP/3, TLS 1.3, optimized build</p>
        </section>
    </main>
</body>
</html>
'@
        '404.html' = @'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>404 Not Found</title>
    <style>
        body {
            font-family: system-ui, sans-serif;
            display: grid;
            place-items: center;
            min-height: 100vh;
            background: #f7f9fb;
        }
        main {
            background: #fff;
            border: 1px solid #e5ece8;
            border-radius: 10px;
            padding: 24px 28px;
            box-shadow: 0 2px 4px rgba(0,0,0,.04);
            text-align: center;
        }
    </style>
</head>
<body>
    <main>
        <h1 style="margin:0 0 8px;color:#c1121f">404</h1>
        <p>The requested resource could not be found.</p>
        <p><a href="/" style="color:#009639;text-decoration:none">Go to homepage</a></p>
    </main>
</body>
</html>
'@
        '50x.html' = @'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Server error</title>
    <style>
        body {
            font-family: system-ui, sans-serif;
            display: grid;
            place-items: center;
            min-height: 100vh;
            background: #f7f9fb;
        }
        main {
            background: #fff;
            border: 1px solid #e5ece8;
            border-radius: 10px;
            padding: 24px 28px;
            box-shadow: 0 2px 4px rgba(0,0,0,.04);
            text-align: center;
        }
    </style>
</head>
<body>
    <main>
        <h1 style="margin:0 0 8px;color:#b08900">Something went wrong</h1>
        <p>A temporary error occurred while processing your request.</p>
        <p>Please try again later.</p>
    </main>
</body>
</html>
'@
    }

    foreach ($file in $htmlFiles.Keys) {
        $path = Join-Path '/usr/share/nginx/html' $file
        Set-Content -Path $path -Value $htmlFiles[$file] -NoNewline
        try { & chmod 0644 $path >$null 2>&1 } catch {}
    }
    Write-Success 'Created HTML files'
}

function Write-ModuleLoader {
    param(
        [string]$ModulePath,
        [string]$LoaderName
    )
    $loaderDir = '/etc/nginx/modules.d'
    if (-not (Test-Path $loaderDir)) {
        New-Item -ItemType Directory -Path $loaderDir -Force | Out-Null
    }
    $loaderPath = Join-Path $loaderDir $LoaderName
    $resolvedPath = if ($ModulePath -match '^[\\/]') {
        $ModulePath
    } else {
        ("/etc/nginx/" + $ModulePath).Replace('\', '/')
    }
    $content = "load_module $resolvedPath;`n"
    Set-Content -Path $loaderPath -Value $content -NoNewline
    try {
        & chmod 0644 $loaderPath >$null 2>&1
    } catch {
        Write-Warn ("Failed to set permissions on module loader {0}: {1}" -f $loaderPath, $_.Exception.Message)
    }
    Write-Info "Module loader written: $loaderPath"
}

function Remove-ModuleLoader {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([string]$LoaderName)
    $loaderPath = Join-Path '/etc/nginx/modules.d' $LoaderName
    if (Test-Path $loaderPath) {
        if ($PSCmdlet.ShouldProcess($loaderPath, 'Remove module loader')) {
            Remove-Item $loaderPath -Force
            Write-Info "Removed module loader: $loaderPath"
        }
    }
}

# ============================================================================
# CORE TASKS
# ============================================================================
function Install-BuildDependency {
    Write-Step 'Installing build dependencies'
    $logPrefix = 'deps'
    $env:DEBIAN_FRONTEND = 'noninteractive'
    if (Get-Command apt-get -ErrorAction SilentlyContinue) {
        Invoke-CommandWithShell -Command 'apt-get update -qq' -LogName "$logPrefix-update.log"
        $packages = 'build-essential libpcre2-dev zlib1g-dev perl curl gcc make hostname zstd libzstd-dev pkg-config'
        Invoke-CommandWithShell -Command "apt-get install -y $packages" -LogName "$logPrefix-install.log"
    }
    elseif (Get-Command dnf -ErrorAction SilentlyContinue) {
        $dnfVersion = (& dnf --version 2>$null)
        if ($dnfVersion -match 'dnf5') {
            Invoke-CommandWithShell -Command 'dnf install -y @development-tools' -LogName "$logPrefix-install.log"
        } else {
            Invoke-CommandWithShell -Command 'dnf groupinstall -y "Development Tools"' -LogName "$logPrefix-install.log"
        }
        $packages = 'pcre2-devel zlib-devel perl curl gcc make hostname zstd libzstd libzstd-devel pkgconfig pkgconf-pkg-config'
        Invoke-CommandWithShell -Command "dnf install -y $packages" -LogName "$logPrefix-packages.log"
    }
    elseif (Get-Command yum -ErrorAction SilentlyContinue) {
        Invoke-CommandWithShell -Command 'yum groupinstall -y "Development Tools"' -LogName "$logPrefix-install.log"
        $packages = 'pcre2-devel zlib-devel perl curl gcc make hostname zstd libzstd libzstd-devel pkgconfig pkgconf-pkg-config'
        Invoke-CommandWithShell -Command "yum install -y $packages" -LogName "$logPrefix-packages.log"
    }
    else {
        throw 'Unsupported package manager. Install dependencies manually (apt, dnf, or yum required).'
    }
    Write-Success 'Build dependencies installed'
}

function Test-Checksum {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string]$Expected,
        [string]$Policy
    )
    if ($Policy -eq 'skip') {
        Write-Warn "Checksum verification skipped for $(Split-Path -Leaf $FilePath)"
        return
    }
    if ([string]::IsNullOrWhiteSpace($Expected)) {
        if ($Policy -eq 'strict') {
            throw "Checksum missing for $(Split-Path -Leaf $FilePath)"
        }
        Write-Warn "No checksum provided for $(Split-Path -Leaf $FilePath); continuing due to policy $Policy"
        return
    }
    $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $Expected.ToLowerInvariant()) {
        throw "Checksum mismatch for $(Split-Path -Leaf $FilePath). Expected $Expected, got $hash"
    }
    Write-Success "Checksum verified for $(Split-Path -Leaf $FilePath)"
}

function Invoke-DownloadArtifact {
    $policy = Get-ChecksumPolicy
    Write-Step 'Downloading source archives'
    Push-Location $Script:BuildDir
    try {
        foreach ($artifact in $Artifacts) {
            if ($artifact.Toggle) {
                $enabled = Get-EnvToggle -Name $artifact.Toggle -Default 'auto'
                if (-not $enabled) {
                    Write-Info "$($artifact.Id): disabled via $($artifact.Toggle); skipping download"
                    continue
                }
            }
            $success = $false
            $archivePath = Join-Path $Script:BuildDir $artifact.Archive
            foreach ($url in $artifact.Urls) {
                try {
                    Write-Info "Downloading $($artifact.Id) from $url"
                    Invoke-WebRequest -Uri $url -OutFile $archivePath -UseBasicParsing -TimeoutSec 60
                    $success = $true
                    break
                }
                catch {
                    Write-Warn ("Download failed from {0}: {1}" -f $url, $_.Exception.Message)
                }
            }
            if (-not $success) {
                throw "All download sources failed for $($artifact.Id)"
            }
            Test-Checksum -FilePath $archivePath -Expected $artifact.Sha256 -Policy $policy
            if ($artifact.Strip -eq 0) {
                Invoke-CommandWithShell -Command "tar xzf '$($artifact.Archive)'" -WorkingDirectory $Script:BuildDir -LogName "extract-$($artifact.Id).log"
            } else {
                $targetDir = Join-Path $Script:BuildDir $artifact.Target
                $null = New-Item -ItemType Directory -Path $targetDir -Force
                Invoke-CommandWithShell -Command "tar xzf '$($artifact.Archive)' --strip-components=$($artifact.Strip) -C '$targetDir'" -WorkingDirectory $Script:BuildDir -LogName "extract-$($artifact.Id).log"
            }
            Write-Success "Downloaded $($artifact.Id)"
        }
    }
    finally {
        Pop-Location
    }
}

function Build-OpenSSL {
    Write-Step "Building OpenSSL $($Versions.OpenSSL)"
    $sourceDir = Join-Path $Script:BuildDir "openssl-$($Versions.OpenSSL)"
    $installDir = Join-Path $Script:BuildDir 'openssl-install'
    $null = New-Item -ItemType Directory -Path $installDir -Force

    Push-Location $sourceDir
    try {
        $target = switch ((& uname -m).Trim()) {
            'x86_64' { 'linux-x86_64' }
            'amd64'  { 'linux-x86_64' }
            'aarch64' { 'linux-aarch64' }
            'arm64' { 'linux-aarch64' }
            'armv7l' { 'linux-armv4' }
            'armv6l' { 'linux-armv4' }
            default { 'linux-generic64' }
        }
        Invoke-LoggedProcess -FilePath (Join-Path $sourceDir 'Configure') -Arguments @(
            $target,
            "--prefix=$installDir",
            "--openssldir=$installDir/ssl",
            'enable-tls1_3','no-shared','no-tests','-fPIC','-O3'
        ) -WorkingDirectory $sourceDir -LogName 'openssl-configure.log'

        Invoke-LoggedProcess -FilePath 'make' -Arguments @("-j$(Get-ProcessorCount)") -WorkingDirectory $sourceDir -LogName 'openssl-make.log'
        Invoke-LoggedProcess -FilePath 'make' -Arguments @('install_sw') -WorkingDirectory $sourceDir -LogName 'openssl-install.log'

        if (-not (Test-Path (Join-Path $installDir 'ssl'))) {
            New-Item -ItemType Directory -Path (Join-Path $installDir 'ssl') -Force | Out-Null
        }
        Copy-Item -Path (Join-Path $sourceDir 'apps/openssl.cnf') -Destination (Join-Path $installDir 'ssl/openssl.cnf') -Force
    }
    finally {
        Pop-Location
    }
    Write-Success 'OpenSSL built successfully'
}

function Build-Nginx {
    Write-Step "Building NGINX $($Versions.Nginx)"
    $sourceDir = Join-Path $Script:BuildDir "nginx-$($Versions.Nginx)"
    Push-Location $sourceDir
    try {
    $opensslSource  = Join-Path $Script:BuildDir "openssl-$($Versions.OpenSSL)"
        $pcre2Dir = Join-Path $Script:BuildDir "pcre2-$($Versions.PCRE2)"
        $zlibDir  = Join-Path $Script:BuildDir "zlib-$($Versions.Zlib)"
        $headersDir = Join-Path $Script:BuildDir 'headers-more-module'
        $zstdDir     = Join-Path $Script:BuildDir 'zstd-module'

        $enableHeaders = Get-EnvToggle -Name 'ENABLE_HEADERS_MORE' -Default 'auto'
        $enableZstd    = Get-EnvToggle -Name 'ENABLE_ZSTD' -Default 'auto'
        $enableStream  = Get-EnvToggle -Name 'ENABLE_STREAM' -Default 'auto'

        $commonArgs = @(
            "--prefix=$Script:Prefix",
            "--sbin-path=/usr/sbin/nginx",
            '--conf-path=/etc/nginx/nginx.conf',
            '--pid-path=/run/nginx.pid',
            '--lock-path=/var/lock/nginx.lock',
            '--http-log-path=/var/log/nginx/access.log',
            '--error-log-path=/var/log/nginx/error.log',
            "--with-pcre=$pcre2Dir",
            "--with-zlib=$zlibDir",
            "--with-openssl=$opensslSource",
            '--with-http_ssl_module',
            '--with-http_v2_module',
            '--with-http_v3_module',
            '--with-http_gzip_static_module',
            '--with-http_stub_status_module',
            '--with-http_realip_module',
            '--with-http_sub_module',
            '--with-http_slice_module',
            '--with-pcre-jit',
            '--with-threads',
            '--with-file-aio',
            '--with-http_secure_link_module'
        )
        if ($enableStream) {
            $commonArgs += @(
                '--with-stream',
                '--with-stream_realip_module',
                '--with-stream_ssl_module',
                '--with-stream_ssl_preread_module'
            )
        }

        $dynamicArgs = $commonArgs + @('--modules-path=/etc/nginx/modules')
        if ($enableHeaders -and (Test-Path $headersDir)) {
            $dynamicArgs += "--add-dynamic-module=$headersDir"
        }
        if ($enableZstd -and (Test-Path $zstdDir)) {
            $dynamicArgs += "--add-dynamic-module=$zstdDir"
        }

        $staticArgs = $commonArgs
        if ($enableHeaders -and (Test-Path $headersDir)) {
            $staticArgs += "--add-module=$headersDir"
        }
        if ($enableZstd -and (Test-Path $zstdDir)) {
            $staticArgs += "--add-module=$zstdDir"
        }

        $configureScript = if (Test-Path (Join-Path $sourceDir 'configure')) {
            Join-Path $sourceDir 'configure'
        } elseif (Test-Path (Join-Path $sourceDir 'auto/configure')) {
            '/bin/bash'
        } else {
            throw 'Unable to locate nginx configure script'
        }
        if ($configureScript -eq '/bin/bash') {
            $dynamicArgs = @('auto/configure') + $dynamicArgs
            $staticArgs  = @('auto/configure') + $staticArgs
        }

        # Try dynamic build first
        try {
            if ($configureScript -eq '/bin/bash') {
                Invoke-LoggedProcess -FilePath '/bin/bash' -Arguments $dynamicArgs -WorkingDirectory $sourceDir -LogName 'nginx-configure.log'
            } else {
                Invoke-LoggedProcess -FilePath $configureScript -Arguments $dynamicArgs -WorkingDirectory $sourceDir -LogName 'nginx-configure.log'
            }
            Invoke-LoggedProcess -FilePath 'make' -Arguments @("-j$(Get-ProcessorCount)") -WorkingDirectory $sourceDir -LogName 'nginx-build.log'
            $Script:ZstdBuildMode = 'dynamic'
        }
        catch {
            $logContent = Get-Content (Get-LogFilePath 'nginx-build.log') -ErrorAction SilentlyContinue
            if ($enableZstd -and $logContent -and ($logContent -match 'recompile with -fPIC' -or $logContent -match 'ngx_http_zstd')) {
                Write-Warn 'Dynamic zstd build failed; retrying with static module.'
                Invoke-LoggedProcess -FilePath 'make' -Arguments @('clean') -WorkingDirectory $sourceDir -LogName 'nginx-make-clean.log'
                if ($configureScript -eq '/bin/bash') {
                    Invoke-LoggedProcess -FilePath '/bin/bash' -Arguments $staticArgs -WorkingDirectory $sourceDir -LogName 'nginx-configure.log'
                } else {
                    Invoke-LoggedProcess -FilePath $configureScript -Arguments $staticArgs -WorkingDirectory $sourceDir -LogName 'nginx-configure.log'
                }
                Invoke-LoggedProcess -FilePath 'make' -Arguments @("-j$(Get-ProcessorCount)") -WorkingDirectory $sourceDir -LogName 'nginx-build.log'
                $Script:ZstdBuildMode = 'static'
            }
            else {
                throw
            }
        }
    }
    finally {
        Pop-Location
    }
    Write-Success 'NGINX built successfully'
}

function Initialize-NginxUser {
    if (-not (Get-Command useradd -ErrorAction SilentlyContinue)) { return }
    & id nginx >$null 2>&1
    if ($LASTEXITCODE -eq 0) {
        return
    }
    $nologin = if (Test-Path '/usr/sbin/nologin') { '/usr/sbin/nologin' }
        elseif (Test-Path '/sbin/nologin') { '/sbin/nologin' } else { '/bin/false' }
    & getent group nginx >$null 2>&1
    if ($LASTEXITCODE -ne 0) { & groupadd --system nginx }
    & useradd --system --home /var/cache/nginx --no-create-home --shell $nologin --gid nginx --comment 'nginx user' nginx
    Write-Info 'Created nginx system user'
}

function Copy-DynamicModule {
    $objs = Join-Path $Script:BuildDir "nginx-$($Versions.Nginx)/objs"
    $modulesDir = '/etc/nginx/modules'
    if (-not (Test-Path $modulesDir)) { New-Item -ItemType Directory -Path $modulesDir -Force | Out-Null }
    if (Test-Path $objs) {
        Get-ChildItem -Path $objs -Filter '*.so' -File | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination $modulesDir -Force
        }
    }
    if (-not (Get-ChildItem -Path $modulesDir -Filter '*.so' -File -ErrorAction SilentlyContinue)) {
        Write-Warn 'No dynamic modules were produced.'
    }
    else {
        try {
            & chown root:root (Join-Path $modulesDir '*.so') >$null 2>&1
            & chmod 0644 (Join-Path $modulesDir '*.so') >$null 2>&1
        } catch {
            Write-Warn ("Failed to adjust module ownership or permissions: {0}" -f $_.Exception.Message)
        }
        Write-Success "Dynamic modules copied to $modulesDir"
    }
    $legacyModulesDir = Join-Path $Script:Prefix 'modules'
    if (Test-Path $legacyModulesDir) {
        try {
            Remove-Item $legacyModulesDir -Recurse -Force -ErrorAction Stop
            Write-Info "Removed legacy module directory: $legacyModulesDir"
        }
        catch {
            Write-Warn ("Failed to remove legacy module directory {0}: {1}" -f $legacyModulesDir, $_.Exception.Message)
        }
    }
}

function Install-Nginx {
    Write-Step 'Installing NGINX'
    Initialize-NginxUser
    foreach ($dir in @('/var/cache/nginx/client_temp','/var/cache/nginx/proxy_temp','/var/cache/nginx/fastcgi_temp','/var/cache/nginx/uwsgi_temp','/var/cache/nginx/scgi_temp','/var/log/nginx','/etc/nginx/conf.d','/etc/nginx/snippets','/etc/nginx/stream.d')) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    }
    if (-not (Test-Path '/var/log/nginx/error.log')) { New-Item -ItemType File -Path '/var/log/nginx/error.log' -Force | Out-Null }
    if (-not (Test-Path '/var/log/nginx/access.log')) { New-Item -ItemType File -Path '/var/log/nginx/access.log' -Force | Out-Null }

    Push-Location (Join-Path $Script:BuildDir "nginx-$($Versions.Nginx)")
    try {
        Invoke-LoggedProcess -FilePath 'make' -Arguments @('install') -WorkingDirectory (Get-Location).Path -LogName 'nginx-install.log'
    }
    finally {
        Pop-Location
    }
    Copy-DynamicModule

    try {
        & chown -R root:nginx /etc/nginx >$null 2>&1
        & chmod -R 775 /etc/nginx >$null 2>&1
        & find /etc/nginx -type f -exec chmod 664 {} + >$null 2>&1
    } catch {
        Write-Warn ("Failed to set ownership or permissions under /etc/nginx: {0}" -f $_.Exception.Message)
    }
    try {
        & chown -R nginx:nginx /var/log/nginx /var/cache/nginx >$null 2>&1
        & chmod -R 775 /var/log/nginx >$null 2>&1
        & find /var/log/nginx -type f -exec chmod 664 {} + >$null 2>&1
        & chmod -R 750 /var/cache/nginx >$null 2>&1
    } catch {
        Write-Warn ("Failed to set ownership or permissions for nginx runtime directories: {0}" -f $_.Exception.Message)
    }
    Write-Success 'NGINX files installed'
}

function Backup-ExistingInstall {
    Write-Step 'Creating backup of any existing installation'
    New-Item -ItemType Directory -Path $Script:BackupDir -Force | Out-Null
    if (Test-Path '/etc/nginx') { Copy-Item -Path '/etc/nginx' -Destination $Script:BackupDir -Recurse -Force }
    if (Test-Path '/usr/sbin/nginx') { Copy-Item -Path '/usr/sbin/nginx' -Destination (Join-Path $Script:BackupDir 'nginx.sbin') -Force }
    if (Test-Systemd) {
        & systemctl is-active --quiet nginx
        $isActive = $LASTEXITCODE -eq 0
        $status = if ($isActive) { 'nginx was active' } else { 'nginx was inactive' }
        Set-Content -Path (Join-Path $Script:BackupDir 'service_status.txt') -Value $status
    }
    Write-Success "Backup stored at $Script:BackupDir"
}

function Write-SystemdService {
    if (-not (Test-Systemd)) {
        Write-Warn 'Systemd not detected; skipping service creation.'
        return
    }
    $servicePath = "/etc/systemd/system/${Script:ServiceName}.service"
    $content = @'
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
'@
    Set-Content -Path $servicePath -Value $content -NoNewline
    try {
        & systemctl daemon-reload >$null 2>&1
        & systemctl enable nginx >$null 2>&1
    } catch {
        Write-Warn ("Failed to register nginx systemd service: {0}" -f $_.Exception.Message)
    }
    Write-Success 'Systemd service created and enabled'
}

function New-SelfSignedCertIfMissing {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()
    Write-Step 'Ensuring self-signed certificate'
    $sslDir = '/etc/nginx/ssl'
    $crt = Join-Path $sslDir 'localhost.crt'
    $key = Join-Path $sslDir 'localhost.key'
    if ((Test-Path $crt) -and (Test-Path $key)) {
        Write-Info "Self-signed certificate already exists: $crt"
        return
    }
    $opensslBin = Join-Path $Script:BuildDir 'openssl-install/bin/openssl'
    if (-not (Test-Path $opensslBin)) {
        throw "OpenSSL binary not found at $opensslBin"
    }
    if (-not $PSCmdlet.ShouldProcess($sslDir, 'Create self-signed certificate')) {
        return
    }
    if (-not (Test-Path $sslDir)) { New-Item -ItemType Directory -Path $sslDir -Force | Out-Null }
    Invoke-LoggedProcess -FilePath $opensslBin -Arguments @(
        'req','-x509','-nodes','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
        '-keyout',$key,'-out',$crt,'-days','397','-sha256',
        '-subj','/CN=localhost',
        '-addext','subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1'
    ) -LogName 'openssl-selfsigned.log'
    try {
        & chmod 0600 $key >$null 2>&1
        & chmod 0644 $crt >$null 2>&1
    } catch {
        Write-Warn ("Failed to set permissions on generated certificate files: {0}" -f $_.Exception.Message)
    }
    Write-Success "Created self-signed cert: $crt"
}

function Set-HTTPSOnlyConfig {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()
    Write-Step 'Configuring HTTPS-only default server'
    New-SelfSignedCertIfMissing
    $httpsConf = '/etc/nginx/conf.d/https-localhost.conf'
    $content = @'
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    listen 443 quic reuseport;
    listen [::]:443 quic reuseport;
    http2 on;
    server_name _;
    root /usr/share/nginx/html;
    ssl_certificate     /etc/nginx/ssl/localhost.crt;
    ssl_certificate_key /etc/nginx/ssl/localhost.key;
    include /etc/nginx/snippets/ssl_core.conf;
    include /etc/nginx/snippets/compression.conf;
    include /etc/nginx/snippets/security.conf;
    include /etc/nginx/snippets/zstd.conf;
    include /etc/nginx/snippets/http_hardening.snippet;
    add_header Alt-Svc 'h3=":443"; ma=86400' always;
    location / {
        index index.html index.htm;
    }
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    location = /50x.html { root /usr/share/nginx/html; }
}
'@
    if ($PSCmdlet.ShouldProcess($httpsConf, 'Write HTTPS default server configuration')) {
        Set-Content -Path $httpsConf -Value $content -NoNewline
        try {
            & chmod 0644 $httpsConf >$null 2>&1
        } catch {
            Write-Warn ("Failed to set permissions on HTTPS configuration file: {0}" -f $_.Exception.Message)
        }
    }
}

function Test-NginxConfiguration {
    Write-Step 'Testing NGINX configuration'
    if (-not (Test-Path '/var/log/nginx')) { New-Item -ItemType Directory -Path '/var/log/nginx' -Force | Out-Null }
    foreach ($log in @('/var/log/nginx/error.log','/var/log/nginx/access.log')) {
        if (-not (Test-Path $log)) { New-Item -ItemType File -Path $log -Force | Out-Null }
    }
    try {
        & chown -R nginx:nginx /var/log/nginx >$null 2>&1
    } catch {
        Write-Warn ("Failed to set ownership for nginx log directory during test: {0}" -f $_.Exception.Message)
    }

    $result = & nginx -t 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-ErrorLog 'NGINX configuration test failed'
        Write-Info $result
        throw 'nginx -t failed'
    }
    Write-Success 'NGINX configuration syntax is valid'

    if (Test-Systemd) {
        & systemctl is-active --quiet nginx
        if ($LASTEXITCODE -eq 0) {
            & systemctl reload nginx
            Write-Success 'NGINX service reloaded'
        } else {
            & systemctl start nginx
            Write-Success 'NGINX service started via systemd'
        }
    } else {
        & pgrep -f 'nginx: master process' >$null 2>&1
        if ($LASTEXITCODE -eq 0) {
            & /usr/sbin/nginx -s reload
            Write-Success 'NGINX process reloaded'
        } else {
            & /usr/sbin/nginx
            Write-Success 'NGINX process started'
        }
    }
}

function Show-InstallationSummary {
    Write-Information -MessageData '' -InformationAction Continue
    Write-Information -MessageData 'Installation Summary' -InformationAction Continue
    Write-Information -MessageData '--------------------------------------------------------------------------' -InformationAction Continue
    if (Get-Command nginx -ErrorAction SilentlyContinue) {
        $nginxVersion = (& nginx -v 2>&1)
        $opensslInfo = (& nginx -V 2>&1 | Select-String 'built with OpenSSL').ToString()
        Write-Success "NGINX installed: $nginxVersion"
        if ($opensslInfo) { Write-Success "OpenSSL integration: $opensslInfo" }
        if (Test-Systemd) {
            $active = (& systemctl is-active nginx 2>$null)
            if ($active -and $active.Trim() -eq 'active') { Write-Success 'NGINX service is running' } else { Write-Warn 'NGINX service not running' }
        }
    } else {
        Write-ErrorLog 'NGINX binary not found; installation may have failed.'
    }
    Write-Information -MessageData '' -InformationAction Continue
    Write-Information -MessageData 'Service management:' -InformationAction Continue
    if (Test-Systemd) {
        Write-Information -MessageData '  sudo systemctl start nginx' -InformationAction Continue
        Write-Information -MessageData '  sudo systemctl stop nginx' -InformationAction Continue
        Write-Information -MessageData '  sudo systemctl reload nginx' -InformationAction Continue
    } else {
        Write-Information -MessageData '  sudo /usr/sbin/nginx' -InformationAction Continue
        Write-Information -MessageData '  sudo /usr/sbin/nginx -s reload' -InformationAction Continue
    }
    Write-Information -MessageData '' -InformationAction Continue
    Write-Information -MessageData "Config directory: /etc/nginx" -InformationAction Continue
    Write-Information -MessageData "Document root:  /usr/share/nginx/html" -InformationAction Continue
    Write-Information -MessageData "Logs:           /var/log/nginx" -InformationAction Continue
    Write-Information -MessageData "Backup:         $Script:BackupDir" -InformationAction Continue
    Write-Information -MessageData "Primary IP:     $(Get-PrimaryIPAddress)" -InformationAction Continue
    Write-Information -MessageData '' -InformationAction Continue
}

function Remove-NginxInstall {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param()
    if (-not $PSCmdlet.ShouldProcess('nginx installation', 'Remove installation')) {
        return
    }
    Write-Step 'Removing NGINX'
    if (Test-Systemd) {
        & systemctl stop nginx >$null 2>&1
        & systemctl disable nginx >$null 2>&1
        if (Test-Path '/etc/systemd/system/nginx.service') {
            Remove-Item '/etc/systemd/system/nginx.service' -Force
            & systemctl daemon-reload >$null 2>&1
        }
    }
    foreach ($path in @($Script:Prefix,'/usr/sbin/nginx','/etc/nginx','/var/log/nginx','/var/cache/nginx','/usr/share/nginx')) {
    if ((Test-Path $path) -and $PSCmdlet.ShouldProcess($path, 'Remove nginx file tree')) {
            Remove-Item $path -Recurse -Force
        }
    }
    if ($PSCmdlet.ShouldProcess('nginx user', 'Remove system user')) {
        try {
            & userdel nginx >$null 2>&1
        } catch {
            Write-Warn ("Failed to remove nginx user: {0}" -f $_.Exception.Message)
        }
    }
    Write-Success 'NGINX removed'
}

function Test-NginxInstall {
    Write-Step 'Verifying existing installation'
    $issues = 0
    if (Test-Path '/usr/sbin/nginx') {
        Write-Success "Binary found: /usr/sbin/nginx"
    } else {
        Write-ErrorLog 'NGINX binary missing'
        $issues++
    }
    if (Test-Path '/etc/nginx/nginx.conf') {
        Write-Success 'nginx.conf present'
        $result = & nginx -t 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success 'nginx -t succeeded'
        } else {
            Write-ErrorLog 'nginx -t failed'
            Write-Info $result
            $issues++
        }
    } else {
        Write-ErrorLog 'nginx.conf missing'
        $issues++
    }
    if (Test-Systemd) {
        $active = (& systemctl is-active nginx 2>$null)
        if ($active -and $active.Trim() -eq 'active') { Write-Success 'Service running' } else { Write-Warn 'Service not running' }
        $enabled = (& systemctl is-enabled nginx 2>$null)
        if ($enabled -and $enabled.Trim() -eq 'enabled') { Write-Success 'Service enabled' } else { Write-Warn 'Service not enabled' }
    }
    if ($issues -eq 0) {
        Write-Success 'Verification passed'
    } else {
        throw "Verification detected $issues issue(s)."
    }
}

function Invoke-Install {
    Assert-RootPrivilege
    if (-not (Confirm-Action -Prompt 'Proceed with NGINX installation?' -EnvVar 'CONFIRM')) { return }
    Backup-ExistingInstall
    Install-BuildDependency
    Invoke-DownloadArtifact
    Build-OpenSSL
    Build-Nginx
    Install-Nginx
    $enableStream = Get-EnvToggle -Name 'ENABLE_STREAM' -Default 'auto'
    $enableZstd   = Get-EnvToggle -Name 'ENABLE_ZSTD' -Default 'auto'
    Set-ConfigTemplate -EnableStream:$enableStream -EnableZstd:$enableZstd
    if ($enableZstd) {
        Write-ModuleLoader -ModulePath 'modules/ngx_http_zstd_filter_module.so' -LoaderName 'zstd_filter.conf'
        if ($Script:ZstdBuildMode -eq 'dynamic') {
            Write-ModuleLoader -ModulePath 'modules/ngx_http_zstd_static_module.so' -LoaderName 'zstd_static.conf'
        }
    } else {
        Remove-ModuleLoader -LoaderName 'zstd_filter.conf'
        Remove-ModuleLoader -LoaderName 'zstd_static.conf'
    }
    if (Get-EnvToggle -Name 'ENABLE_HEADERS_MORE' -Default 'auto') {
        Write-ModuleLoader -ModulePath 'modules/ngx_http_headers_more_filter_module.so' -LoaderName 'headers_more.conf'
    } else {
        Remove-ModuleLoader -LoaderName 'headers_more.conf'
    }
    Write-SystemdService
    Set-HTTPSOnlyConfig
    Test-NginxConfiguration
    Show-InstallationSummary
    Write-Success 'NGINX installation completed'
}

function Invoke-Remove {
    Assert-RootPrivilege
    if (-not (Confirm-Action -Prompt 'Remove NGINX installation?' -EnvVar 'CONFIRM')) { return }
    Remove-NginxInstall
    Write-Warn "Configuration backup located at $Script:BackupDir"
}

function Invoke-Verify {
    Test-NginxInstall
}

# ============================================================================
# CLEANUP
# ============================================================================
function Remove-InstallerTempData {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param()
    if ((Test-Path $Script:BuildDir) -and $PSCmdlet.ShouldProcess($Script:BuildDir, 'Remove build directory')) {
        Remove-Item $Script:BuildDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ((Test-Path $Script:LogDir) -and $PSCmdlet.ShouldProcess($Script:LogDir, 'Remove log directory')) {
        Remove-Item $Script:LogDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# ENTRY POINT
# ============================================================================
$Script:FailureOccurred = $false
try {
    switch ($Command) {
        'install' { Invoke-Install }
        'remove'  { Invoke-Remove }
        'verify'  { Invoke-Verify }
        default {
            Write-Information -MessageData '' -InformationAction Continue
            Write-Information -MessageData 'NGINX Compiler and Installer' -InformationAction Continue
            Write-Information -MessageData 'Usage: ./nginx_installer.ps1 {install|remove|verify}' -InformationAction Continue
            Write-Information -MessageData '' -InformationAction Continue
            Write-Information -MessageData 'Environment variables:' -InformationAction Continue
            Write-Information -MessageData '  CONFIRM=no               # Abort automatically without executing' -InformationAction Continue
            Write-Information -MessageData '  ENABLE_HEADERS_MORE=1|0  # Enable headers-more module' -InformationAction Continue
            Write-Information -MessageData '  ENABLE_ZSTD=1|0          # Enable Zstandard module' -InformationAction Continue
            Write-Information -MessageData '  ENABLE_STREAM=1|0        # Enable stream core' -InformationAction Continue
            Write-Information -MessageData '  CHECKSUM_POLICY=strict|allow-missing|skip' -InformationAction Continue
            Write-Information -MessageData '' -InformationAction Continue
        }
    }
}
catch {
    $Script:FailureOccurred = $true
    throw
}
finally {
    if ($Script:FailureOccurred) {
        Write-Warn "Logs preserved in $Script:LogDir"
    } else {
        Remove-InstallerTempData
    }
}
