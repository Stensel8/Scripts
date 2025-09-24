#!/usr/bin/env pwsh
<#
.SYNOPSIS
  TLS & HTTP feature tester using static cURL binary.
.DESCRIPTION
  Downloads a self-contained curl if needed, then tests compression, TLS versions,
  HTTP versions, QUIC, and HSTS for given domains. Requires PowerShell 7.5.0 or higher.
.PARAMETER Domain
  The domain to test (can be provided interactively)
.PARAMETER TestType
  Test to run: Compression, TLS, HTTP, QUIC, HSTS, or All
.PARAMETER Force
  Force re-download of curl binary
.PARAMETER PreferMusl
  On Linux, prefer musl version over glibc (useful for compatibility issues)
.PARAMETER Timeout
  Connection timeout in seconds (default: 15)
.PARAMETER MaxTime
  Maximum time for the whole operation in seconds (default: 30)
.PARAMETER Quiet
  Suppress detailed output, show only results
.PARAMETER WhatIf
  Show what actions would be performed without executing them
.PARAMETER Verbose
  Enable verbose output for debugging
.EXAMPLE
  .\TLS-checker.ps1 -Domain "example.com" -TestType "All"
.EXAMPLE
  .\TLS-checker.ps1 -Domain "example.com" -TestType "TLS" -Quiet
.EXAMPLE
  .\TLS-checker.ps1 -Domain "example.com" -TestType "All" -WhatIf
.EXAMPLE
  .\TLS-checker.ps1 -Domain "example.com" -TestType "All" -Verbose
.EXAMPLE
  .\TLS-checker.ps1 -Domain "example.com" -TestType "All" -PreferMusl
.NOTES
  Requires: PowerShell 7.5.0+
  
  If you experience issues on Linux, try running with -Verbose to see detailed debugging information.
  This will show platform detection, curl binary selection, and connection attempts.
  
  Example for debugging: .\TLS-checker.ps1 -Domain "example.com" -TestType "All" -Verbose
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Domain,
    [ValidateSet('Compression', 'TLS', 'HTTP', 'QUIC', 'HSTS', 'All')]
    [string]$TestType,
    [switch]$Force,
    [switch]$PreferMusl,
    [int]$Timeout = 15,
    [int]$MaxTime = 30,
    [switch]$Quiet
)

# Version and prerequisites check
#Requires -Version 7.5

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# Configuration
$Config = @{
    Version = '8.14.1'
    BaseUrl = "https://github.com/stunnel/static-curl/releases/download/8.14.1"
    Checksums = @{
        'linux-x86_64-musl'   = '0b4622d9df4fd282b5a2d222e4e0146fc409053ee15ee1979784f6c8a56cf573'
        'linux-x86_64-glibc'  = 'cac45d633e947cc2f17f7b69c179ca366fcd5038c4c0ff0bc3cd62a5f25b16c9'
        'linux-aarch64-musl'  = 'e0fecb5ecaba101b4b560f1035835770e7d1c151416ee84e18c813ba32b9d1dd'
        'linux-aarch64-glibc' = 'a51fcfa5de2aca0c49ac676b9cf93a84b077fe7239da0950995f35cf30f955b4'
        'macos-x86_64'        = 'dbf7e91be8278c1ce279da107089b4d9bc8e2c10b73ce3cd3570e3fae04bfd26'
        'macos-arm64'         = 'c6d7dbcb3d85ada79b0fd1bfc18a2d0d2a5076bc4a3ef9b7f4a6ad7e75def00b'
        'windows-x86_64'      = '0558c9e40fc01f17ed1df2490247e5c5589d0f76913a4c1cdd88109bf5141069'
        'windows-aarch64'     = '10802983da0ea33db16a77efd218454da61673f3c02620f271f03bbdd251d5d9'
    }
    TlsVersions = @('1.0', '1.1', '1.2', '1.3')
    HttpVersions = @('1.1', '2', '3')
    CompressionTypes = @('gzip', 'br', 'zstd')
}

# Global variables
$Script:CurlPath = $null
$Script:DevNull = $IsWindows ? 'NUL' : '/dev/null'

# Utility functions
function Write-Log {
    param([string]$Message, [ValidateSet('Info', 'Warning', 'Error', 'Success')][string]$Level = 'Info')
    if ($Quiet -and $Level -eq 'Info') { return }
    $colors = @{'Info'='Cyan'; 'Warning'='Yellow'; 'Error'='Red'; 'Success'='Green'}
    Write-Host $Message -ForegroundColor $colors[$Level]
}

function Get-PlatformKey {
    param([switch]$PreferMusl)
    
    $os = $IsLinux ? 'linux' : $IsMacOS ? 'macos' : 'windows'
    $arch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64' ? 'aarch64' : 'x86_64'
    
    if ($IsMacOS -and $arch -eq 'aarch64') { $arch = 'arm64' }
    
    if ($os -eq 'linux') {
        if ($PreferMusl) { return "${os}-${arch}-musl" }
        
        $libc = 'glibc'
        try {
            $lddOutput = & ldd --version 2>&1 | Out-String
            if ($lddOutput -match "musl" -or 
                (Test-Path '/lib/libc.musl-*' -ErrorAction SilentlyContinue) -or 
                ((Test-Path '/proc/version' -ErrorAction SilentlyContinue) -and 
                 (Get-Content '/proc/version' -ErrorAction SilentlyContinue | Out-String) -match 'Alpine')) {
                $libc = 'musl'
            }
        } catch { }
        
        return "${os}-${arch}-${libc}"
    }
    return "${os}-${arch}"
}

function Install-Curl {
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$PreferMusl)
    
    $platformKey = Get-PlatformKey -PreferMusl:$PreferMusl
    
    if (-not $Config.Checksums.ContainsKey($platformKey)) { 
        throw "Unsupported platform: $platformKey. Available: $($Config.Checksums.Keys -join ', ')" 
    }
    
    $archiveName = "curl-$platformKey-$($Config.Version).tar.xz"
    $installDir = Join-Path $HOME "staticcurl-$($Config.Version)$(if ($PreferMusl) { '-musl' })"
    $executableName = $IsWindows ? 'curl.exe' : 'curl'
    $curlPath = Join-Path $installDir $executableName

    if ($PSCmdlet.ShouldProcess($curlPath, "Install curl binary")) {
        if ((Test-Path $curlPath) -and -not $Force) {
            Write-Log "Using existing curl: $curlPath" -Level Success
            return $curlPath
        }

        Write-Log "Installing curl binary for $platformKey..." -Level Info
        $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "staticcurl-$(Get-Random)"
        New-Item -ItemType Directory -Path $tempDir, $installDir -Force | Out-Null

        try {
            $archivePath = Join-Path $tempDir $archiveName
            $downloadUrl = "$($Config.BaseUrl)/$archiveName"
            
            Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath -UseBasicParsing
            
            # Quick validation
            $fileContent = Get-Content $archivePath -TotalCount 10 -Encoding UTF8 | Out-String
            if ($fileContent -match '<html|<!DOCTYPE') {
                throw "Download failed - received HTML error page"
            }
            
            # Verify checksum
            if ((Get-FileHash $archivePath -Algorithm SHA256).Hash.ToLower() -ne $Config.Checksums[$platformKey]) { 
                throw "Checksum mismatch" 
            }
            
            # Extract using tar
            $extractArgs = @('-xf', $archivePath, '-C', $installDir)
            if ($IsWindows) {
                $result = Start-Process -FilePath 'tar' -ArgumentList $extractArgs -Wait -PassThru -NoNewWindow
                if ($result.ExitCode -ne 0) { throw "Extraction failed" }
            } else {
                & tar @extractArgs
                if ($LASTEXITCODE -ne 0) { throw "Extraction failed" }
                & chmod +x $curlPath
            }

            if (-not (Test-Path $curlPath)) { throw "curl not found after extraction" }
            
            # Test binary
            $testResult = & $curlPath --version 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "curl binary test failed: $($testResult -join "`n")"
            }
            
            Write-Log "curl ready: $curlPath" -Level Success
            return $curlPath
            
        } finally {
            Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-Curl {
    param([string[]]$Arguments)
    
    $baseArgs = @('-s', '-S', '-L', '--connect-timeout', $Timeout, '--max-time', $MaxTime) + $Arguments
    
    try {
        $output = & $Script:CurlPath @baseArgs 2>&1
        return @{ 
            Success = ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 23)
            Output = $output -join "`n"
            ExitCode = $LASTEXITCODE
        }
    } catch {
        return @{ Success = $false; Output = $_.Exception.Message; ExitCode = -1 }
    }
}

function Test-Site {
    param([string]$Domain)
    
    $httpsResult = Invoke-Curl @('-w', '%{http_code}', '-o', $Script:DevNull, "https://$Domain/")
    if ($httpsResult.Success -and $httpsResult.Output -match '^[23]\d{2}$') {
        return @{ Protocol = 'https'; Working = $true }
    }
    
    $httpResult = Invoke-Curl @('-w', '%{http_code}', '-o', $Script:DevNull, "http://$Domain/")
    return @{ Protocol = 'http'; Working = ($httpResult.Success -and $httpResult.Output -match '^[23]\d{2}$') }
}

function Test-Feature {
    param([string]$Name, [string[]]$CurlArgs)
    
    $result = Invoke-Curl $CurlArgs
    $success = $result.Success -and ($result.Output -match '^[23]\d{2}$' -or $result.Output -match '\b[23]\d{2}\b')
    
    $status = $success ? 'SUPPORTED' : 'NOT SUPPORTED'
    $color = $success ? 'Success' : 'Warning'
    Write-Log "$Name : $status" -Level $color
    
    return $success
}

function Test-Compression {
    param([string]$Domain)
    
    Write-Log "Testing compression support for: $Domain"
    $siteTest = Test-Site $Domain
    if (-not $siteTest.Working) {
        Write-Log "Site not accessible, skipping compression test" -Level Warning
        return
    }

    foreach ($compression in $Config.CompressionTypes) {
        $curlArgs = @('-H', "Accept-Encoding: $compression", '-w', '%{http_code}', '-o', $Script:DevNull, "$($siteTest.Protocol)://$Domain/")
        Test-Feature $compression.ToUpper() $curlArgs | Out-Null
    }
}

function Test-TLS {
    param([string]$Domain)
    
    Write-Log "Testing TLS versions for: $Domain"
    $siteTest = Test-Site $Domain
    if ($siteTest.Protocol -ne 'https') {
        Write-Log "HTTPS not available, skipping TLS test" -Level Warning
        return
    }

    foreach ($version in $Config.TlsVersions) {
        $curlArgs = @("--tlsv$version", '--tls-max', $version, '-w', '%{http_code}', '-o', $Script:DevNull, "https://$Domain/")
        Test-Feature "TLS $version" $curlArgs | Out-Null
    }
}

function Test-HTTP {
    param([string]$Domain)
    
    Write-Log "Testing HTTP versions for: $Domain"
    $siteTest = Test-Site $Domain
    if (-not $siteTest.Working) {
        Write-Log "Site not accessible, skipping HTTP test" -Level Warning
        return
    }

    foreach ($version in $Config.HttpVersions) {
        $httpArg = $version -eq '1.1' ? '--http1.1' : $version -eq '2' ? '--http2' : '--http3'
        $curlArgs = @($httpArg, '-w', '%{http_code}', '-o', $Script:DevNull, "$($siteTest.Protocol)://$Domain/")
        Test-Feature "HTTP $version" $curlArgs | Out-Null
    }
}

function Test-QUIC {
    param([string]$Domain)
    
    Write-Log "Testing QUIC support for: $Domain"
    $siteTest = Test-Site $Domain
    if ($siteTest.Protocol -ne 'https') {
        Write-Log "HTTPS not available, skipping QUIC test" -Level Warning
        return
    }

    $curlArgs = @('--http3', '-w', '%{http_code}', '-o', $Script:DevNull, "https://$Domain/")
    Test-Feature "QUIC" $curlArgs | Out-Null
}

function Test-HSTS {
    param([string]$Domain)
    
    Write-Log "Testing HSTS support for: $Domain"
    $siteTest = Test-Site $Domain
    if ($siteTest.Protocol -ne 'https') {
        Write-Log "HTTPS not available, skipping HSTS test" -Level Warning
        return
    }

    $curlArgs = @('-I', "https://$Domain/")
    $result = Invoke-Curl $curlArgs
    
    if ($result.Success -and $result.Output -match "Strict-Transport-Security:") {
        Write-Log "HSTS : SUPPORTED" -Level Success
    } else {
        Write-Log "HSTS : NOT SUPPORTED" -Level Warning
    }
}

function Test-All {
    param([string]$Domain)
    
    Write-Log "Starting full test for: $Domain"
    Write-Host ("=" * 50)
    
    Test-Compression $Domain
    Write-Host ("-" * 30)
    Test-TLS $Domain
    Write-Host ("-" * 30)
    Test-HTTP $Domain
    Write-Host ("-" * 30)
    Test-QUIC $Domain
    Write-Host ("-" * 30)
    Test-HSTS $Domain
    
    Write-Host ("=" * 50)
    Write-Log "Test completed for: $Domain" -Level Success
}

function Get-ValidDomain {
    do {
        $inputDomain = Read-Host 'Enter domain to test (e.g., example.com)'
        if ($inputDomain -and $inputDomain -match '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
            return $inputDomain
        }
        Write-Log 'Invalid domain name. Please try again.' -Level Error
    } while ($true)
}

function Show-Menu {
    param([string]$Domain)
    
    # Use ANSI escape sequences for better cross-platform compatibility
    if ($IsLinux -or $IsMacOS) {
        # Clear screen and move cursor to top-left
        Write-Host "`e[2J`e[H" -NoNewline
    } else {
        Clear-Host
    }
    
    Write-Host '=== TLS & HTTP Tester ===' -ForegroundColor Magenta
    Write-Host "Domain: $Domain" -ForegroundColor Cyan
    Write-Host ""
    Write-Host '1) Compression Test'
    Write-Host '2) TLS Version Test'
    Write-Host '3) HTTP Version Test'
    Write-Host '4) QUIC Test'
    Write-Host '5) HSTS Test'
    Write-Host '6) All Tests'
    Write-Host 'S) Change domain'
    Write-Host 'Q) Quit'
    Write-Host ""
}

# Main execution
try {
    # Initialize curl with improved Linux feedback
    if ($IsLinux) {
        $platformKey = Get-PlatformKey -PreferMusl:$PreferMusl
        $isMusl = $platformKey -match 'musl'
        Write-Log "Trying $(if ($isMusl) { 'musl' } else { 'glibc' }) build..." -Level Info
    }
    
    $Script:CurlPath = Install-Curl -PreferMusl:$PreferMusl
    
    # Test connectivity with fallback mechanism
    $connectivityTest = Invoke-Curl @('-w', '%{http_code}', '-o', $Script:DevNull, 'https://httpbin.org/status/200')
    
    if (-not $connectivityTest.Success) {
        if ($IsLinux -and $connectivityTest.ExitCode -eq 136 -and -not $PreferMusl) {
            Write-Log "FAILED" -Level Error
            Write-Log "Falling back to musl build..." -Level Warning
            
            try {
                $Script:CurlPath = Install-Curl -PreferMusl
                $connectivityTest = Invoke-Curl @('-w', '%{http_code}', '-o', $Script:DevNull, 'https://httpbin.org/status/200')
                
                if ($connectivityTest.Success) {
                    Write-Log "SUCCESS" -Level Success
                } else {
                    Write-Log "Musl build also failed (Exit code: $($connectivityTest.ExitCode))" -Level Warning
                }
            } catch {
                Write-Log "Failed to try musl version: $_" -Level Error
            }
        } else {
            Write-Log "Connectivity test failed (Exit code: $($connectivityTest.ExitCode))" -Level Warning
        }
    } elseif ($IsLinux) {
        Write-Log "SUCCESS" -Level Success
    }
    
    # Non-interactive mode
    if ($Domain -and $TestType) {
        switch ($TestType) {
            'Compression' { Test-Compression $Domain }
            'TLS'         { Test-TLS $Domain         }
            'HTTP'        { Test-HTTP $Domain        }
            'QUIC'        { Test-QUIC $Domain        }
            'HSTS'        { Test-HSTS $Domain        }
            'All'         { Test-All $Domain         }
        }
        return
    }
    
    # Interactive mode
    $currentDomain = if ($Domain) { $Domain } else { Get-ValidDomain }
    
    :MainLoop while ($true) {
        Show-Menu $currentDomain
        $choice = (Read-Host 'Choose option').ToUpper()
        
        switch ($choice) {
            '1' { Test-Compression $currentDomain; Read-Host 'Press Enter to continue' | Out-Null }
            '2' { Test-TLS $currentDomain; Read-Host 'Press Enter to continue' | Out-Null }
            '3' { Test-HTTP $currentDomain; Read-Host 'Press Enter to continue' | Out-Null }
            '4' { Test-QUIC $currentDomain; Read-Host 'Press Enter to continue' | Out-Null }
            '5' { Test-HSTS $currentDomain; Read-Host 'Press Enter to continue' | Out-Null }
            '6' { Test-All $currentDomain; Read-Host 'Press Enter to continue' | Out-Null }
            'S' { $currentDomain = Get-ValidDomain }
            'Q' { Write-Log "Goodbye!" -Level Success; break MainLoop }
            default { Write-Log 'Invalid choice' -Level Error; Start-Sleep 1 }
        }
    }
    
} catch {
    Write-Error "Error: $_"
    exit 1
}
