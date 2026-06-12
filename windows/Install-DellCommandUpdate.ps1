<#
.SYNOPSIS
    Installs Dell Command | Update via winget.
.DESCRIPTION
    Thin wrapper around winget for unattended installation of Dell Command |
    Update on Dell machines.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

winget install --accept-source-agreements --accept-package-agreements Dell.CommandUpdate
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to install Dell Command | Update (winget exit code $LASTEXITCODE)." -ForegroundColor Red
    Exit 1
}
Write-Host "Dell Command | Update installed." -ForegroundColor Green
