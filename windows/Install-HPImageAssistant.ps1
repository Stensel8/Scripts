<#
.SYNOPSIS
    Installs HP Image Assistant via winget.
.DESCRIPTION
    Thin wrapper around winget for unattended installation of HP Image
    Assistant (HPIA) on HP machines.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

winget install --accept-source-agreements --accept-package-agreements HP.ImageAssistant
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to install HP Image Assistant (winget exit code $LASTEXITCODE)." -ForegroundColor Red
    Exit 1
}
Write-Host "HP Image Assistant installed." -ForegroundColor Green
