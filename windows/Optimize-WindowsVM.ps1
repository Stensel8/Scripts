<#
.SYNOPSIS
    Disables unnecessary services and features for Windows VMs.
.DESCRIPTION
    Optimizes a Windows VM by disabling Windows Update, Windows Search,
    SysMain, diagnostics tracking, error reporting, OneDrive, hibernation
    and Fast Startup, and sets the High Performance power plan.

    Tested on Windows 11 and Windows Server 2025. It may work on other
    versions, but some services may differ.
.NOTES
    Run as Administrator (the script self-elevates if needed).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Self-elevate when not running as Administrator
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Restarting the script with administrator rights..." -ForegroundColor Yellow
    # Restart PowerShell as admin with the same parameters
    Start-Process -FilePath "PowerShell" `
                  -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" `
                  -Verb RunAs
    Exit
}
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# Disables a service if it exists; absent services (Server vs 11) are skipped.
function Disable-WindowsService {
    param([string]$Name, [string]$DisplayName)
    Write-Host "Disabling $DisplayName..."
    Stop-Service $Name -Force -ErrorAction SilentlyContinue
    Set-Service $Name -StartupType Disabled -ErrorAction SilentlyContinue
}

Disable-WindowsService -Name wuauserv -DisplayName "Windows Update"
Disable-WindowsService -Name WSearch  -DisplayName "Windows Search"
Disable-WindowsService -Name SysMain  -DisplayName "SysMain (Superfetch)"
Disable-WindowsService -Name DiagTrack -DisplayName "Diagnostics Tracking"
Disable-WindowsService -Name WerSvc   -DisplayName "Windows Error Reporting"

# Disable OneDrive (if present)
Write-Host "Disabling OneDrive (if installed)..."
$onedrive = Get-Process OneDrive -ErrorAction SilentlyContinue
if ($onedrive) {
    Stop-Process -Name OneDrive -Force
    $onedrivePath = "$env:SystemRoot\System32\OneDriveSetup.exe"
    if (Test-Path $onedrivePath) {
        Start-Process $onedrivePath "/uninstall" -NoNewWindow -Wait
    }
}

# Set power plan to high performance
Write-Host "Setting power plan to High Performance..."
powercfg -setactive SCHEME_MIN

# Disable hibernation
Write-Host "Disabling hibernation..."
powercfg -h off

# Disable Fast Startup
Write-Host "Disabling Fast Startup..."
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
Set-ItemProperty -Path $regPath -Name HiberbootEnabled -Value 0

Write-Host "VM optimization is done!" -ForegroundColor Green
