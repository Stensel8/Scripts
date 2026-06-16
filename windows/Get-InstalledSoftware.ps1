<#
.SYNOPSIS
    Lists installed software from the Windows registry.
.DESCRIPTION
    Reads the Uninstall registry keys (machine-wide 64-bit, machine-wide
    32-bit and current user) and prints a table of installed applications.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$registryPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$installedApps = foreach ($path in $registryPaths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
}

$installedApps | Sort-Object DisplayName | Format-Table -AutoSize
