$registryPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$installedApps = foreach ($path in $registryPaths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } |
    Select-Object @{Name="Naam";Expression={$_.DisplayName}},
                  @{Name="Versie";Expression={$_.DisplayVersion}},
                  @{Name="Publisher";Expression={$_.Publisher}},
                  @{Name="InstallatieDatum";Expression={$_.InstallDate}}
}

$installedApps | Sort-Object Naam | Format-Table -AutoSize
