# Install-VagrantVMware.ps1
# Automates the installation of VMware Workstation with Vagrant on Windows.
# Credits: https://github.com/1eedaegon
# Run as Administrator.

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Restarting the script with administrator rights..." -ForegroundColor Yellow
    Start-Process -FilePath "PowerShell" `
                  -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" `
                  -Verb RunAs
    Exit
}
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# --- Configuration ---
$WorkDir = "$env:USERPROFILE\vagrant-vm"
$BoxName = "hashicorp/bionic64"

# --- Helper ---
function Install-WingetPackage {
    param([string]$PackageId, [string]$DisplayName)
    Write-Host "Installing $DisplayName..." -ForegroundColor Cyan
    winget install --id $PackageId --silent --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to install $DisplayName. Please install it manually." -ForegroundColor Red
        Exit 1
    }
    Write-Host "$DisplayName installed." -ForegroundColor Green
}

# 1. Install Go
Install-WingetPackage -PackageId "GoLang.Go" -DisplayName "Go"

# 2. Install VMware Workstation Player
Install-WingetPackage -PackageId "VMware.WorkstationPlayer" -DisplayName "VMware Workstation Player"

# 3. Install Vagrant
Install-WingetPackage -PackageId "Hashicorp.Vagrant" -DisplayName "Vagrant"

# 4. Install VMware Vagrant Utility
Write-Host "Downloading Vagrant VMware Utility..." -ForegroundColor Cyan
$UtilityUrl  = "https://releases.hashicorp.com/vagrant-vmware-utility/1.0.22/vagrant-vmware-utility_1.0.22_windows_amd64.msi"
$UtilityPath = "$env:TEMP\vagrant-vmware-utility.msi"
Invoke-WebRequest -Uri $UtilityUrl -OutFile $UtilityPath
Write-Host "Installing Vagrant VMware Utility..." -ForegroundColor Cyan
Start-Process msiexec.exe -ArgumentList "/i `"$UtilityPath`" /quiet /norestart" -Wait
Write-Host "Vagrant VMware Utility installed." -ForegroundColor Green

# Refresh PATH so vagrant is available without reopening the shell
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("Path", "User")

# 5. Install vagrant-vmware-desktop plugin
Write-Host "Installing vagrant-vmware-desktop plugin..." -ForegroundColor Cyan
vagrant plugin install vagrant-vmware-desktop

# 6. Update vagrant-vmware-desktop plugin
Write-Host "Updating vagrant-vmware-desktop plugin..." -ForegroundColor Cyan
vagrant plugin update vagrant-vmware-desktop

# 7. Start the Vagrant VMware utility service
Write-Host "Starting vagrant-vmware-utility service..." -ForegroundColor Cyan
net.exe start vagrant-vmware-utility

# 8. Create working directory and initialise Vagrant
Write-Host "Creating working directory: $WorkDir" -ForegroundColor Cyan
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
Set-Location $WorkDir
vagrant init

# 9. Add the VMware base box
Write-Host "Adding Vagrant box '$BoxName' for vmware_desktop..." -ForegroundColor Cyan
vagrant box add $BoxName --provider vmware_desktop

# 10. Update Vagrantfile to use the box
Write-Host "Updating Vagrantfile..." -ForegroundColor Cyan
$VagrantfilePath = Join-Path $WorkDir "Vagrantfile"
(Get-Content $VagrantfilePath) -replace 'config\.vm\.box = "base"', "config.vm.box = `"$BoxName`"" |
    Set-Content $VagrantfilePath

# 11. Start the VM
Write-Host "Starting VM with vmware_desktop provider..." -ForegroundColor Cyan
vagrant up --provider vmware_desktop

# 12. Check VM status
Write-Host "VM status:" -ForegroundColor Cyan
vagrant status

Write-Host "`nSetup complete! Connect to the VM with: vagrant ssh" -ForegroundColor Green
