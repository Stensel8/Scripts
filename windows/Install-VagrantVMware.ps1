# Install-VagrantVMware.ps1
# Automates the installation of VMware Workstation with Vagrant on Windows.
# Note: vagrant-vmware-utility is bundled with Vagrant since v2.x
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
$VAGRANT_VERSION = "2.4.9"

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

# 3. Install Vagrant (includes vagrant-vmware-utility since v2.x)
Write-Host "Installing Vagrant $VAGRANT_VERSION..." -ForegroundColor Cyan
winget install --id Hashicorp.Vagrant --version $VAGRANT_VERSION --silent --accept-source-agreements --accept-package-agreements
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to install Vagrant. Please install it manually." -ForegroundColor Red
    Exit 1
}
Write-Host "Vagrant installed." -ForegroundColor Green

# Refresh PATH so vagrant is available without reopening the shell
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("Path", "User")

# 4. Install vagrant-vmware-desktop plugin
Write-Host "Installing vagrant-vmware-desktop plugin..." -ForegroundColor Cyan
vagrant plugin install vagrant-vmware-desktop

# 5. Update vagrant-vmware-desktop plugin
Write-Host "Updating vagrant-vmware-desktop plugin..." -ForegroundColor Cyan
vagrant plugin update vagrant-vmware-desktop

# 6. Create working directory and initialise Vagrant
Write-Host "Creating working directory: $WorkDir" -ForegroundColor Cyan
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
Set-Location $WorkDir
vagrant init

# 7. Add the VMware base box
Write-Host "Adding Vagrant box '$BoxName' for vmware_desktop..." -ForegroundColor Cyan
vagrant box add $BoxName --provider vmware_desktop

# 8. Update Vagrantfile to use the box
Write-Host "Updating Vagrantfile..." -ForegroundColor Cyan
$VagrantfilePath = Join-Path $WorkDir "Vagrantfile"
(Get-Content $VagrantfilePath) -replace 'config\.vm\.box = "base"', "config.vm.box = `"$BoxName`"" |
    Set-Content $VagrantfilePath

# 9. Start the VM
Write-Host "Starting VM with vmware_desktop provider..." -ForegroundColor Cyan
vagrant up --provider vmware_desktop

# 10. Check VM status
Write-Host "VM status:" -ForegroundColor Cyan
vagrant status

Write-Host "`nSetup complete! Connect to the VM with: vagrant ssh" -ForegroundColor Green
