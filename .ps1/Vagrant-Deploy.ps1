<#
    Interactive Vagrant deploy script.
    - Prompts user for hypervisor/provider
    - Prompts user for a predefined image (Windows 11 Pro, Windows Server 2025 Datacenter, Fedora Workstation 42, Ubuntu 25.10)
    - Initializes a Vagrant project and brings up the VM with the selected provider.

    Requirements:
    - Vagrant installed; provider must be installed (VirtualBox/Hyper-V/VMware plugin & utility).
#>

[CmdletBinding()]
param(
    [string]$ProjectPath,
    [switch]$ForceRecreate,
    [switch]$NoUp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-Info { param([Parameter(Mandatory=$true)][string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Err  { param([Parameter(Mandatory=$true)][string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }
function Test-Command { param([Parameter(Mandatory=$true)][string]$Name) return $null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue) }

# Providers list
$providers = @(
    @{ Name = 'VMware (vmware_desktop)'; Value = 'vmware_desktop' },
    @{ Name = 'VirtualBox (virtualbox)'; Value = 'virtualbox' },
    @{ Name = 'Hyper-V (hyperv)'; Value = 'hyperv' }
)

# Predefined images map
$images = @(
    @{ Name = 'Windows 11 Pro';            Box = 'gusztavvargadr/windows-11' ;     ProviderHint = 'hyperv' },
    @{ Name = 'Windows Server 2025 DC';    Box = 'gusztavvargadr/windows-server-2025'; ProviderHint = 'hyperv' },
    @{ Name = 'Fedora Workstation 42';     Box = 'fedora/official-f39' ;        ProviderHint = 'virtualbox' },
    @{ Name = 'Ubuntu 25.10';              Box = 'ubuntu/kinetic64' ;           ProviderHint = 'virtualbox' }
)

# Prompt helper
function Select-FromList {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)][object[]]$Options,
        [string]$DisplayKey = 'Name'
    )
    Write-Host "`n$Title" -ForegroundColor Yellow
    for ($i=0; $i -lt $Options.Count; $i++) {
        $label = $Options[$i].$DisplayKey
        Write-Host ("  {0}) {1}" -f ($i+1), $label)
    }
    do {
        $sel = Read-Host 'Enter choice number'
    } while (-not ($sel -as [int]) -or [int]$sel -lt 1 -or [int]$sel -gt $Options.Count)
    return $Options[[int]$sel - 1]
}

# Validate tooling
if (-not (Test-Command 'vagrant')) { throw 'Vagrant not found on PATH. Please install Vagrant first.' }

# Pick provider
$providerChoice = Select-FromList -Title 'Select hypervisor / provider:' -Options $providers
$provider = $providerChoice.Value

# Pick image
$imageChoice = Select-FromList -Title 'Select base image:' -Options $images
$box = $imageChoice.Box

# Determine project path
if (-not $ProjectPath) {
    $safeProvider = $provider -replace '[^a-zA-Z0-9_-]','-'
    $safeBox = ($imageChoice.Name -replace '\s+','-').ToLower()
    $ProjectPath = Join-Path $HOME ("vagrant-" + $safeProvider + '-' + $safeBox)
}
Write-Info "Project path: $ProjectPath"
$dir = (New-Item -ItemType Directory -Path $ProjectPath -Force).FullName
$dir = Resolve-Path -LiteralPath $dir

# Initialize Vagrant project
Push-Location $dir
try {
    if ($ForceRecreate -and (Test-Path -LiteralPath (Join-Path $dir 'Vagrantfile'))) {
        Remove-Item -LiteralPath (Join-Path $dir 'Vagrantfile') -Force
    }

    if (-not (Test-Path -LiteralPath (Join-Path $dir 'Vagrantfile'))) {
        Write-Info "Running 'vagrant init'"
        vagrant init | Out-Null
    }

    # Add the box for the chosen provider
    Write-Info "Adding box $box for provider $provider (if not already present)"
    vagrant box add $box --provider $provider --force | Out-Host

    # Ensure Vagrantfile has the chosen box and a minimal provider-specific tweak if needed
    $vf = Join-Path $dir 'Vagrantfile'
    $content = Get-Content $vf -Raw
    if ($content -match 'config\.vm\.box\s*=') {
        $replacement = 'config.vm.box = "' + $box + '"'
        $content = $content -replace 'config\.vm\.box\s*=\s*".*?"', $replacement
    } else {
        $content += "`nconfig.vm.box = `"$box`"`n"
    }

    # For Hyper-V, ensure basic provider block exists (optional)
    if ($provider -eq 'hyperv' -and ($content -notmatch 'config\.vm\.provider\s+:hyperv')) {
        $content += "`nconfig.vm.provider :hyperv do |hv|\n  hv.vm_integration_services = { guest_service_interface: true }\nend\n"
    }

    Set-Content -Path $vf -Value $content

    if (-not $NoUp) {
        Write-Info "Bringing the VM up with provider $provider"
        vagrant up --provider $provider | Out-Host
        vagrant status | Out-Host
    } else {
        Write-Info 'Skipping vagrant up due to -NoUp.'
    }
}
finally {
    Pop-Location
}

Write-Host "`nDone." -ForegroundColor Green

