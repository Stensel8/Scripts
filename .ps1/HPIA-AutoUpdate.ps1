# #Requires -RunAsAdministrator
# <#
# .SYNOPSIS
# HP Device Automated Update Tool - Single Script Solution

# .DESCRIPTION
# Automatically downloads and installs ALL available HP updates without prompts:
# - BIOS updates
# - Driver updates  
# - Software updates
# - Firmware updates
# - Accessories updates

# Just run it and let it work. No clicking, no prompts, just updates.

# .EXAMPLE
# .\HPIA-autoUpdate.ps1

# .NOTES
# - Requires Administrator privileges
# - Works on HP ProBooks, ZBooks, EliteBooks, etc.
# - Automatically reboots if required
# #>

# [CmdletBinding()]
# param()

# # Set console title and clear screen
# $Host.UI.RawUI.WindowTitle = "HP Device Auto-Update Tool"
# Clear-Host

# Write-Host "========================================" -ForegroundColor Cyan
# Write-Host "HP Device Automated Update Tool" -ForegroundColor Cyan
# Write-Host "Installing ALL available updates..." -ForegroundColor Cyan
# Write-Host "========================================" -ForegroundColor Cyan

# #region Functions

# ### Write-CMTraceLog
# Function Write-CMTraceLog {
#     [CmdletBinding()]
#     Param (
#         [Parameter(Mandatory=$false)]
#         $Message,
#         [Parameter(Mandatory=$false)]
#         $ErrorMessage,
#         [Parameter(Mandatory=$false)]
#         $Component = "Script",
#         [Parameter(Mandatory=$false)]
#         [int]$Type,
#         [Parameter(Mandatory=$false)]
#         $LogFile = "$($env:ProgramData)\logs\HPIA-autoUpdate.log"
#     )
#     <#
#     Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
#     #>
#     $Time = Get-Date -Format "HH:mm:ss.ffffff"
#     $Date = Get-Date -Format "MM-dd-yyyy"
#     if ($null -ne $ErrorMessage) {$Type = 3}
#     if ($Component -eq $null) {$Component = " "}
#     if ($null -eq $Type) {$Type = 1}
#     $LogMessage = "<![LOG[$Message $ErrorMessage" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
#     $LogMessage.Replace("`0","") | Out-File -Append -Encoding UTF8 -FilePath $LogFile
# }

# #### Get-HPIALatestVersion
# Function Get-HPIALatestVersion{
#     $script:TempWorkFolder = "$env:windir\Temp\HPIA"
#     $ProgressPreference = 'SilentlyContinue' # to speed up web requests
#     $HPIACABUrl = "https://hpia.hpcloud.hp.com/HPIAMsg.cab"
#     $HPIACABUrlFallback = "https://ftp.hp.com/pub/caps-softpaq/cmit/imagepal/HPIAMsg.cab"
#     try {
#         [void][System.IO.Directory]::CreateDirectory($TempWorkFolder)
#     }
#     catch {throw}
#     $OutFile = "$TempWorkFolder\HPIAMsg.cab"
    
#     try {Invoke-WebRequest -Uri $HPIACABUrl -UseBasicParsing -OutFile $OutFile}
#     catch {}
#     if (!(test-path $OutFile)){
#         try {Invoke-WebRequest -Uri $HPIACABUrlFallback -UseBasicParsing -OutFile $OutFile}
#         catch {}
#     }
#     if (test-path $OutFile){
#         if(test-path "$env:windir\System32\expand.exe"){
#             try { cmd.exe /c "C:\Windows\System32\expand.exe -F:* $OutFile $TempWorkFolder\HPIAMsg.xml" | Out-Null}
#             catch {}
#         }
#         if (Test-Path -Path "$TempWorkFolder\HPIAMsg.xml"){
#             [XML]$HPIAXML = Get-Content -Path "$TempWorkFolder\HPIAMsg.xml"
#             $HPIADownloadURL = $HPIAXML.ImagePal.HPIALatest.SoftpaqURL
#             $HPIAVersion = $HPIAXML.ImagePal.HPIALatest.Version
#             $HPIAFileName = $HPIADownloadURL.Split('/')[-1]
#         }
#     }

#     else { #Falling back to Static Web Page Scrapping if Cab File wasn't available... highly unlikely
#         $HPIAWebUrl = "https://ftp.hp.com/pub/caps-softpaq/cmit/HPIA.html" # Static web page of the HP Image Assistant
#         try {$HTML = Invoke-WebRequest -Uri $HPIAWebUrl -ErrorAction Stop }
#         catch {Write-Output "Failed to download the HPIA web page. $($_.Exception.Message)" ;throw}
#         $HPIADownloadURL = ($HTML.Links | Where-Object {$_.href -match "hp-hpia-"}).href
#         $HPIAFileName = $HPIADownloadURL.Split('/')[-1]
#         $HPIAVersion = ($HPIAFileName.Split("-") | Select-Object -Last 1).replace(".exe","")
#     }
#     $Return = @(
#     @{HPIAVersion = "$($HPIAVersion)"; HPIADownloadURL = $HPIADownloadURL ; HPIAFileName = $HPIAFileName}
#     )
#     return $Return
# } 

# Function Install-HPIA{
#     [CmdletBinding()]
#         Param (
#             [Parameter(Mandatory=$false)]
#             $HPIAInstallPath = "$env:ProgramFiles\HP\HPIA\bin"
#             )
#         $script:TempWorkFolder = "$env:windir\Temp\HPIA"
#         $ProgressPreference = 'SilentlyContinue' # to speed up web requests
#         $HPIACABUrl = "https://hpia.hpcloud.hp.com/HPIAMsg.cab"
        
#         try {
#             [void][System.IO.Directory]::CreateDirectory($HPIAInstallPath)
#             [void][System.IO.Directory]::CreateDirectory($TempWorkFolder)
#         }
#         catch {throw}
#         $OutFile = "$TempWorkFolder\HPIAMsg.cab"
#         Invoke-WebRequest -Uri $HPIACABUrl -UseBasicParsing -OutFile $OutFile
#         if(test-path "$env:windir\System32\expand.exe"){
#             try { cmd.exe /c "C:\Windows\System32\expand.exe -F:* $OutFile $TempWorkFolder\HPIAMsg.xml"}
#             catch { Write-host "Nope, don't have that."}
#         }
#         if (Test-Path -Path "$TempWorkFolder\HPIAMsg.xml"){
#             [XML]$HPIAXML = Get-Content -Path "$TempWorkFolder\HPIAMsg.xml"
#             $HPIADownloadURL = $HPIAXML.ImagePal.HPIALatest.SoftpaqURL
#             $HPIAVersion = $HPIAXML.ImagePal.HPIALatest.Version
#             $HPIAFileName = $HPIADownloadURL.Split('/')[-1]
            
#         }
#         else {
#             $HPIAWebUrl = "https://ftp.hp.com/pub/caps-softpaq/cmit/HPIA.html" # Static web page of the HP Image Assistant
#             try {$HTML = Invoke-WebRequest -Uri $HPIAWebUrl -ErrorAction Stop }
#             catch {Write-Output "Failed to download the HPIA web page. $($_.Exception.Message)" ;throw}
#             $HPIADownloadURL = ($HTML.Links | Where-Object {$_.href -match "hp-hpia-"}).href
#             $HPIAFileName = $HPIADownloadURL.Split('/')[-1]
#             $HPIAVersion = ($HPIAFileName.Split("-") | Select-Object -Last 1).replace(".exe","")
#         }
    
#         Write-Host "Downloading HPIA Version: $HPIAVersion" -ForegroundColor Green
#         Write-CMTraceLog -Message "HPIA Download URL: $HPIADownloadURL | Version: $HPIAVersion" -Component "Install-HPIA"
        
#         If (Test-Path $HPIAInstallPath\HPImageAssistant.exe){
#             $HPIA = get-item -Path $HPIAInstallPath\HPImageAssistant.exe
#             $HPIAExtractedVersion = $HPIA.VersionInfo.FileVersion
#             if ($HPIAExtractedVersion -match $HPIAVersion){
#                 Write-Host "✅ HPIA $HPIAVersion already installed" -ForegroundColor Green
#                 Write-CMTraceLog -Message "HPIA $HPIAVersion already installed" -Component "Install-HPIA"
#                 $HPIAIsCurrent = $true
#             }
#             else{$HPIAIsCurrent = $false}
#         }
#         else{$HPIAIsCurrent = $false}
        
#         #Download HPIA
#         if ($HPIAIsCurrent -eq $false){
#             Write-Host "Downloading and installing HPIA..." -ForegroundColor Yellow
#             if (!(Test-Path -Path "$TempWorkFolder\$HPIAFileName")){
#                 Invoke-WebRequest -UseBasicParsing -Uri $HPIADownloadURL -OutFile "$TempWorkFolder\$HPIAFileName"
#             }
    
#             #Extract HPIA
#             Write-Host "Extracting HPIA..." -ForegroundColor Yellow
#             try {
#                 $Process = Start-Process -FilePath $TempWorkFolder\$HPIAFileName -WorkingDirectory $HPIAInstallPath -ArgumentList '/s /f .\ /e' -NoNewWindow -PassThru -Wait -ErrorAction Stop
#                 Start-Sleep -Seconds 5
#                 $null = $Process
#                 If (Test-Path "$HPIAInstallPath\HPImageAssistant.exe"){
#                     Write-Host "✅ HPIA extraction complete" -ForegroundColor Green
#                     Write-CMTraceLog -Message "HPIA extraction complete" -Component "Install-HPIA"
#                 }
#                 Else{
#                     Write-Host "❌ HPImageAssistant not found!" -ForegroundColor Red
#                     throw
#                 }
#             }
#             catch {
#                 Write-Host "❌ Failed to extract HPIA: $($_.Exception.Message)" -ForegroundColor Red
#                 Write-CMTraceLog -Message "Failed to extract HPIA: $($_.Exception.Message)" -Component "Install-HPIA" -Type 3
#                 throw
#             }
#         }
#     }

# ## Run-HPIA
# Function Invoke-HPIA {
#     [CmdletBinding()]
#         Param (
#             [Parameter(Mandatory=$false)]
#             [ValidateSet("Analyze", "DownloadSoftPaqs")]
#             $Operation = "Analyze",
#             [Parameter(Mandatory=$false)]
#             [ValidateSet("All", "BIOS", "Drivers", "Software", "Firmware", "Accessories","BIOS,Drivers")]
#             $Category = "All",
#             [Parameter(Mandatory=$false)]
#             [ValidateSet("All", "Critical", "Recommended", "Routine")]
#             $Selection = "All",
#             [Parameter(Mandatory=$false)]
#             [ValidateSet("List", "Download", "Extract", "Install", "UpdateCVA")]
#             $Action = "List",
#             [Parameter(Mandatory=$false)]
#             $LogFolder = "$env:systemdrive\ProgramData\HP\Logs",
#             [Parameter(Mandatory=$false)]
#             $ReportsFolder = "$env:systemdrive\ProgramData\HP\HPIA",
#             [Parameter(Mandatory=$false)]
#             $HPIAInstallPath = "$env:ProgramFiles\HP\HPIA\bin",
#             [Parameter(Mandatory=$false)]
#             $ReferenceFile
#             )
#     $DateTime = Get-Date -Format "yyyyMMdd-HHmm"
#     $ReportsFolder = "$($ReportsFolder)\$($DateTime)"
#     $CMTraceLog = "$ReportsFolder\HPIA-autoUpdate.log"
#     $script:TempWorkFolder = 'C:\windows\temp\HP\HPIA\TempWorkFolder'
    
#     try{
#         [void][System.IO.Directory]::CreateDirectory($LogFolder)
#         [void][System.IO.Directory]::CreateDirectory($TempWorkFolder)
#         [void][System.IO.Directory]::CreateDirectory($ReportsFolder)
#         [void][System.IO.Directory]::CreateDirectory($HPIAInstallPath)
#     }
#     catch{
#         throw
#     }
    
#     Install-HPIA -HPIAInstallPath $HPIAInstallPath
#     if ($Action -eq "List"){$LogComp = "Scanning"}
#     else {$LogComp = "Installing"}

#     try {
#         $Arguments = "/Operation:$Operation /Category:$Category /Selection:$Selection /Action:$Action /Silent /Debug /ReportFolder:$ReportsFolder"
        
#         if ($ReferenceFile){
#             $Arguments += " /ReferenceFile:$ReferenceFile"
#         }
        
#         Write-CMTraceLog -LogFile $CMTraceLog -Message "HPIA Command: $Arguments" -Component $LogComp
#         Write-Host "Running HPIA: $Operation $Category $Action" -ForegroundColor Yellow
        
#         $Process = Start-Process -FilePath $HPIAInstallPath\HPImageAssistant.exe -WorkingDirectory $TempWorkFolder -ArgumentList $Arguments -NoNewWindow -PassThru -Wait -ErrorAction Stop
        
#         If ($Process.ExitCode -eq 0){
#             Write-CMTraceLog -LogFile $CMTraceLog -Message "HPIA completed successfully" -Component $LogComp
#             Write-Host "✅ HPIA operation completed successfully" -ForegroundColor Green
#         }
#         elseif ($Process.ExitCode -eq 256){
#             Write-CMTraceLog -LogFile $CMTraceLog -Message "Exit $($Process.ExitCode) - No recommendations found." -Component $LogComp -Type 2
#             Write-Host "ℹ️  No updates available for this system" -ForegroundColor Yellow
#         }
#         elseif ($Process.ExitCode -eq 257){
#             Write-CMTraceLog -LogFile $CMTraceLog -Message "Exit $($Process.ExitCode) - No recommendations selected." -Component $LogComp -Type 2
#             Write-Host "ℹ️  No recommendations selected for installation" -ForegroundColor Yellow
#         }
#         elseif ($Process.ExitCode -eq 3010){
#             Write-CMTraceLog -LogFile $CMTraceLog -Message "Exit $($Process.ExitCode) - HPIA Complete, requires Restart" -Component $LogComp -Type 2
#             Write-Host "🔄 Updates installed - System restart required" -ForegroundColor Yellow
#             $script:RebootRequired = $true
#         }
#         elseif ($Process.ExitCode -eq 3020){
#             Write-CMTraceLog -LogFile $CMTraceLog -Message "Exit $($Process.ExitCode) - Some installations failed." -Component $LogComp -Type 2
#             Write-Host "⚠️  Some installations failed, but updates were applied" -ForegroundColor Yellow
#         }
#         elseif ($Process.ExitCode -eq 4096){
#             Write-CMTraceLog -LogFile $CMTraceLog -Message "Exit $($Process.ExitCode) - Platform not supported!" -Component $LogComp -Type 2
#             Write-Host "❌ This HP platform is not supported by HPIA" -ForegroundColor Red
#         }
#         else{
#             Write-CMTraceLog -LogFile $CMTraceLog -Message "Exit $($Process.ExitCode) - Unexpected exit code" -Component $LogComp -Type 3
#             Write-Host "⚠️  HPIA finished with exit code: $($Process.ExitCode)" -ForegroundColor Yellow
#         }
        
#         return $Process.ExitCode
#     }
#     catch {
#         Write-CMTraceLog -LogFile $CMTraceLog -Message "HPIA execution failed: $($_.Exception.Message)" -Component $LogComp -Type 3
#         Write-Host "❌ HPIA execution failed: $($_.Exception.Message)" -ForegroundColor Red
#         throw
#     }
# }

# #endregion

# #region Main Execution

# # Initialize variables
# $script:RebootRequired = $false
# $DateTime = Get-Date -Format "yyyyMMdd-HHmm"
# $LogFolder = "$env:systemdrive\ProgramData\HP\Logs"
# $ReportsFolder = "$env:systemdrive\ProgramData\HP\HPIA\$DateTime"

# # Create directories
# try {
#     [void][System.IO.Directory]::CreateDirectory($LogFolder)
#     [void][System.IO.Directory]::CreateDirectory($ReportsFolder)
# }
# catch {
#     Write-Host "❌ Failed to create directories: $($_.Exception.Message)" -ForegroundColor Red
#     exit 1
# }

# # Check if running as Administrator
# $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# if (-not $isAdmin) {
#     Write-Host "❌ This script must be run as Administrator!" -ForegroundColor Red
#     Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
#     exit 1
# }

# # Check if this is an HP device
# try {
#     $Manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
#     $Model = (Get-WmiObject -Class Win32_ComputerSystem).Model
    
#     if ($Manufacturer -notlike "*HP*" -and $Manufacturer -notlike "*Hewlett*") {
#         Write-Host "❌ This is not an HP device (Manufacturer: $Manufacturer)" -ForegroundColor Red
#         Write-Host "This tool only works on HP ProBooks, ZBooks, EliteBooks, etc." -ForegroundColor Yellow
#         exit 1
#     }
    
#     Write-Host "✅ HP Device Detected: $Model" -ForegroundColor Green
#     Write-CMTraceLog -Message "HP Device detected: $Manufacturer $Model" -Component "Main"
# }
# catch {
#     Write-Host "⚠️  Could not determine device manufacturer, continuing anyway..." -ForegroundColor Yellow
#     Write-CMTraceLog -Message "Could not determine manufacturer: $($_.Exception.Message)" -Component "Main" -Type 2
# }

# Write-Host ""
# Write-Host "Step 1: Scanning for ALL available updates..." -ForegroundColor Cyan
# Write-CMTraceLog -Message "Starting comprehensive scan for all updates" -Component "Scan"

# try {
#     $ScanExitCode = Invoke-HPIA -Operation "Analyze" -Category "All" -Selection "All" -Action "List" -ReportsFolder $ReportsFolder
#     Write-Host "✅ Scan completed" -ForegroundColor Green
# }
# catch {
#     Write-Host "❌ Scan failed: $($_.Exception.Message)" -ForegroundColor Red
#     Write-CMTraceLog -Message "Scan failed: $($_.Exception.Message)" -Component "Scan" -Type 3
#     exit 1
# }

# # If no updates found, exit gracefully
# if ($ScanExitCode -eq 256) {
#     Write-Host ""
#     Write-Host "Great! Your HP device is already up to date!" -ForegroundColor Green
#     Write-Host "No updates were found." -ForegroundColor Gray
#     Write-CMTraceLog -Message "No updates found - system is current" -Component "Main"
#     exit 0
# }

# Write-Host ""
# Write-Host "Step 2: Downloading and installing ALL updates..." -ForegroundColor Cyan
# Write-Host "This includes: BIOS, Drivers, Software, Firmware, and Accessories" -ForegroundColor Gray
# Write-CMTraceLog -Message "Starting download and installation of all available updates" -Component "Install"

# try {
#     $InstallExitCode = Invoke-HPIA -Operation "DownloadSoftPaqs" -Category "All" -Selection "All" -Action "Install" -ReportsFolder $ReportsFolder
#     Write-Host "✅ Installation process completed" -ForegroundColor Green
#     Write-CMTraceLog -Message "Installation process completed with exit code: $InstallExitCode" -Component "Install"
# }
# catch {
#     Write-Host "❌ Installation failed: $($_.Exception.Message)" -ForegroundColor Red
#     Write-CMTraceLog -Message "Installation failed: $($_.Exception.Message)" -Component "Install" -Type 3
#     exit 1
# }

# Write-Host ""
# Write-Host "========================================" -ForegroundColor Cyan

# # Handle reboot requirement
# if ($script:RebootRequired -or $InstallExitCode -eq 3010) {
#     Write-Host "UPDATES COMPLETED - RESTART REQUIRED" -ForegroundColor Yellow
#     Write-Host "The system will restart automatically in 30 seconds..." -ForegroundColor Red
#     Write-CMTraceLog -Message "Updates completed - automatic restart in 30 seconds" -Component "Main" -Type 2
    
#     # 30 second countdown
#     for ($i = 30; $i -gt 0; $i--) {
#         Write-Host "Restarting in $i seconds... (Press Ctrl+C to cancel)" -ForegroundColor Red
#         Start-Sleep -Seconds 1
#     }
    
#     Write-Host ""
#     Write-Host "Restarting system now..." -ForegroundColor Red
#     Write-CMTraceLog -Message "Initiating automatic system restart" -Component "Main"
#     Restart-Computer -Force
# }
# else {
#     Write-Host "ALL UPDATES COMPLETED SUCCESSFULLY!" -ForegroundColor Green
#     Write-Host "No restart required - you're all set!" -ForegroundColor Gray
#     Write-CMTraceLog -Message "All updates completed successfully - no restart required" -Component "Main"
# }

# Write-Host ""
# Write-Host "Log files saved to: $ReportsFolder" -ForegroundColor Gray
# Write-Host "========================================" -ForegroundColor Cyan

# #endregion
