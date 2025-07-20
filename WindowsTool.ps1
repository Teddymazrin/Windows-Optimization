# Windows Tool

function Option1 {
    Clear-Host
    # SFC Scannow
    SFC /scannow
Read-Host -Prompt "Press Enter to exit"
    
}

function Option2 {
    Clear-Host
# Target user's temporary folder
$tempFolder = $env:TEMP

# Remove all files and folders inside it
Get-ChildItem -Path $tempFolder -Recurse -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

# Run Diskcleanup (No GUI Interaction)
Start-Process "cleanmgr.exe" -ArgumentList "/verylowdisk" -Wait

}

function Option3 {
    Clear-Host
    # Reset Network
	netsh winsock reset
    ipconfig /flushdns
	netsh int ipv4 reset
	netsh int ipv6 reset
	netsh advfirewall reset
	netsh int tcp reset
}

function Option4 {
Clear-host
$download1 = "https://adwcleaner.malwarebytes.com/adwcleaner?channel=release"
$download2 = "https://github.com/Teddymazrin/Windows-Optimization/raw/refs/heads/main/Programs/MBSetup.exe"
$downloadPath1 = "$env:TEMP\adwcleaner.exe"
$downloadPath2 = "$env:TEMP\MBSetup.exe"
$destinationFolder = "C:\Users\$env:USERNAME\Desktop\PC\AntiVirus"
$destinationPath1 = "$destinationFolder\adwcleaner.exe"
$destinationPath2 = "$destinationFolder\MBSetup.exe"

# Check if both files already exist in destination
if ((Test-Path $destinationPath1) -and (Test-Path $destinationPath2)) {
    Write-Host "Both files already exist in the destination folder. Skipping download and install." -ForegroundColor Cyan
} else {
    # Create the AntiVirus folder if it doesn't exist
    if (-Not (Test-Path $destinationFolder)) {
        New-Item -Path $destinationFolder -ItemType Directory -Force
    }

    # Download adwcleaner if not in destination
    if (-Not (Test-Path $destinationPath1)) {
        Invoke-WebRequest -Uri $download1 -OutFile $downloadPath1
        Move-Item -Path $downloadPath1 -Destination $destinationPath1 -Force
        Write-Host "Downloaded and moved adwcleaner.exe" -ForegroundColor Green
    }

    # Download MBSetup if not in destination
    if (-Not (Test-Path $destinationPath2)) {
        Invoke-WebRequest -Uri $download2 -OutFile $downloadPath2
        Move-Item -Path $downloadPath2 -Destination $destinationPath2 -Force
        Write-Host "Downloaded and moved MBSetup.exe" -ForegroundColor Green
    }

    # Install AdwCleaner
    if (Test-Path $destinationPath1) {
        Write-Host "Installing AdwCleaner..." -ForegroundColor Yellow
        Start-Process -FilePath $destinationPath1 -ArgumentList "/eula /clean" -Wait
    }

    # Install MBSetup
    if (Test-Path $destinationPath2) {
        Write-Host "Installing MBSetup..." -ForegroundColor Yellow
        Start-Process -FilePath $destinationPath2 -Wait
    }
}

Write-Host "Script completed. Check Desktop > PC > AntiVirus folder." -ForegroundColor Magenta
Pause


}


function Option5 {
Clear-Host
# Registry Changes
# --- Restorepoint Section ---
Clear-Host
Write-Host "==============================================================================="
Write-Host "  Press 1 -  Create a Restore Point"
Write-Host "  Press 2 -  Continue Without Restore Point"
Write-Host "==============================================================================="

$choice = Read-Host "Enter Your Option"

if ($choice -eq "1") {
    Write-Host "Creating Restore Point..." -ForegroundColor Cyan
    Start-Service -Name 'vss'
    Enable-ComputerRestore -Drive "C:"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" `
        -Name "SystemRestorePointCreationFrequency" -Value 0
    Checkpoint-Computer -Description "BeforeTweaking"
}

Write-Host "Applying system tweaks..." -ForegroundColor Yellow

# Disable power throttling
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Value 1

# Games scheduling tweaks
$gamesPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
New-Item -Path $gamesPath -Force
Set-ItemProperty -Path $gamesPath -Name "Affinity" -Value 0
Set-ItemProperty -Path $gamesPath -Name "Background Only" -Value "False"
Set-ItemProperty -Path $gamesPath -Name "Clock Rate" -Value 10000
Set-ItemProperty -Path $gamesPath -Name "GPU Priority" -Value 8
Set-ItemProperty -Path $gamesPath -Name "Priority" -Value 6
Set-ItemProperty -Path $gamesPath -Name "Scheduling Category" -Value "High"
Set-ItemProperty -Path $gamesPath -Name "SFIO Priority" -Value "Normal"

# Sleep and startup
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabled" -Value 0

# Maintenance
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "MaintenanceDisabled" -Value 1

# UI tweaks
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value "0"
New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" `
    -Name "(default)" -PropertyType String -Value "" -Force

# Windows 11 features
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0

# Cortana
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0

# Priority control
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 2

# Pointer precision
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Value "0"
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Value "0"
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Value "0"

# UAC
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0

# Hibernate and PowerPlan
powercfg -h off
powercfg -restoredefaultschemes
powercfg -setactive "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
powercfg -delete 381b4222-f694-41f0-9685-ff5bb260df2e
powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a

Write-Host "`nTweaking complete!" -ForegroundColor Green
pause

}

function Option6 {
Clear-Host
# Nvidia
   Write-Host "==========================================="
    Write-Host "Nvidia Utilities" -ForegroundColor Yellow
    Write-Host "1. Update Nvidia Drivers"
    Write-Host "2. Uninstall Graphics Driver"
    Write-Host "3. Return to Main Menu"
    Write-Host "==========================================="
    $subChoice = Read-Host "Enter your Nvidia option"
    

    switch ($subChoice) {
        "1" {
            Write-Host "Launching Nvidia driver update..." -ForegroundColor Cyan
            Start-Process "https://www.nvidia.com/en-us/drivers/"
        }
        "2" {
            Write-Host "Running Driver Uninstaller" -ForegroundColor Cyan

            $cleanupPath = "C:/CleanupTool.exe"

            if (Test-Path $cleanupPath) {
            Write-Host "Cleanup Tool already exists. Starting it..." -ForegroundColor Green
    	    Start-Process -FilePath $cleanupPath
      } else {
    	    Write-Host "Cleanup Tool not found. Downloading..." -ForegroundColor Yellow
            Invoke-WebRequest -Uri "https://github.com/Teddymazrin/Windows-Optimization/raw/refs/heads/main/Programs/CleanupTool.exe" -OutFile $cleanupPath
            Write-Host "Download complete. Starting Cleanup Tool..." -ForegroundColor Green
            Start-Process -FilePath $cleanupPath
}

        }
	
        "3" {
            return
        }
        default {
            Write-Host "Invalid Nvidia option. Returning to Main Menu." -ForegroundColor Red
        }
    }

}

function Option7 {
Clear-Host
# Default Services / Bare Gaming Services
   Write-Host "==========================================="
    Write-Host "Set Services to Default / Manual for Performance" -ForegroundColor Yellow
    Write-Host "1. Set Services to Manual"
    Write-Host "2. Set Services to Default"
    Write-Host "3. Return to Main Menu"
    Write-Host "==========================================="
    $subChoice = Read-Host "Enter your Nvidia option"
    

    switch ($subChoice) {
        "1" {
# Set Services to Manual

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AJRouter" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ALG" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppMgmt" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppReadiness" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppVClient" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppXSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Appinfo" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AudioEndpointBuilder" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AudioSrv" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Audiosrv" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AxInstSV" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BDESVC" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BFE" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BITS" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BTAGService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BcastDVRUserService_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BluetoothUserService_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Browser" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BthAvctpSvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BthHFSrv" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CDPSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc_*" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\COMSysApp" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CaptureService_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertPropSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ClipSVC" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CoreMessagingRegistrar" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CryptSvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CscService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DPS" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DcomLaunch" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DcpSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DevQueryBroker" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceAssociationService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceInstall" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dhcp" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DialogBlockingService" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DispBrokerDesktopSvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EFS" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EapHost" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EntAppSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventSystem" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\FDResPub" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Fax" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\FontCache" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\FrameServer" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\FrameServerMonitor" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HomeGroupListener" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HvHost" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\IEEtwCollectorService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\IKEEXT" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\InstallService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\InventorySvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KeyIso" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KtmRm" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LSM" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LicenseManager" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LxpSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MSDTC" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MSiSCSI" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\McpManagementService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MessagingService_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MpsSvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NPSMSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NaturalAuthentication" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NcaSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NcbService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NcdAutoSetup" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetSetupSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netman" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NgcCtnrSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NgcSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\OneSyncSvc_*" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\P9RdrService_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPAutoReg" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PcaSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PeerDistSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PenService_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PerfHost" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PhoneSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PlugPlay" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Power" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PrintNotify" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ProfSvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PushToInstall" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\QWAVE" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasAuto" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RetailDemo" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RmSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RpcEptMapper" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RpcLocator" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RpcSs" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SCPolicySvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SCardSvr" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SDRSVC" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SEMgrSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SENS" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMPTRAP" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMPTrap" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SamSs" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ScDeviceEnum" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Schedule" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityHealthService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SensorDataService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SensorService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SensrSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SessionEnv" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedRealitySvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ShellHWDetection" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SmsRouter" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SstpSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\StiSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\StorSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SystemEventsBroker" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TabletInputService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TapiSrv" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TermService" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Themes" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TieringEngineService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TimeBroker" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TokenBroker" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TrkWks" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TrustedInstaller" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UI0Detect" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UdkUserSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UevAgentService" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UmRdpService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UnistoreSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UserDataSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UserManager" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UsoSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VGAuthService" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VMTools" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VSS" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VacSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VaultSvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WManSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WPDBusEnum" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WalletService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WarpJITSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WbioSrvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Wcmsvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WcsPlugInService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WdiServiceHost" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WdiSystemHost" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WiaRpc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Winmgmt" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WlanSvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WpcMonSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WpnService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WpnUserService_*" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XboxGipSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\autotimesvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\bthserv" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\camsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\cbdhsvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\cloudidsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dcsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\defragsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\diagsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dot3svc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdate" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdatem" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\embeddedmode" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\fdPHost" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\fhsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\gpsvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\hidserv" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\icssvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\iphlpsvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lltdsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lmhosts" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpssvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\msiserver" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\netprofm" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nsi" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\p2pimsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\p2psvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\perceptionsimulation" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\pla" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\seclogon" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\shpamsvc" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\smphost" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\spectrum" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\sppsvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ssh-agent" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\svsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\swprv" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\tiledatamodelsvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\uhssvc" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vds" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vm3dservice" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicguestinterface" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicheartbeat" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmickvpexchange" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicrdv" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicshutdown" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmictimesync" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicvmsession" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicvss" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmvss" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wbengine" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wcncsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\webthreatdefsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc_*" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wisvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wlidsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wlpasvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wmiApSrv" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\workfolderssvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wscsvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wudfsvc" -Name "Start" -Value 3

Write-Host "Services Set to Manual. Restart Computer for this to go into effect" -Foregroundcolor Yellow
pause
        }
        "2" {
# Set Services to Default

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AJRouter" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ALG" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppMgmt" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppReadiness" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppVClient" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppXSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Appinfo" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AudioEndpointBuilder" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AudioSrv" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Audiosrv" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AxInstSV" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BDESVC" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BFE" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BITS" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BTAGService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BcastDVRUserService_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BluetoothUserService_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Browser" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BthAvctpSvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BthHFSrv" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CDPSvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc_*" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\COMSysApp" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CaptureService_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertPropSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ClipSVC" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CoreMessagingRegistrar" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CryptSvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CscService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DPS" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DcomLaunch" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DcpSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DevQueryBroker" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceAssociationService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceInstall" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dhcp" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DialogBlockingService" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DispBrokerDesktopSvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EFS" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EapHost" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EntAppSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventSystem" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\FDResPub" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Fax" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\FontCache" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\FrameServer" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\FrameServerMonitor" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HomeGroupListener" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HvHost" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\IEEtwCollectorService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\IKEEXT" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\InstallService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\InventorySvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KeyIso" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KtmRm" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LSM" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LicenseManager" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LxpSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MSDTC" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MSiSCSI" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\McpManagementService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MessagingService_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MpsSvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NPSMSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NaturalAuthentication" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NcaSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NcbService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NcdAutoSetup" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetSetupSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netman" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NgcCtnrSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NgcSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\OneSyncSvc_*" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\P9RdrService_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPAutoReg" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PcaSvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PeerDistSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PenService_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PerfHost" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PhoneSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PlugPlay" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Power" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PrintNotify" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ProfSvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PushToInstall" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\QWAVE" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasAuto" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RetailDemo" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RmSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RpcEptMapper" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RpcLocator" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RpcSs" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SCPolicySvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SCardSvr" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SDRSVC" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SEMgrSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SENS" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMPTRAP" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMPTrap" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SamSs" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ScDeviceEnum" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Schedule" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityHealthService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SensorDataService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SensorService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SensrSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SessionEnv" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedRealitySvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ShellHWDetection" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SmsRouter" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SstpSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\StiSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\StorSvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SystemEventsBroker" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TabletInputService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TapiSrv" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TermService" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Themes" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TieringEngineService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TimeBroker" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TokenBroker" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TrkWks" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TrustedInstaller" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UI0Detect" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UdkUserSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UevAgentService" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UmRdpService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UnistoreSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UserDataSvc_*" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UserManager" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UsoSvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VGAuthService" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VMTools" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VSS" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VacSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VaultSvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WManSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WPDBusEnum" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WalletService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WarpJITSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WbioSrvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Wcmsvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WcsPlugInService" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WdiServiceHost" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WdiSystemHost" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WiaRpc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Winmgmt" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WlanSvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WpcMonSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WpnService" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WpnUserService_*" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XboxGipSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\autotimesvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\bthserv" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\camsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\cbdhsvc_*" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\cloudidsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dcsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\defragsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\diagsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dot3svc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdate" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdatem" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\embeddedmode" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\fdPHost" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\fhsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\gpsvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\hidserv" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\icssvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\iphlpsvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lltdsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lmhosts" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpssvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\msiserver" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\netprofm" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nsi" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\p2pimsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\p2psvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\perceptionsimulation" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\pla" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\seclogon" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\shpamsvc" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\smphost" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\spectrum" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\sppsvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ssh-agent" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\svsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\swprv" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\tiledatamodelsvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\uhssvc" -Name "Start" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vds" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vm3dservice" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicguestinterface" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicheartbeat" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmickvpexchange" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicrdv" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicshutdown" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmictimesync" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicvmsession" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicvss" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmvss" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wbengine" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wcncsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\webthreatdefsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc_*" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wisvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wlidsvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wlpasvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wmiApSrv" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\workfolderssvc" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wscsvc" -Name "Start" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv" -Name "Start" -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wudfsvc" -Name "Start" -Value 3

Write-Host "Services Set to Default. Restart Computer for this to go into effect" -Foregroundcolor Yellow
pause

        }
	
        "3" {
            return
        }
        default {
            Write-Host "Invalid Nvidia option. Returning to Main Menu." -ForegroundColor Red
        }
    }

}


# Display the Menu and Handle User Input
while ($true) {
Clear-Host

Write-Host "Windows Tool" -ForegroundColor Cyan

    Write-Host "==========================================="
    Write-Host "PC Maintenance" -ForegroundColor Yellow
    Write-Host "1. Troubleshoot PC"
    Write-Host "2. Clear Disk Space"
    Write-Host "3. Reset Network"
    Write-Host "4. Download AntiVirus Programs"
    Write-Host "PC Optimization" -ForegroundColor Yellow
    Write-Host "5. Apply Optimizations"
    Write-Host "6. Nvidia"
    Write-Host "7. Set Services to Default / Manual for Performance"
    Write-Host "==========================================="
    $choice = Read-Host "Enter your choice"

        switch ($choice) {
        "1" { Option1 }
        "2" { Option2 }
        "3" { Option3 }
	"4" { Option4 }
        "5" { Option5 }
	"6" { Option6 }
        "7" { Option7 }
        default { Write-Host "Invalid choice. Please try again." }
    }
}
