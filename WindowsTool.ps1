# Windows Tool

function Option1 {
    Clear-Host
    # SFC Scannow
    SFC /scannow
    
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

Set-Service -Name "AJRouter" -StartupType Disabled
Set-Service -Name "ALG" -StartupType Manual
Set-Service -Name "AppIDSvc" -StartupType Manual
Set-Service -Name "AppMgmt" -StartupType Manual
Set-Service -Name "AppReadiness" -StartupType Manual
Set-Service -Name "AppVClient" -StartupType Disabled
Set-Service -Name "AppXSvc" -StartupType Manual
Set-Service -Name "Appinfo" -StartupType Manual
Set-Service -Name "AssignedAccessManagerSvc" -StartupType Disabled
Set-Service -Name "AudioEndpointBuilder" -StartupType Automatic
Set-Service -Name "AudioSrv" -StartupType Automatic
Set-Service -Name "Audiosrv" -StartupType Automatic
Set-Service -Name "AxInstSV" -StartupType Manual
Set-Service -Name "BDESVC" -StartupType Manual
Set-Service -Name "BFE" -StartupType Automatic
Set-Service -Name "BITS" -StartupType AutomaticDelayedStart
Set-Service -Name "BTAGService" -StartupType Manual
Set-Service -Name "BcastDVRUserService_*" -StartupType Manual
Set-Service -Name "BluetoothUserService_*" -StartupType Manual
Set-Service -Name "BrokerInfrastructure" -StartupType Automatic
Set-Service -Name "Browser" -StartupType Manual
Set-Service -Name "BthAvctpSvc" -StartupType Automatic
Set-Service -Name "BthHFSrv" -StartupType Automatic
Set-Service -Name "CDPSvc" -StartupType Manual
Set-Service -Name "CDPUserSvc_*" -StartupType Automatic
Set-Service -Name "COMSysApp" -StartupType Manual
Set-Service -Name "CaptureService_*" -StartupType Manual
Set-Service -Name "CertPropSvc" -StartupType Manual
Set-Service -Name "ClipSVC" -StartupType Manual
Set-Service -Name "ConsentUxUserSvc_*" -StartupType Manual
Set-Service -Name "CoreMessagingRegistrar" -StartupType Automatic
Set-Service -Name "CredentialEnrollmentManagerUserSvc_*" -StartupType Manual
Set-Service -Name "CryptSvc" -StartupType Automatic
Set-Service -Name "CscService" -StartupType Manual
Set-Service -Name "DPS" -StartupType Automatic
Set-Service -Name "DcomLaunch" -StartupType Automatic
Set-Service -Name "DcpSvc" -StartupType Manual
Set-Service -Name "DevQueryBroker" -StartupType Manual
Set-Service -Name "DeviceAssociationBrokerSvc_*" -StartupType Manual
Set-Service -Name "DeviceAssociationService" -StartupType Manual
Set-Service -Name "DeviceInstall" -StartupType Manual
Set-Service -Name "DevicePickerUserSvc_*" -StartupType Manual
Set-Service -Name "DevicesFlowUserSvc_*" -StartupType Manual
Set-Service -Name "Dhcp" -StartupType Automatic
Set-Service -Name "DiagTrack" -StartupType Disabled
Set-Service -Name "DialogBlockingService" -StartupType Disabled
Set-Service -Name "DispBrokerDesktopSvc" -StartupType Automatic
Set-Service -Name "DisplayEnhancementService" -StartupType Manual
Set-Service -Name "DmEnrollmentSvc" -StartupType Manual
Set-Service -Name "Dnscache" -StartupType Automatic
Set-Service -Name "EFS" -StartupType Manual
Set-Service -Name "EapHost" -StartupType Manual
Set-Service -Name "EntAppSvc" -StartupType Manual
Set-Service -Name "EventLog" -StartupType Automatic
Set-Service -Name "EventSystem" -StartupType Automatic
Set-Service -Name "FDResPub" -StartupType Manual
Set-Service -Name "Fax" -StartupType Manual
Set-Service -Name "FontCache" -StartupType Automatic
Set-Service -Name "FrameServer" -StartupType Manual
Set-Service -Name "FrameServerMonitor" -StartupType Manual
Set-Service -Name "GraphicsPerfSvc" -StartupType Manual
Set-Service -Name "HomeGroupListener" -StartupType Manual
Set-Service -Name "HomeGroupProvider" -StartupType Manual
Set-Service -Name "HvHost" -StartupType Manual
Set-Service -Name "IEEtwCollectorService" -StartupType Manual
Set-Service -Name "IKEEXT" -StartupType Manual
Set-Service -Name "InstallService" -StartupType Manual
Set-Service -Name "InventorySvc" -StartupType Manual
Set-Service -Name "IpxlatCfgSvc" -StartupType Manual
Set-Service -Name "KeyIso" -StartupType Automatic
Set-Service -Name "KtmRm" -StartupType Manual
Set-Service -Name "LSM" -StartupType Automatic
Set-Service -Name "LanmanServer" -StartupType Automatic
Set-Service -Name "LanmanWorkstation" -StartupType Automatic
Set-Service -Name "LicenseManager" -StartupType Manual
Set-Service -Name "LxpSvc" -StartupType Manual
Set-Service -Name "MSDTC" -StartupType Manual
Set-Service -Name "MSiSCSI" -StartupType Manual
Set-Service -Name "MapsBroker" -StartupType AutomaticDelayedStart
Set-Service -Name "McpManagementService" -StartupType Manual
Set-Service -Name "MessagingService_*" -StartupType Manual
Set-Service -Name "MicrosoftEdgeElevationService" -StartupType Manual
Set-Service -Name "MixedRealityOpenXRSvc" -StartupType Manual
Set-Service -Name "MpsSvc" -StartupType Automatic
Set-Service -Name "MsKeyboardFilter" -StartupType Manual
Set-Service -Name "NPSMSvc_*" -StartupType Manual
Set-Service -Name "NaturalAuthentication" -StartupType Manual
Set-Service -Name "NcaSvc" -StartupType Manual
Set-Service -Name "NcbService" -StartupType Manual
Set-Service -Name "NcdAutoSetup" -StartupType Manual
Set-Service -Name "NetSetupSvc" -StartupType Manual
Set-Service -Name "NetTcpPortSharing" -StartupType Disabled
Set-Service -Name "Netlogon" -StartupType Automatic
Set-Service -Name "Netman" -StartupType Manual
Set-Service -Name "NgcCtnrSvc" -StartupType Manual
Set-Service -Name "NgcSvc" -StartupType Manual
Set-Service -Name "NlaSvc" -StartupType Manual
Set-Service -Name "OneSyncSvc_*" -StartupType Automatic
Set-Service -Name "P9RdrService_*" -StartupType Manual
Set-Service -Name "PNRPAutoReg" -StartupType Manual
Set-Service -Name "PNRPsvc" -StartupType Manual
Set-Service -Name "PcaSvc" -StartupType Manual
Set-Service -Name "PeerDistSvc" -StartupType Manual
Set-Service -Name "PenService_*" -StartupType Manual
Set-Service -Name "PerfHost" -StartupType Manual
Set-Service -Name "PhoneSvc" -StartupType Manual
Set-Service -Name "PimIndexMaintenanceSvc_*" -StartupType Manual
Set-Service -Name "PlugPlay" -StartupType Manual
Set-Service -Name "PolicyAgent" -StartupType Manual
Set-Service -Name "Power" -StartupType Automatic
Set-Service -Name "PrintNotify" -StartupType Manual
Set-Service -Name "PrintWorkflowUserSvc_*" -StartupType Manual
Set-Service -Name "ProfSvc" -StartupType Automatic
Set-Service -Name "PushToInstall" -StartupType Manual
Set-Service -Name "QWAVE" -StartupType Manual
Set-Service -Name "RasAuto" -StartupType Manual
Set-Service -Name "RasMan" -StartupType Manual
Set-Service -Name "RemoteAccess" -StartupType Disabled
Set-Service -Name "RemoteRegistry" -StartupType Disabled
Set-Service -Name "RetailDemo" -StartupType Manual
Set-Service -Name "RmSvc" -StartupType Manual
Set-Service -Name "RpcEptMapper" -StartupType Automatic
Set-Service -Name "RpcLocator" -StartupType Manual
Set-Service -Name "RpcSs" -StartupType Automatic
Set-Service -Name "SCPolicySvc" -StartupType Manual
Set-Service -Name "SCardSvr" -StartupType Manual
Set-Service -Name "SDRSVC" -StartupType Manual
Set-Service -Name "SEMgrSvc" -StartupType Manual
Set-Service -Name "SENS" -StartupType Automatic
Set-Service -Name "SNMPTRAP" -StartupType Manual
Set-Service -Name "SNMPTrap" -StartupType Manual
Set-Service -Name "SSDPSRV" -StartupType Manual
Set-Service -Name "SamSs" -StartupType Automatic
Set-Service -Name "ScDeviceEnum" -StartupType Manual
Set-Service -Name "Schedule" -StartupType Automatic
Set-Service -Name "SecurityHealthService" -StartupType Manual
Set-Service -Name "Sense" -StartupType Manual
Set-Service -Name "SensorDataService" -StartupType Manual
Set-Service -Name "SensorService" -StartupType Manual
Set-Service -Name "SensrSvc" -StartupType Manual
Set-Service -Name "SessionEnv" -StartupType Manual
Set-Service -Name "SharedAccess" -StartupType Manual
Set-Service -Name "SharedRealitySvc" -StartupType Manual
Set-Service -Name "ShellHWDetection" -StartupType Automatic
Set-Service -Name "SmsRouter" -StartupType Manual
Set-Service -Name "Spooler" -StartupType Automatic
Set-Service -Name "SstpSvc" -StartupType Manual
Set-Service -Name "StiSvc" -StartupType Manual
Set-Service -Name "StorSvc" -StartupType Manual
Set-Service -Name "SysMain" -StartupType Automatic
Set-Service -Name "SystemEventsBroker" -StartupType Automatic
Set-Service -Name "TabletInputService" -StartupType Manual
Set-Service -Name "TapiSrv" -StartupType Manual
Set-Service -Name "TermService" -StartupType Automatic
Set-Service -Name "Themes" -StartupType Automatic
Set-Service -Name "TieringEngineService" -StartupType Manual
Set-Service -Name "TimeBroker" -StartupType Manual
Set-Service -Name "TimeBrokerSvc" -StartupType Manual
Set-Service -Name "TokenBroker" -StartupType Manual
Set-Service -Name "TrkWks" -StartupType Automatic
Set-Service -Name "TroubleshootingSvc" -StartupType Manual
Set-Service -Name "TrustedInstaller" -StartupType Manual
Set-Service -Name "UI0Detect" -StartupType Manual
Set-Service -Name "UdkUserSvc_*" -StartupType Manual
Set-Service -Name "UevAgentService" -StartupType Disabled
Set-Service -Name "UmRdpService" -StartupType Manual
Set-Service -Name "UnistoreSvc_*" -StartupType Manual
Set-Service -Name "UserDataSvc_*" -StartupType Manual
Set-Service -Name "UserManager" -StartupType Automatic
Set-Service -Name "UsoSvc" -StartupType Manual
Set-Service -Name "VGAuthService" -StartupType Automatic
Set-Service -Name "VMTools" -StartupType Automatic
Set-Service -Name "VSS" -StartupType Manual
Set-Service -Name "VacSvc" -StartupType Manual
Set-Service -Name "VaultSvc" -StartupType Automatic
Set-Service -Name "W32Time" -StartupType Manual
Set-Service -Name "WEPHOSTSVC" -StartupType Manual
Set-Service -Name "WFDSConMgrSvc" -StartupType Manual
Set-Service -Name "WMPNetworkSvc" -StartupType Manual
Set-Service -Name "WManSvc" -StartupType Manual
Set-Service -Name "WPDBusEnum" -StartupType Manual
Set-Service -Name "WSService" -StartupType Manual
Set-Service -Name "WSearch" -StartupType AutomaticDelayedStart
Set-Service -Name "WaaSMedicSvc" -StartupType Manual
Set-Service -Name "WalletService" -StartupType Manual
Set-Service -Name "WarpJITSvc" -StartupType Manual
Set-Service -Name "WbioSrvc" -StartupType Manual
Set-Service -Name "Wcmsvc" -StartupType Automatic
Set-Service -Name "WcsPlugInService" -StartupType Manual
Set-Service -Name "WdNisSvc" -StartupType Manual
Set-Service -Name "WdiServiceHost" -StartupType Manual
Set-Service -Name "WdiSystemHost" -StartupType Manual
Set-Service -Name "WebClient" -StartupType Manual
Set-Service -Name "Wecsvc" -StartupType Manual
Set-Service -Name "WerSvc" -StartupType Manual
Set-Service -Name "WiaRpc" -StartupType Manual
Set-Service -Name "WinDefend" -StartupType Automatic
Set-Service -Name "WinHttpAutoProxySvc" -StartupType Manual
Set-Service -Name "WinRM" -StartupType Manual
Set-Service -Name "Winmgmt" -StartupType Automatic
Set-Service -Name "WlanSvc" -StartupType Automatic
Set-Service -Name "WpcMonSvc" -StartupType Manual
Set-Service -Name "WpnService" -StartupType Manual
Set-Service -Name "WpnUserService_*" -StartupType Automatic
Set-Service -Name "XblAuthManager" -StartupType Manual
Set-Service -Name "XblGameSave" -StartupType Manual
Set-Service -Name "XboxGipSvc" -StartupType Manual
Set-Service -Name "XboxNetApiSvc" -StartupType Manual
Set-Service -Name "autotimesvc" -StartupType Manual
Set-Service -Name "bthserv" -StartupType Manual
Set-Service -Name "camsvc" -StartupType Manual
Set-Service -Name "cbdhsvc_*" -StartupType Manual
Set-Service -Name "cloudidsvc" -StartupType Manual
Set-Service -Name "dcsvc" -StartupType Manual
Set-Service -Name "defragsvc" -StartupType Manual
Set-Service -Name "diagnosticshub.standardcollector.service" -StartupType Manual
Set-Service -Name "diagsvc" -StartupType Manual
Set-Service -Name "dmwappushservice" -StartupType Manual
Set-Service -Name "dot3svc" -StartupType Manual
Set-Service -Name "edgeupdate" -StartupType Manual
Set-Service -Name "edgeupdatem" -StartupType Manual
Set-Service -Name "embeddedmode" -StartupType Manual
Set-Service -Name "fdPHost" -StartupType Manual
Set-Service -Name "fhsvc" -StartupType Manual
Set-Service -Name "gpsvc" -StartupType Automatic
Set-Service -Name "hidserv" -StartupType Manual
Set-Service -Name "icssvc" -StartupType Manual
Set-Service -Name "iphlpsvc" -StartupType Automatic
Set-Service -Name "lfsvc" -StartupType Manual
Set-Service -Name "lltdsvc" -StartupType Manual
Set-Service -Name "lmhosts" -StartupType Manual
Set-Service -Name "mpssvc" -StartupType Automatic
Set-Service -Name "msiserver" -StartupType Manual
Set-Service -Name "netprofm" -StartupType Manual
Set-Service -Name "nsi" -StartupType Automatic
Set-Service -Name "p2pimsvc" -StartupType Manual
Set-Service -Name "p2psvc" -StartupType Manual
Set-Service -Name "perceptionsimulation" -StartupType Manual
Set-Service -Name "pla" -StartupType Manual
Set-Service -Name "seclogon" -StartupType Manual
Set-Service -Name "shpamsvc" -StartupType Disabled
Set-Service -Name "smphost" -StartupType Manual
Set-Service -Name "spectrum" -StartupType Manual
Set-Service -Name "sppsvc" -StartupType AutomaticDelayedStart
Set-Service -Name "ssh-agent" -StartupType Disabled
Set-Service -Name "svsvc" -StartupType Manual
Set-Service -Name "swprv" -StartupType Manual
Set-Service -Name "tiledatamodelsvc" -StartupType Automatic
Set-Service -Name "tzautoupdate" -StartupType Disabled
Set-Service -Name "uhssvc" -StartupType Disabled
Set-Service -Name "upnphost" -StartupType Manual
Set-Service -Name "vds" -StartupType Manual
Set-Service -Name "vm3dservice" -StartupType Manual
Set-Service -Name "vmicguestinterface" -StartupType Manual
Set-Service -Name "vmicheartbeat" -StartupType Manual
Set-Service -Name "vmickvpexchange" -StartupType Manual
Set-Service -Name "vmicrdv" -StartupType Manual
Set-Service -Name "vmicshutdown" -StartupType Manual
Set-Service -Name "vmictimesync" -StartupType Manual
Set-Service -Name "vmicvmsession" -StartupType Manual
Set-Service -Name "vmicvss" -StartupType Manual
Set-Service -Name "vmvss" -StartupType Manual
Set-Service -Name "wbengine" -StartupType Manual
Set-Service -Name "wcncsvc" -StartupType Manual
Set-Service -Name "webthreatdefsvc" -StartupType Manual
Set-Service -Name "webthreatdefusersvc_*" -StartupType Automatic
Set-Service -Name "wercplsupport" -StartupType Manual
Set-Service -Name "wisvc" -StartupType Manual
Set-Service -Name "wlidsvc" -StartupType Manual
Set-Service -Name "wlpasvc" -StartupType Manual
Set-Service -Name "wmiApSrv" -StartupType Manual
Set-Service -Name "workfolderssvc" -StartupType Manual
Set-Service -Name "wscsvc" -StartupType AutomaticDelayedStart
Set-Service -Name "wuauserv" -StartupType Manual
Set-Service -Name "wudfsvc" -StartupType Manual
        }
        "2" {
# Set Services to Default

Set-Service -Name "AJRouter" -StartupType Manual
Set-Service -Name "ALG" -StartupType Manual
Set-Service -Name "AppIDSvc" -StartupType Manual
Set-Service -Name "AppMgmt" -StartupType Manual
Set-Service -Name "AppReadiness" -StartupType Manual
Set-Service -Name "AppVClient" -StartupType Disabled
Set-Service -Name "AppXSvc" -StartupType Manual
Set-Service -Name "Appinfo" -StartupType Manual
Set-Service -Name "AssignedAccessManagerSvc" -StartupType Manual
Set-Service -Name "AudioEndpointBuilder" -StartupType Automatic
Set-Service -Name "AudioSrv" -StartupType Automatic
Set-Service -Name "Audiosrv" -StartupType Automatic
Set-Service -Name "AxInstSV" -StartupType Manual
Set-Service -Name "BDESVC" -StartupType Manual
Set-Service -Name "BFE" -StartupType Automatic
Set-Service -Name "BITS" -StartupType Automatic
Set-Service -Name "BTAGService" -StartupType Manual
Set-Service -Name "BcastDVRUserService_*" -StartupType Manual
Set-Service -Name "BluetoothUserService_*" -StartupType Manual
Set-Service -Name "BrokerInfrastructure" -StartupType Automatic
Set-Service -Name "Browser" -StartupType Manual
Set-Service -Name "BthAvctpSvc" -StartupType Automatic
Set-Service -Name "BthHFSrv" -StartupType Automatic
Set-Service -Name "CDPSvc" -StartupType Automatic
Set-Service -Name "CDPUserSvc_*" -StartupType Automatic
Set-Service -Name "COMSysApp" -StartupType Manual
Set-Service -Name "CaptureService_*" -StartupType Manual
Set-Service -Name "CertPropSvc" -StartupType Manual
Set-Service -Name "ClipSVC" -StartupType Manual
Set-Service -Name "ConsentUxUserSvc_*" -StartupType Manual
Set-Service -Name "CoreMessagingRegistrar" -StartupType Automatic
Set-Service -Name "CredentialEnrollmentManagerUserSvc_*" -StartupType Manual
Set-Service -Name "CryptSvc" -StartupType Automatic
Set-Service -Name "CscService" -StartupType Manual
Set-Service -Name "DPS" -StartupType Automatic
Set-Service -Name "DcomLaunch" -StartupType Automatic
Set-Service -Name "DcpSvc" -StartupType Manual
Set-Service -Name "DevQueryBroker" -StartupType Manual
Set-Service -Name "DeviceAssociationBrokerSvc_*" -StartupType Manual
Set-Service -Name "DeviceAssociationService" -StartupType Manual
Set-Service -Name "DeviceInstall" -StartupType Manual
Set-Service -Name "DevicePickerUserSvc_*" -StartupType Manual
Set-Service -Name "DevicesFlowUserSvc_*" -StartupType Manual
Set-Service -Name "Dhcp" -StartupType Automatic
Set-Service -Name "DiagTrack" -StartupType Automatic
Set-Service -Name "DialogBlockingService" -StartupType Disabled
Set-Service -Name "DispBrokerDesktopSvc" -StartupType Automatic
Set-Service -Name "DisplayEnhancementService" -StartupType Manual
Set-Service -Name "DmEnrollmentSvc" -StartupType Manual
Set-Service -Name "Dnscache" -StartupType Automatic
Set-Service -Name "EFS" -StartupType Manual
Set-Service -Name "EapHost" -StartupType Manual
Set-Service -Name "EntAppSvc" -StartupType Manual
Set-Service -Name "EventLog" -StartupType Automatic
Set-Service -Name "EventSystem" -StartupType Automatic
Set-Service -Name "FDResPub" -StartupType Manual
Set-Service -Name "Fax" -StartupType Manual
Set-Service -Name "FontCache" -StartupType Automatic
Set-Service -Name "FrameServer" -StartupType Manual
Set-Service -Name "FrameServerMonitor" -StartupType Manual
Set-Service -Name "GraphicsPerfSvc" -StartupType Manual
Set-Service -Name "HomeGroupListener" -StartupType Manual
Set-Service -Name "HomeGroupProvider" -StartupType Manual
Set-Service -Name "HvHost" -StartupType Manual
Set-Service -Name "IEEtwCollectorService" -StartupType Manual
Set-Service -Name "IKEEXT" -StartupType Manual
Set-Service -Name "InstallService" -StartupType Manual
Set-Service -Name "InventorySvc" -StartupType Manual
Set-Service -Name "IpxlatCfgSvc" -StartupType Manual
Set-Service -Name "KeyIso" -StartupType Automatic
Set-Service -Name "KtmRm" -StartupType Manual
Set-Service -Name "LSM" -StartupType Automatic
Set-Service -Name "LanmanServer" -StartupType Automatic
Set-Service -Name "LanmanWorkstation" -StartupType Automatic
Set-Service -Name "LicenseManager" -StartupType Manual
Set-Service -Name "LxpSvc" -StartupType Manual
Set-Service -Name "MSDTC" -StartupType Manual
Set-Service -Name "MSiSCSI" -StartupType Manual
Set-Service -Name "MapsBroker" -StartupType Automatic
Set-Service -Name "McpManagementService" -StartupType Manual
Set-Service -Name "MessagingService_*" -StartupType Manual
Set-Service -Name "MicrosoftEdgeElevationService" -StartupType Manual
Set-Service -Name "MixedRealityOpenXRSvc" -StartupType Manual
Set-Service -Name "MpsSvc" -StartupType Automatic
Set-Service -Name "MsKeyboardFilter" -StartupType Disabled
Set-Service -Name "NPSMSvc_*" -StartupType Manual
Set-Service -Name "NaturalAuthentication" -StartupType Manual
Set-Service -Name "NcaSvc" -StartupType Manual
Set-Service -Name "NcbService" -StartupType Manual
Set-Service -Name "NcdAutoSetup" -StartupType Manual
Set-Service -Name "NetSetupSvc" -StartupType Manual
Set-Service -Name "NetTcpPortSharing" -StartupType Disabled
Set-Service -Name "Netlogon" -StartupType Automatic
Set-Service -Name "Netman" -StartupType Manual
Set-Service -Name "NgcCtnrSvc" -StartupType Manual
Set-Service -Name "NgcSvc" -StartupType Manual
Set-Service -Name "NlaSvc" -StartupType Manual
Set-Service -Name "OneSyncSvc_*" -StartupType Automatic
Set-Service -Name "P9RdrService_*" -StartupType Manual
Set-Service -Name "PNRPAutoReg" -StartupType Manual
Set-Service -Name "PNRPsvc" -StartupType Manual
Set-Service -Name "PcaSvc" -StartupType Automatic
Set-Service -Name "PeerDistSvc" -StartupType Manual
Set-Service -Name "PenService_*" -StartupType Manual
Set-Service -Name "PerfHost" -StartupType Manual
Set-Service -Name "PhoneSvc" -StartupType Manual
Set-Service -Name "PimIndexMaintenanceSvc_*" -StartupType Manual
Set-Service -Name "PlugPlay" -StartupType Manual
Set-Service -Name "PolicyAgent" -StartupType Manual
Set-Service -Name "Power" -StartupType Automatic
Set-Service -Name "PrintNotify" -StartupType Manual
Set-Service -Name "PrintWorkflowUserSvc_*" -StartupType Manual
Set-Service -Name "ProfSvc" -StartupType Automatic
Set-Service -Name "PushToInstall" -StartupType Manual
Set-Service -Name "QWAVE" -StartupType Manual
Set-Service -Name "RasAuto" -StartupType Manual
Set-Service -Name "RasMan" -StartupType Manual
Set-Service -Name "RemoteAccess" -StartupType Disabled
Set-Service -Name "RemoteRegistry" -StartupType Disabled
Set-Service -Name "RetailDemo" -StartupType Manual
Set-Service -Name "RmSvc" -StartupType Manual
Set-Service -Name "RpcEptMapper" -StartupType Automatic
Set-Service -Name "RpcLocator" -StartupType Manual
Set-Service -Name "RpcSs" -StartupType Automatic
Set-Service -Name "SCPolicySvc" -StartupType Manual
Set-Service -Name "SCardSvr" -StartupType Manual
Set-Service -Name "SDRSVC" -StartupType Manual
Set-Service -Name "SEMgrSvc" -StartupType Manual
Set-Service -Name "SENS" -StartupType Automatic
Set-Service -Name "SNMPTRAP" -StartupType Manual
Set-Service -Name "SNMPTrap" -StartupType Manual
Set-Service -Name "SSDPSRV" -StartupType Manual
Set-Service -Name "SamSs" -StartupType Automatic
Set-Service -Name "ScDeviceEnum" -StartupType Manual
Set-Service -Name "Schedule" -StartupType Automatic
Set-Service -Name "SecurityHealthService" -StartupType Manual
Set-Service -Name "Sense" -StartupType Manual
Set-Service -Name "SensorDataService" -StartupType Manual
Set-Service -Name "SensorService" -StartupType Manual
Set-Service -Name "SensrSvc" -StartupType Manual
Set-Service -Name "SessionEnv" -StartupType Manual
Set-Service -Name "SharedAccess" -StartupType Manual
Set-Service -Name "SharedRealitySvc" -StartupType Manual
Set-Service -Name "ShellHWDetection" -StartupType Automatic
Set-Service -Name "SmsRouter" -StartupType Manual
Set-Service -Name "Spooler" -StartupType Automatic
Set-Service -Name "SstpSvc" -StartupType Manual
Set-Service -Name "StiSvc" -StartupType Manual
Set-Service -Name "StorSvc" -StartupType Automatic
Set-Service -Name "SysMain" -StartupType Automatic
Set-Service -Name "SystemEventsBroker" -StartupType Automatic
Set-Service -Name "TabletInputService" -StartupType Manual
Set-Service -Name "TapiSrv" -StartupType Manual
Set-Service -Name "TermService" -StartupType Automatic
Set-Service -Name "Themes" -StartupType Automatic
Set-Service -Name "TieringEngineService" -StartupType Manual
Set-Service -Name "TimeBroker" -StartupType Manual
Set-Service -Name "TimeBrokerSvc" -StartupType Manual
Set-Service -Name "TokenBroker" -StartupType Manual
Set-Service -Name "TrkWks" -StartupType Automatic
Set-Service -Name "TroubleshootingSvc" -StartupType Manual
Set-Service -Name "TrustedInstaller" -StartupType Manual
Set-Service -Name "UI0Detect" -StartupType Manual
Set-Service -Name "UdkUserSvc_*" -StartupType Manual
Set-Service -Name "UevAgentService" -StartupType Disabled
Set-Service -Name "UmRdpService" -StartupType Manual
Set-Service -Name "UnistoreSvc_*" -StartupType Manual
Set-Service -Name "UserDataSvc_*" -StartupType Manual
Set-Service -Name "UserManager" -StartupType Automatic
Set-Service -Name "UsoSvc" -StartupType Automatic
Set-Service -Name "VGAuthService" -StartupType Automatic
Set-Service -Name "VMTools" -StartupType Automatic
Set-Service -Name "VSS" -StartupType Manual
Set-Service -Name "VacSvc" -StartupType Manual
Set-Service -Name "VaultSvc" -StartupType Automatic
Set-Service -Name "W32Time" -StartupType Manual
Set-Service -Name "WEPHOSTSVC" -StartupType Manual
Set-Service -Name "WFDSConMgrSvc" -StartupType Manual
Set-Service -Name "WMPNetworkSvc" -StartupType Manual
Set-Service -Name "WManSvc" -StartupType Manual
Set-Service -Name "WPDBusEnum" -StartupType Manual
Set-Service -Name "WSService" -StartupType Manual
Set-Service -Name "WSearch" -StartupType Automatic
Set-Service -Name "WaaSMedicSvc" -StartupType Manual
Set-Service -Name "WalletService" -StartupType Manual
Set-Service -Name "WarpJITSvc" -StartupType Manual
Set-Service -Name "WbioSrvc" -StartupType Manual
Set-Service -Name "Wcmsvc" -StartupType Automatic
Set-Service -Name "WcsPlugInService" -StartupType Manual
Set-Service -Name "WdNisSvc" -StartupType Manual
Set-Service -Name "WdiServiceHost" -StartupType Manual
Set-Service -Name "WdiSystemHost" -StartupType Manual
Set-Service -Name "WebClient" -StartupType Manual
Set-Service -Name "Wecsvc" -StartupType Manual
Set-Service -Name "WerSvc" -StartupType Manual
Set-Service -Name "WiaRpc" -StartupType Manual
Set-Service -Name "WinDefend" -StartupType Automatic
Set-Service -Name "WinHttpAutoProxySvc" -StartupType Manual
Set-Service -Name "WinRM" -StartupType Manual
Set-Service -Name "Winmgmt" -StartupType Automatic
Set-Service -Name "WlanSvc" -StartupType Automatic
Set-Service -Name "WpcMonSvc" -StartupType Manual
Set-Service -Name "WpnService" -StartupType Automatic
Set-Service -Name "WpnUserService_*" -StartupType Automatic
Set-Service -Name "XblAuthManager" -StartupType Manual
Set-Service -Name "XblGameSave" -StartupType Manual
Set-Service -Name "XboxGipSvc" -StartupType Manual
Set-Service -Name "XboxNetApiSvc" -StartupType Manual
Set-Service -Name "autotimesvc" -StartupType Manual
Set-Service -Name "bthserv" -StartupType Manual
Set-Service -Name "camsvc" -StartupType Manual
Set-Service -Name "cbdhsvc_*" -StartupType Automatic
Set-Service -Name "cloudidsvc" -StartupType Manual
Set-Service -Name "dcsvc" -StartupType Manual
Set-Service -Name "defragsvc" -StartupType Manual
Set-Service -Name "diagnosticshub.standardcollector.service" -StartupType Manual
Set-Service -Name "diagsvc" -StartupType Manual
Set-Service -Name "dmwappushservice" -StartupType Manual
Set-Service -Name "dot3svc" -StartupType Manual
Set-Service -Name "edgeupdate" -StartupType Automatic
Set-Service -Name "edgeupdatem" -StartupType Manual
Set-Service -Name "embeddedmode" -StartupType Manual
Set-Service -Name "fdPHost" -StartupType Manual
Set-Service -Name "fhsvc" -StartupType Manual
Set-Service -Name "gpsvc" -StartupType Automatic
Set-Service -Name "hidserv" -StartupType Manual
Set-Service -Name "icssvc" -StartupType Manual
Set-Service -Name "iphlpsvc" -StartupType Automatic
Set-Service -Name "lfsvc" -StartupType Manual
Set-Service -Name "lltdsvc" -StartupType Manual
Set-Service -Name "lmhosts" -StartupType Manual
Set-Service -Name "mpssvc" -StartupType Automatic
Set-Service -Name "msiserver" -StartupType Manual
Set-Service -Name "netprofm" -StartupType Manual
Set-Service -Name "nsi" -StartupType Automatic
Set-Service -Name "p2pimsvc" -StartupType Manual
Set-Service -Name "p2psvc" -StartupType Manual
Set-Service -Name "perceptionsimulation" -StartupType Manual
Set-Service -Name "pla" -StartupType Manual
Set-Service -Name "seclogon" -StartupType Manual
Set-Service -Name "shpamsvc" -StartupType Disabled
Set-Service -Name "smphost" -StartupType Manual
Set-Service -Name "spectrum" -StartupType Manual
Set-Service -Name "sppsvc" -StartupType Automatic
Set-Service -Name "ssh-agent" -StartupType Disabled
Set-Service -Name "svsvc" -StartupType Manual
Set-Service -Name "swprv" -StartupType Manual
Set-Service -Name "tiledatamodelsvc" -StartupType Automatic
Set-Service -Name "tzautoupdate" -StartupType Disabled
Set-Service -Name "uhssvc" -StartupType Disabled
Set-Service -Name "upnphost" -StartupType Manual
Set-Service -Name "vds" -StartupType Manual
Set-Service -Name "vm3dservice" -StartupType Automatic
Set-Service -Name "vmicguestinterface" -StartupType Manual
Set-Service -Name "vmicheartbeat" -StartupType Manual
Set-Service -Name "vmickvpexchange" -StartupType Manual
Set-Service -Name "vmicrdv" -StartupType Manual
Set-Service -Name "vmicshutdown" -StartupType Manual
Set-Service -Name "vmictimesync" -StartupType Manual
Set-Service -Name "vmicvmsession" -StartupType Manual
Set-Service -Name "vmicvss" -StartupType Manual
Set-Service -Name "vmvss" -StartupType Manual
Set-Service -Name "wbengine" -StartupType Manual
Set-Service -Name "wcncsvc" -StartupType Manual
Set-Service -Name "webthreatdefsvc" -StartupType Manual
Set-Service -Name "webthreatdefusersvc_*" -StartupType Automatic
Set-Service -Name "wercplsupport" -StartupType Manual
Set-Service -Name "wisvc" -StartupType Manual
Set-Service -Name "wlidsvc" -StartupType Manual
Set-Service -Name "wlpasvc" -StartupType Manual
Set-Service -Name "wmiApSrv" -StartupType Manual
Set-Service -Name "workfolderssvc" -StartupType Manual
Set-Service -Name "wscsvc" -StartupType Automatic
Set-Service -Name "wuauserv" -StartupType Manual
Set-Service -Name "wudfsvc" -StartupType Manual

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
