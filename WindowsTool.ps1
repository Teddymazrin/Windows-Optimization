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
    Write-Host "5. Registry Changes"
    Write-Host "6. Nvidia"
    Write-Host "7. Default Services / Bare Gaming Services"
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
