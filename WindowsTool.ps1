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

}

function Option6 {
Clear-Host
# Nvidia
    Write-Host "Nvidia Utilities" -ForegroundColor Yellow
    Write-Host "1. Update Nvidia Drivers"
    Write-Host "2. Uninstall Graphics Driver"
    Write-Host "3. Return to Main Menu"
    $subChoice = Read-Host "Enter your Nvidia option"

    switch ($subChoice) {
        "1" {
            Write-Host "Launching Nvidia driver update..." -ForegroundColor Cyan
            Start-Process "https://www.nvidia.com/en-us/drivers/"
        }
        "2" {
            Write-Host "Uninstalling Driver" -ForegroundColor Cyan
            Invoke-WebRequest -Uri "https://github.com/Teddymazrin/Windows-Optimization/raw/refs/heads/main/Programs/CleanupTool.exe" -OutFile "$env:TEMP/CleanupTool.exe"
	    Start-Process -FilePath "$env:TEMP/CleanupTool.exe"
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

Write-Host "Window Tool" -ForegroundColor Cyan

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
