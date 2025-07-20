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
	$downloadUrl = "https://adwcleaner.malwarebytes.com/adwcleaner?channel=release"
$downloadPath = "$env:TEMP\adwcleaner.exe"
$destinationFolder = "C:\Users\$env:USERNAME\Desktop\PC\AntiVirus"
$destinationPath = "$destinationFolder\adwcleaner.exe"

# Download the file
Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath

# Create the AntiVirus folder on the Desktop
New-Item -Path $destinationFolder -ItemType Directory -Force

# Move the file to the Desktop folder
Move-Item -Path $downloadPath -Destination $destinationPath -Force

# Optionally run it
Start-Process -FilePath $destinationPath -ArgumentList "/eula /clean" -Wait

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
    Write-Host "==========================================="
    $choice = Read-Host "Enter your choice"

        switch ($choice) {
        "1" { Option1 }
        "2" { Option2 }
        "3" { Option3 }
		"4" { Option4 }
        default { Write-Host "Invalid choice. Please try again." }
    }
}
