@echo off

curl -o "%Temp%\SCEWIN.zip" "https://cdn.discordapp.com/attachments/1117130118125584414/1117138447002513419/SCEWIN.zip"
cd %Temp%
tar -xf SCEWIN.zip
timeout 3
del /f SCEWIN.zip
%SystemRoot%\explorer.exe "%Temp%\SCEWIN\Extract Settings.bat"
timeout 3
%SystemRoot%\explorer.exe "%Temp%\SCEWIN\BIOSSettings.txt"
%SystemRoot%\explorer.exe "%Temp%\SCEWIN"