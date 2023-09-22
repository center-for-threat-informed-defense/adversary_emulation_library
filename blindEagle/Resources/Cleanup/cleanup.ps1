# cleanup.ps1
# Removes artifacts from C:\Windows\Temap and %APPDATA%\\Microsoft\Windows\Start Menu\Programs\Startup as part of the Blind Eagle emulation.

foreach ($file in Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -force) { if ($file.Name -eq 'notepad.lnk') { $file.Delete() } }
foreach ($file in Get-ChildItem "C:\Windows\Temp" -force) { if ($file.Name -eq 'OneDrive.vbs') { $file.Delete() } }