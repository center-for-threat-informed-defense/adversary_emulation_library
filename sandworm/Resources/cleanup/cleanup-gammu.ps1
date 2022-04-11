# Remove registry persistence
reg.exe delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v SecurityHealth /f

# terminate processes
Stop-Process -Name "wsmprovav" -Force
Stop-Process -Name "rundll32" -Force
Stop-Process -Name "mslog" -Force

# delete filesystem artifacts
Remove-Item -Force "C:\Windows\wsmprovav.exe"
Remove-Item -Force "C:\Windows\wsmprovav.dll"
Remove-Item -Force "C:\Windows\System32\oradump.exe"
Remove-Item -Force "C:\Windows\System32\mslog.exe"
Remove-Item -Force "C:\Windows\System32\mslog.txt"