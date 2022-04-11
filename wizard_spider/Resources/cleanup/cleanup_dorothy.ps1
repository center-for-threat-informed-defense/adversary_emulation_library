# kill emotet
taskkill /F /IM rundll32.exe

# delete emotet dropper code
Remove-Item $env:AppData\adb.vbs

# delete emotet DLL
Remove-Item $env:AppData\adb.dll

# delete outlook dll
Remove-Item C:\Windows\SysWOW64\Outlook.dll

# delete registry persistence
reg DELETE HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v blbdigital /F