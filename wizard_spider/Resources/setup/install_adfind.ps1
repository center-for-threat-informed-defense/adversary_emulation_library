Write-Host "[i] Installing adfind.exe"
Invoke-WebRequest -Uri "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1087.002/src/AdFind.exe" -OutFile C:\Windows\System32\adfind.exe