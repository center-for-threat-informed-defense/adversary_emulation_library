# Enable PSRemoting and trust all hosts
Write-Host "[i] Enabling WinRM"
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# permit WMI through firewall
netsh advfirewall firewall add rule dir=in name="DCOM" action=allow protocol=TCP localport=135
netsh advfirewall firewall add rule dir=in name="WMI" program=%systemroot%\system32\svchost.exe service=winmgmt action=allow protocol=TCP localport=any