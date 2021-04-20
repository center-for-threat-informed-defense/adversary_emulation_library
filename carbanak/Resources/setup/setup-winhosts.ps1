
# Create CFO User
Write-Host "[+] Adding new AD user: <cfo_user>"
New-ADUser -Name <cfo_user> -Department "Finance" -Description "Chief Finance Officer" -EmailAddress "<cfo_user>@<domain_full>"
Set-ADComputer -Identity "cfo" -ManagedBy "CN=<cfo_user>,CN=Users,DC=<domain>,DC=<domain_tld>"
net user <cfo_user> /domain /active:yes Passw0rd!

# add RDP permissions
Write-Host "[+] giving <cfo_user> permissions needed for RDP"
Invoke-Command -Computer cfo -ScriptBlock {net.exe localgroup "Remote Desktop Users" <cfo_user> /add}
Invoke-Command -Computer cfo -ScriptBlock {net.exe localgroup "Remote Management Users" <cfo_user> /add}


# Disable Defender on all hosts
Write-Host "[+] Disabling Windows Defender throughout domain"
Invoke-Command -ComputerName hrmanager,cfo,bankdc -FilePath C:\Users\Public\set-defender.ps1

# Drop OLE Security
Write-Host "[+] Disabling OLE security on hrmanager"
Invoke-Command -ComputerName hrmanager -FilePath C:\Users\Public\set-OLEsecurity.ps1