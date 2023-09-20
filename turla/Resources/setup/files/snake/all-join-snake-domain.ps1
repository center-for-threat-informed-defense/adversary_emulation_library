# ---------------------------------------------------------------------------
# all-join-snake-domain.ps1 - Join Snake domain server

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: all-join-snake-domain.ps1

# ---------------------------------------------------------------------------


$username = "evals_domain_admin"
$DomainName = "nk"
$DomainControllerIP = "10.100.30.202"
$SecPassword = "DuapQj7k8Va8U1X27rw6" | ConvertTo-SecureString -AsPlainText -Force
# Set the execution Policy
Set-ExecutionPolicy -ExecutionPolicy "Bypass" -Scope "Process" -Force
Set-ExecutionPolicy -ExecutionPolicy "Bypass" -Scope "CurrentUser" -Force
Set-ExecutionPolicy -ExecutionPolicy "Bypass" -Scope "LocalMachine" -Force

# Set the DNS to DC
Get-DnsClient | Set-DnsClientServerAddress -ServerAddresses ($DomainControllerIP)
Get-DnsClient | Set-DnSClient -ConnectionSpecificSuffix "nk.local"

# Create our credential for joining the domain
$DomainCred = New-Object System.Management.Automation.PSCredential ("$DomainName\$($username)", $SecPassword)
# Allow storing of wdigest credentials
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /f /v UseLogonCredential /t REG_DWORD /d 1

# Configure firewall to allow smb
Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True

# Join the domain
Start-Sleep -seconds 30
Add-Computer -DomainName "NK.local" -Credential $DomainCred -Force

#enable WinRM default so Azure can do its thing
winrm quickconfig -quiet

Restart-Computer -Force
