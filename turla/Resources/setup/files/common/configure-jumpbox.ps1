# ---------------------------------------------------------------------------
# configure-jumpbox.ps1 - configure jumpbox, create users, set dns

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: configure-jumpbox.ps1

# ---------------------------------------------------------------------------


$userList = "Operator1", "Operator2", "Operator3", "Operator4", "Operator5", "Operator6"
$Password = ConvertTo-SecureString "Passw@rd1!" -AsPlainText -Force
$rangeDns = "91.52.201.22"

# Disable password expiration for accounts
foreach ($usr in $userList) {
    Write-Host "Setting account: $uname"
    New-LocalUser $usr -Password $Password -FullName $usr -Description "$usr"
    Write-Host "Setting account: $uname"
    Set-LocalUser $usr -PasswordNeverExpires $true -Verbose
    Write-Host "Adding new user: $usr to Admin group..."
    Add-LocalGroupMember -Group "Administrators" -Member $usr
    Add-LocalGroupMember -Group "Remote Desktop Users"  -Member $usr
}

Get-DnsClient | Set-DnsClientServerAddress -ServerAddresses ($rangeDns)
