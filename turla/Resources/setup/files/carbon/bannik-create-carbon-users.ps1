# ---------------------------------------------------------------------------
# bannik-create-carbon-users.ps1 - create carbon users

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: bannik-create-carbon-users.ps1

# ---------------------------------------------------------------------------

# Create the Carbon scenario users

$userList = "evals_domain_admin", "evals_domain_user", "vendor_domain_admin", "vendor_domain_user", "Gunter", "Adalwolfa", "Frieda"

try{
    Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch{
    throw "Module ActiveDirectory not Installed"
    }

# Create AD Groups
New-ADGroup -Name "Employee Users" -GroupCategory Security -GroupScope Global
New-ADGroup -Name "Network Admin" -GroupCategory Security -GroupScope Global
New-ADGroup -Name "Web Server Admins" -GroupCategory Security -GroupScope Global
New-ADGroup -Name "Web Servers" -GroupCategory Security -GroupScope Global

# function to create users
function createSpecifiedUser {
    param($employeeId, $defaultPw, $uName, $uDesc, $uEnabled, $uEmail)
    New-ADUser -Name $uName -Description $uDesc  -Enabled $uEnabled -AccountPassword $defaultPw `
        -ChangePasswordAtLogon $false `
        -EmailAddress $uEmail -EmployeeID $employeeId
}



# Create vendor and eval domain accounts
$EvalsDomainAdminPassword = ConvertTo-SecureString "DuapQj7k8Va8U1X27rw6" –AsPlainText -Force
New-ADUser -Name "evals_domain_admin" -Description "Domain Admin account for evals team." -Enabled $true -AccountPassword $EvalsDomainAdminPassword

$EvalsDomainUserPassword = ConvertTo-SecureString "U9ZhdSKXQWhECY8Js9h9" –AsPlainText -Force
New-ADUser -Name "evals_domain_user" -Description "Domain User account for evals team." -Enabled $true -AccountPassword $EvalsDomainUserPassword

$VendorDomainAdminPassword = ConvertTo-SecureString "cYXDJ7DO2WUYupLybJSq" –AsPlainText -Force
New-ADUser -Name "vendor_domain_admin" -Description "Domain Admin account for vendor team." -Enabled $true -AccountPassword $VendorDomainAdminPassword

$VendorDomainUserPassword = ConvertTo-SecureString "XbG4431kAz5WLSVMYliV" –AsPlainText -Force
New-ADUser -Name "vendor_domain_user" -Description "Domain User account for vendor team." -Enabled $true -AccountPassword $VendorDomainUserPassword

$newId = Get-Random -Minimum $eidMin -Maximum $eidMax
$nonAdmin = ConvertTo-SecureString "Password1!" –AsPlainText -Force
createSpecifiedUser -employeeId $newId -defaultPw $nonAdmin -uName "Gunter" -uDesc "Employee" -uEnabled $true -uEmail "gunter@skt.local"

$netAdmin = ConvertTo-SecureString "Password2!" –AsPlainText -Force
$newId = Get-Random -Minimum $eidMin -Maximum $eidMax
createSpecifiedUser -employeeId $newId -defaultPw $netAdmin -uName "Adalwolfa" -uDesc "Web Admin" -uEnabled $true -uEmail "adalwolfa@skt.local"

$newId = Get-Random -Minimum $eidMin -Maximum $eidMax
$domainAdmin = ConvertTo-SecureString "Password3!" –AsPlainText -Force
createSpecifiedUser -employeeId $newId -defaultPw $domainAdmin -uName "Frieda" -uDesc "Local Admin" -uEnabled $true -uEmail "frieda@skt.local"

# Add scenario to groups
Add-AdGroupMember -Identity "Domain Admins" -Members evals_domain_admin,vendor_domain_admin,Frieda
Add-AdGroupMember -Identity "Employee Users" -Members Gunter
Add-AdGroupMember -Identity "Network Admin" -Members Adalwolfa
Add-AdGroupMember -Identity "Web Server Admins" -Members Adalwolfa

# Add admin user to Enterprise/Schema Admin groups to allow Exchange setup
Add-AdGroupMember -Identity "Schema Admins" -Members evals_domain_admin,vendor_domain_admin
Add-AdGroupMember -Identity "Enterprise Admins" -Members evals_domain_admin,vendor_domain_admin

# Disable password expiration for accounts
foreach ($usr in $userList) {
    $uname=$usr
    $ufull=$usr
    Write-Host "Setting account: $uname"
    Set-ADUser $usr -PasswordNeverExpires $true -Verbose
}
