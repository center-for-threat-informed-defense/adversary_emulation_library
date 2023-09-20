# ---------------------------------------------------------------------------
# berlios-create-snake-users.ps1 - create snake users

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: berlios-create-snake-users.ps1

# ---------------------------------------------------------------------------


# Create the Snake scenario users

$nonAdminUsr = "EgleAdmin"
$netAdminUsr = "ZilvinasAdmin"
$standardUsr1 = "Egle"
$standardUsr2 = "Zilvinas"

$domainSuffix = "nk.local"

$userList = "evals_domain_admin", "evals_domain_user", "vendor_domain_admin", "vendor_domain_user", $nonAdminUsr, $netAdminUsr, $domainAdminUsr, $standardUsr1, $standardUsr2

try{
    Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch{
    throw "Module ActiveDirectory not Installed"
    }

function createSpecifiedUser {
    param($employeeId, $defaultPw, $uName, $uDesc, $uEnabled, $uEmail)
    New-ADUser -Name $uName -Description $uDesc  -Enabled $uEnabled -AccountPassword $defaultPw `
        -ChangePasswordAtLogon $false `
        -EmailAddress $uEmail -EmployeeID $employeeId
}

# Create AD Groups
New-ADGroup -Name "File Server Admins" -GroupCategory Security -GroupScope Global

# Create vendor and eval domain accounts
# repetitive but prepping for conversion to automated loop to reduce duplication and simplifiy global changes
$newId = Get-Random -Minimum $eidMin -Maximum $eidMax
$EvalsDomainAdminPassword = ConvertTo-SecureString "DuapQj7k8Va8U1X27rw6" –AsPlainText -Force
createSpecifiedUser -employeeId $newId -defaultPw $EvalsDomainAdminPassword -uName "evals_domain_admin" -uDesc "Domain Admin account for evals team" -uEnabled $true -uEmail "evals_domain_admin@${domainSuffix}"

$newId = Get-Random -Minimum $eidMin -Maximum $eidMax
$EvalsDomainUserPassword = ConvertTo-SecureString "U9ZhdSKXQWhECY8Js9h9" –AsPlainText -Force
createSpecifiedUser -employeeId $newId -defaultPw $EvalsDomainUserPassword -uName "evals_domain_user" -uDesc "Domain User account for evals team" -uEnabled $true -uEmail "evals_domain_user@${domainSuffix}"

$newId = Get-Random -Minimum $eidMin -Maximum $eidMax
$VendorDomainAdminPassword = ConvertTo-SecureString "cYXDJ7DO2WUYupLybJSq" –AsPlainText -Force
createSpecifiedUser -employeeId $newId -defaultPw $VendorDomainAdminPassword -uName "vendor_domain_admin" -uDesc "Domain Admin account for vendor team" -uEnabled $true -uEmail "vendor_domain_admin@${domainSuffix}"

$newId = Get-Random -Minimum $eidMin -Maximum $eidMax
$VendorDomainUserPassword = ConvertTo-SecureString "XbG4431kAz5WLSVMYliV" –AsPlainText -Force
createSpecifiedUser -employeeId $newId -defaultPw $VendorDomainUserPassword -uName "vendor_domain_user" -uDesc "Domain User account for vendor team" -uEnabled $true -uEmail "vendor_domain_user@${domainSuffix}"

$newId = Get-Random -Minimum $eidMin -Maximum $eidMax
$nonAdminPassword = ConvertTo-SecureString "Producer1!" –AsPlainText -Force
createSpecifiedUser -employeeId $newId -defaultPw $nonAdminPassword -uName $nonAdminUsr -uDesc "File Server Admin" -uEnabled $true -uEmail "${nonAdminUsr}@${domainSuffix}"

$newId = Get-Random -Minimum $eidMin -Maximum $eidMax
$netAdminPassword = ConvertTo-SecureString "Producer2!" –AsPlainText -Force
createSpecifiedUser -employeeId $newId -defaultPw $netAdminPassword -uName $netAdminUsr -uDesc "Exchange Admin" -uEnabled $true -uEmail "${netAdminUsr}@${domainSuffix}"

$newId = Get-Random -Minimum $eidMin -Maximum $eidMax
$nonAdminPassword = ConvertTo-SecureString "Producer1!" –AsPlainText -Force
createSpecifiedUser -employeeId $newId -defaultPw $nonAdminPassword -uName $standardUsr1 -uDesc "User" -uEnabled $true -uEmail "${standardUsr1}@${domainSuffix}"

$newId = Get-Random -Minimum $eidMin -Maximum $eidMax
$netAdminPassword = ConvertTo-SecureString "Producer2!" –AsPlainText -Force
createSpecifiedUser -employeeId $newId -defaultPw $netAdminPassword -uName $standardUsr2 -uDesc "User" -uEnabled $true -uEmail "${standardUsr2}@${domainSuffix}"


# Add members to groups
Add-AdGroupMember -Identity "Domain Admins" -Members evals_domain_admin,vendor_domain_admin, $netAdminUsr
Add-AdGroupMember -Identity "Enterprise Admins" -Members evals_domain_admin, $netAdminUsr
Add-AdGroupMember -Identity "Schema Admins" -Members evals_domain_admin, $netAdminUsr

# Disable password expiration for accounts
foreach ($usr in $userList) {
    $uname=$usr
    $ufull=$usr
    Write-Host "Setting account: $uname"
    Set-AdUser $usr -PasswordNeverExpires $true -Verbose
}
