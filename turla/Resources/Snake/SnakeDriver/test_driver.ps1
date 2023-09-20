 # ---------------------------------------------------------------------------
 # test_driver.ps1 - Test script intended to confirm infinityhook hooks are present and functional

 # Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
 # Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

 # http://www.apache.org/licenses/LICENSE-2.0

 # Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 # This project makes use of ATT&CK®
 # ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 
 
 # Usage: .\test_driver.ps1
 
 # Revision History:
 
 # --------------------------------------------------------------------------- 

$num_tests = 0
$num_success = 0
$num_failure = 0

$regkey = "HKLM:\SYSTEM\CurrentControlSet\Services\gusb"
$driver = "C:\Windows\`$NtUninstallQ608317`$\gusb.sys"

# Install our driver
.\run_driver.ps1 start

# Attempt to get our key - should be hidden
Get-ItemProperty -Path $regkey -ErrorVariable err -ErrorAction SilentlyContinue
if ($err) {
    Write-Host "SUCCESS: Registry Key query failed to find $regkey" -BackgroundColor "Green" -ForegroundColor "Black"
    $num_success++
}
else {
    Write-Host "FAILURE: Found registry key $regkey" -BackgroundColor "Red" -ForegroundColor "Black"
    $num_failure++
}
$num_tests++

# Attempt to access our driver file - Attempting to copy the file is a simple way to test access
$driver_copy = "tmp.sys"
Copy-Item $driver $driver_copy -ErrorVariable err -ErrorAction SilentlyContinue
if ($err){
    Write-Host "SUCCESS: Failed to access file $driver" -BackgroundColor "Green" -ForegroundColor "Black"
    $num_success++
}
else {
    Write-Host "FAILURE: Was able to access file $driver" -BackgroundColor "Red" -ForegroundColor "Black"
    Remove-Item $driver_copy
    $num_failure++
}
$num_tests++

# See if we can find our module in NtQuerySystemInformation
.\SnakeTester.exe
if (!$LASTEXITCODE){
    Write-Host "SUCCESS: Failed to find $driver in system module list" -BackgroundColor "Green" -ForegroundColor "Black"
    $num_success++
}
else {
    Write-Host "FAILURE: Was able to find $driver in system module list" -BackgroundColor "Red" -ForegroundColor "Black"
    $num_failure++
}
$num_tests++

# Uninstall driver
.\run_driver.ps1 stop

# Attempt to get our regkey - should now succeed
Get-ItemProperty -Path $regkey -ErrorVariable err -ErrorAction SilentlyContinue
if ($err) {
    Write-Host "FAILURE: Didn't find registry key after uninstall $regkey" -BackgroundColor "Red" -ForegroundColor "Black"
    $num_failure++
}
else {
    Write-Host "SUCCESS: Found registry key after uninstall $regkey" -BackgroundColor "Green" -ForegroundColor "Black"
    $num_success++
}
$num_tests++

# Attempt again to access our driver file - should now succeed
Copy-Item $driver $driver_copy -ErrorVariable err -ErrorAction SilentlyContinue
if ($err){
    Write-Host "FAILURE: Failed to access file $driver" -BackgroundColor "Red" -ForegroundColor "Black"
    $num_failure++
}
else {
    Write-Host "SUCCESS: Was able to access file $driver" -BackgroundColor "Green" -ForegroundColor "Black"
    Remove-Item $driver_copy
    $num_success++
}
$num_tests++

Write-Host "$num_tests : Number of tests"
Write-Host "$num_success : Number of passed tests"
Write-Host "$num_failure : Number of failed tests"