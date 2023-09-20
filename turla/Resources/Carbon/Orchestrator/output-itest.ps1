 # ---------------------------------------------------------------------------
 # Carbon Orchestrator and Communications Library integration testing script with output
 # Useful if you would like to run carbon without installing it, or would like to see console output

 # Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
 # Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

 # http://www.apache.org/licenses/LICENSE-2.0

 # Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 # This project makes use of ATT&CK®
 # ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 
 
 # Usage: output-itest.ps1
 # Must be run from inside the "Orchestrator" folder and run with Administrator permissions
 
 # Revision History:
 
 # --------------------------------------------------------------------------- 

# orchcestrator and comms lib integration testing script with output for carbon

$workingDir = "C:\Program Files\Windows NT"
$startDir = $pwd

Write-Host "[CARBON] Beginning Carbon integration testing with output"
Write-Host "[CARBON] This script is meant to be run from \turla\Resources\Carbon\Orchestrator as admin. Not doing so may break it"
Write-Host "[CARBON] Also make sure any config files are pointing to the correct C2 server"

Copy-Item ".\bin\MSSVCCFG.dll" ".\resources\MSSVCCFG.dll" -Force

Write-Host "[CARBON] Checking for required files in turla\Resources\Carbon\Orchestrator\resources"
if (!(Test-Path -Path ".\resources\MSSVCCFG.DLL")) {
    Write-Error "[CARBON] Unable to find orchestrator dll 'MSSVCCFG.DLL', exiting"
    Write-Host "[CARBON] This can be found in 'Resources/Carbon/Orchestrator/bin/MSSVCCFG.DLL'"
    exit
}
if (!(Test-Path -Path ".\resources\MSXHLP.dll")) {
    Write-Error "[CARBON] Unable to find comms lib dll 'MSXHLP.dll', exiting"
    Write-Host "[CARBON] This can be found in 'Resources/Carbon/CommLib/bin/commlib.dll' and needs to be renamed"
    exit
}
if (!(Test-Path -Path ".\resources\setuplst.xml")) {
    Write-Error "[CARBON] Unable to find encrypted config 'setuplst.xml', exiting"
    Write-Host "[CARBON] This can be found in 'Resources/Carbon/Orchestrator/bin/setuplst.xml' and needs to be encrypted"
    Write-Host "[CARBON] You can encrypt the config by putting setuplst.xml in C:\Program Files\Windows NT\ and running 'Resources/Carbon/Orchestrator/bin/configEncrypt.exe' as admin"
    Write-Host "[CARBON] This will encrypt setuplst.xml (From Rob - I know this is a pain, just tell me if you want me to improve this)"
    exit
}

if (!(Test-Path -Path ".\resources\dllrunner.exe")) {
    Write-Error "[CARBON] Unable to find dll runner 'dllrunner.exe, exiting"
    Write-Host "[CARBON] This can be found in the resources repo (not turla) 'resources\Payloads\DllLoader\dllrunner.exe'"
    exit
}

# clean
Write-Host "[CARBON] Killing Chrome and cleaning working directory"
Remove-Item -Path "$workingDir\MSSVCCFG.DLL" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$workingDir\setuplst.xml" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$workingDir\MSXHLP.dll" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$workingDir\bootinfo.dat" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$workingDir\history.jpg" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$workingDir\commslib.dll" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$workingDir\dllrunner.exe" -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path "$workingDir\0511" -Recurse | ForEach-Object {$_.Delete()}
Get-ChildItem -Path "$workingDir\2028" -Recurse | ForEach-Object {$_.Delete()}
Get-ChildItem -Path "$workingDir\Nlts" -Recurse | ForEach-Object {$_.Delete()}
Remove-Item -Path "$workingDir\0511" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$workingDir\2028" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$workingDir\Nlts" -Force -ErrorAction SilentlyContinue

# make dirs
Write-Host "[CARBON] Making directories in the working directory"
New-Item -Path $workingDir -Name "0511" -ItemType "directory"
New-Item -Path $workingDir -Name "2028" -ItemType "directory"
New-Item -Path $workingDir -Name "Nlts" -ItemType "directory"

# drop stuff
Write-Host "[CARBON] Copying over required files"
Copy-Item ".\resources\MSSVCCFG.DLL" "$workingDir\MSSVCCFG.DLL"
Copy-Item ".\resources\MSXHLP.dll" "$workingDir\commslib.dll" # commslib.dll instead of MSXHLP.dll so orch doesn't inject, don't want two of them running
Copy-Item ".\resources\setuplst.xml" "$workingDir\setuplst.xml"
Copy-Item ".\resources\dllrunner.exe" "$workingDir\dllrunner.exe"

# start carbon
Write-Host "[CARBON] Starting Carbon"
Start-Process powershell {
    & 'C:\Program Files\Windows NT\dllrunner.exe' 'C:\Program Files\Windows NT\commslib.dll'
}
Start-Process powershell {
    Set-Location $startDir
    .\bin\runner.exe
}

# wait for user input
$nothing = Read-Host "[CARBON] Carbon execution started. Once you're done, enter '1' to output logs."

# output logs
.\bin\castDecrypt.exe 'C:\Program Files\Windows NT\history.jpg'
.\bin\castDecrypt.exe 'C:\Program Files\Windows NT\bootinfo.dat'

# wait for user input
$nothing = Read-Host "[CARBON] Finished outputting logs. enter '1' to begin cleanup."

# cleanup
Write-Host "[CARBON] Stopping Carbon"
Get-Process -name runner | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process -name dllrunner | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "[CARBON] Cleaning working directory"
Remove-Item -Path "$workingDir\MSSVCCFG.DLL" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$workingDir\setuplst.xml" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$workingDir\lidufhlst2.xml" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$workingDir\MSXHLP.dll" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$workingDir\bootinfo.dat" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$workingDir\history.jpg" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$workingDir\commslib.dll" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$workingDir\dllrunner.exe" -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path "$workingDir\0511" -Recurse | ForEach-Object {$_.Delete()}
Get-ChildItem -Path "$workingDir\2028" -Recurse | ForEach-Object {$_.Delete()}
Get-ChildItem -Path "$workingDir\Nlts" -Recurse | ForEach-Object {$_.Delete()}
Remove-Item -Path "$workingDir\0511" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$workingDir\2028" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$workingDir\Nlts" -Force -ErrorAction SilentlyContinue

Write-Host "[CARBON] Execution complete"