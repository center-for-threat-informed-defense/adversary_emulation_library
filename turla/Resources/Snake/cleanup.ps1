 # ---------------------------------------------------------------------------
 # cleanup.ps1 - Attempts to clean up any artifacts left by Snake. Must be run from an Administrative command prompt

 # Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
 # Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

 # http://www.apache.org/licenses/LICENSE-2.0

 # Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 # This project makes use of ATT&CK®
 # ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 
 
 # Usage: [name of script] [flags]
 
 # Revision History:
 
 # --------------------------------------------------------------------------- 

$cleanup = "[CLEANUP]"
$installer_sc_name = "gigabit"
$driver_sc_name = "gusb"
$usermodule_name = "C:\Windows\msnrcv64t.dll"
$home_dir = "C:\Windows\`$NtUninstallQ608317`$"

function StopAndDeleteService {
    # Calls sc.exe to attempt to stop and delete a service that was previously created and started
    param (
        $servicename
    )
    Write-Host "$cleanup Attempting to stop $servicename"
    CMD /C "sc.exe stop $servicename"
    Write-Host "$cleanup Attempting to delete $servicename"
    CMD /C "sc.exe delete $servicename"
}

StopAndDeleteService($installer_sc_name)
StopAndDeleteService($driver_sc_name)

Write-Host "$cleanup Attempting to delete User Module DLL $usermodule_name"
Remove-Item $usermodule_name

Write-Host "$cleanup Attempting to delete $home_dir directory and all contents"
Remove-Item -Recurse -Force $home_dir