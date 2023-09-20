 # ---------------------------------------------------------------------------
 # lightneuron_cleanup.ps1 - Removes artifacts installed by LightNeuron

 # Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
 # Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

 # http://www.apache.org/licenses/LICENSE-2.0

 # Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 # This project makes use of ATT&CK®
 # ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 
 
 # Usage: lightneuron_cleanup.ps1
 
 # Revision History:
 
 # --------------------------------------------------------------------------- 

function Write-TestInfo() {
    param (
        $message
    )
    Write-Host $message -ForegroundColor Yellow
}
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
Write-TestInfo "Uninstall Service"

Disable-TransportAgent -Identity "Connection Filtering Agent" -Confirm:$false
Uninstall-TransportAgent -Identity "Connection Filtering Agent" -Confirm:$false

Stop-Service MSExchangeTransport

Remove-Item "C:\Program Files\Microsoft\Exchange Server\v15\TransportRoles\agents\Hygiene\Microsoft.Exchange.Transport.Agent.ConnectionFiltering.dll"
Remove-Item "C:\Windows\serviceprofiles\networkservice\appdata\Roaming\Microsoft\Windows\msxfer.dat"

Remove-Item "C:\Program Files\Microsoft\Exchange Server\v15\bin\exdbdata.dll"

Remove-Item "C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\tmp4C4E"
Remove-Item "C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\msmdat.xml"
Remove-Item "C:\Program Files\Microsoft\Exchange Server\V15\Bin\winmail.dat"

Write-TestInfo "Restarting Service"
Restart-Service MSExchangeTransport

Write-TestInfo "Teardown complete."

