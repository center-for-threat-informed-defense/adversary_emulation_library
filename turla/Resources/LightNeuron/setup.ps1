 # ---------------------------------------------------------------------------
 # setup.ps1 - Sets up the Light Neuron implant locally on a Microsoft Exchange Server for testing

 # Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
 # Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

 # http://www.apache.org/licenses/LICENSE-2.0

 # Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 # This project makes use of ATT&CK®
 # ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 
 
 # Usage: setup.ps1
 
 # Revision History:
 
 # --------------------------------------------------------------------------- 

function Write-TestInfo() {
    param (
        $message
    )
    Write-Host $message -ForegroundColor Yellow
}

Write-TestInfo "Copying Transport Agent."
Copy-Item -Path "TransportAgent\Microsoft.Exchange.Transport.Agent.ConnectionFiltering\Microsoft.Exchange.Transport.Agent.ConnectionFiltering.dll" `
    -Destination "C:\Program Files\Microsoft\Exchange Server\v15\TransportRoles\agents\Hygiene\Microsoft.Exchange.Transport.Agent.ConnectionFiltering.dll"

Write-TestInfo "Copying Companion DLL."
Copy-Item -Path "CompanionDLL\data\exdbdata.dll" -Destination "C:\Program Files\Microsoft\Exchange Server\v15\bin\exdbdata.dll"

Write-TestInfo "Copying rule file."
Copy-Item -Path "CompanionDLL\data\rules.xml" -Destination "C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\msmdat.xml"

Write-TestInfo "Copying Config file."
Copy-Item -Path "CompanionDLL\data\winmail.dat" -Destination "C:\Program Files\Microsoft\Exchange Server\V15\Bin\winmail.dat"

Write-TestInfo "Installing Transport agent."
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn

Install-Transportagent -Name "Connection Filtering Agent" -AssemblyPath "C:\Program Files\Microsoft\Exchange Server\v15\TransportRoles\agents\Hygiene\Microsoft.Exchange.Transport.Agent.ConnectionFiltering.dll" -TransportAgentFactory Microsoft.Exchange.Transport.Agent.ConnectionFiltering.ConnectionFilteringAgentFactory

Enable-TransportAgent -Identity "Connection Filtering Agent"

Write-TestInfo "Restarting Service"
Restart-Service MSExchangeTransport

Write-TestInfo "Installation Complete."