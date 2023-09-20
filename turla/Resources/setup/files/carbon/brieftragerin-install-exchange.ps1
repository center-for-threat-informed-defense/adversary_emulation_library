# ---------------------------------------------------------------------------
# brieftragerin-install-exchange.ps1 - install exchange

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in 
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License 
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express 
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 

# Usage: brieftragerin-install-exchange.ps1

# --------------------------------------------------------------------------- 

# Script for installing Exchange mail server, requires being logged in as a Domain User

$OrganizationName = "skt"

# Install required roles
$baseFeatures = 'Server-Media-Foundation', 'WAS-Process-Model'
$webHttpFeatures = 'Web-Http-Errors', 'Web-Http-Logging', 'Web-Http-Redirect', 'Web-Http-Tracing'
$webSupportFeatures = 'Web-Asp-Net45', 'Web-Basic-Auth', 'Web-Client-Auth', 'Web-Digest-Auth', 'Web-Dir-Browsing', 'Web-Dyn-Compression'
$webAdminFeatures = 'Web-Server', 'Web-Stat-Compression', 'Web-Static-Content', 'Web-Windows-Auth', 'Web-WMI'
$webMgmtFeatures = 'Web-Metabase', 'Web-Mgmt-Console', 'Web-Mgmt-Compat', 'Web-Mgmt-Service'
$winFeatures = 'Web-Net-Ext45', 'Web-Request-Monitor', 'NET-Framework-45-Features', 'RPC-over-HTTP-proxy'
$rsatFeatures = 'RSAT-Clustering', 'RSAT-Clustering-CmdInterface', 'RSAT-Clustering-PowerShell', 'RSAT-ADDS'
$isapiFeatures = 'Web-ISAPI-Ext', 'Web-ISAPI-Filter'

###### Step 1 ######
# base feature install
foreach ($feature in $baseFeatures) { Install-WindowsFeature $feature }

# win and rsat
foreach ($feature in $winFeatures) { Install-WindowsFeature $feature }
foreach ($feature in $rsatFeatures) { Install-WindowsFeature $feature }

# web http and support
foreach ($feature in $webHttpFeatures) { Install-WindowsFeature $feature }
foreach ($feature in $webSupportFeatures) { Install-WindowsFeature $feature }

# web admin and mgmt
foreach ($feature in $webAdminFeatures) { Install-WindowsFeature $feature }
foreach ($feature in $webMgmtFeatures) { Install-WindowsFeature $feature }

# isapi
foreach ($feature in $isapiFeatures) { Install-WindowsFeature $feature }

# Install Microsoft Unified Communications Managed API 4.0
choco install -y ucma4 dotnetfx vcredist2012 msvisualcplusplus2013-redist urlrewrite


# Mount Exchange Server 2019 Installation Media
# Exchange Server 2019 Installation Media must be downloaded separately from Microsoft

$isoDrive = Mount-DiskImage -ImagePath "<DRIVELETTER>:\EXCHANGE2019.ISO"
$isoLetter = ($isoDrive | Get-Volume).DriveLetter
$setupExe = "${isoLetter}:\Setup.exe"

# Prepare Active Directory
& $setupExe /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /PrepareAD /OrganizationName:$OrganizationName

# Run installer
& $setupExe /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /mode:Install /role:Mailbox /OrganizationName:$OrganizationName

##### restart
Restart-Computer -Force
