# ---------------------------------------------------------------------------
# drebule-install-exchange.ps1 - install exchange

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: drebule-install-exchange.ps1

# ---------------------------------------------------------------------------


# Script for installing Exchange mail server, requires being logged in as a Domain User

$OrganizationName = "nk"

# Install required roles
Install-WindowsFeature Server-Media-Foundation, RSAT-ADDS
Install-WindowsFeature Server-Media-Foundation, NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Compat, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, RSAT-ADDS

# Install Microsoft Unified Communications Managed API 4.0
choco install -y ucma4 dotnetfx vcredist2012 msvisualcplusplus2013-redist urlrewrite

# Mount Azure Fileshare with Exchange 2019 Installation Media

$connectTestResult = Test-NetConnection -ComputerName sharedevalstorage.file.core.windows.net -Port 445
if ($connectTestResult.TcpTestSucceeded) {
    # Save the password so the drive will persist on reboot
    cmd.exe /C "cmdkey /add:`"sharedevalstorage.file.core.windows.net`" /user:`"localhost\sharedevalstorage`" /pass:`"lpB1PV1KgzymtmoSS3wM9XDfmKcUrb35VB++wdnLiP3Nji9J+s4gQDOzaHhA7D9JUAip3u55RmdS1zpYrP0TYA==`""
    # Mount the drive
    New-PSDrive -Name Z -PSProvider FileSystem -Root "\\sharedevalstorage.file.core.windows.net\exchange2019" -Persist
} else {
    Write-Error -Message "Unable to reach the Azure storage account via port 445. Check to make sure your organization or ISP is not blocking port 445, or use Azure P2S VPN, Azure S2S VPN, or Express Route to tunnel SMB traffic over a different port."
}

# Mount Exchange Server 2019 Installation Media
# Exchange Server 2019 Installation Media must be downloaded separately from Microsoft

$OrganizationName = "nk"
$isoDrive = Mount-DiskImage -ImagePath "<DRIVELETTER:\EXCHANGE2019.ISO"
$isoLetter = ($isoDrive | Get-Volume).DriveLetter
$setupExe = "${isoLetter}:\Setup.exe"

& $setupExe /IAcceptExchangeServerLicenseTerms_DiagnosticDataON /PrepareAD /OrganizationName:$OrganizationName
& $setupExe /IAcceptExchangeServerLicenseTerms_DiagnosticDataON /mode:Install /role:Mailbox /OrganizationName:$OrganizationName
& $setupExe /IAcceptExchangeServerLicenseTerms_DiagnosticDataON /Role:ManagementTools /OrganizationName:$OrganizationName
