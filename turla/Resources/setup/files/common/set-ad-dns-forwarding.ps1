# ---------------------------------------------------------------------------
# set-ad-dns-forwarding.ps1 - set ad dns forwarding

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: set-ad-dns-forwarding.ps1

# ---------------------------------------------------------------------------


# remove existing dns server forwarding configuration
Write-Host "Removing existing forwarder configuration..."
Get-DnsServerForwarder |select IPAddress| Remove-DnsServerForwarder -Force

# add stlouis as valid dns forwarder
Write-Host "Adding new forwarder configuration..."
Add-DnsServerForwarder -IPAddress 91.52.201.22

# print configuration
Write-Host "Printing forwarder configuration..."
Get-DnsServerForwarder

Write-Host "Clearing DNS server cache..."
Clear-DNSServerCache -Force
Clear-DnsClientCache
