# Description: Installs chocolatey to expedite package installs.
#Requires -RunAsAdministrator

# ---------------------------------------------------------------------------
# chocolatey-install.ps1 - Installs chocolatey package manager

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: chocolatey-install.ps1

# ---------------------------------------------------------------------------

Write-Host "[+] Installing Chocolatey"

Write-Host "  [-] Setting 'Get-ExecutionPolicy to unrestricted"
Set-ExecutionPolicy Bypass -Scope Process -Force

Write-Host "  [-] Enabling TLS 1.2"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

Write-Host "  [-] Pulling and installing package"
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

Write-Host "[+] Install Successful"

Write-Host "[+] Rebooting..."
Restart-Computer -Force
