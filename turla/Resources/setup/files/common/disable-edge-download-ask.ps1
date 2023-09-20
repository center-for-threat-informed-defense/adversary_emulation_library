# ---------------------------------------------------------------------------
# disable-edge-download-ask.ps1 - disable edge download ask

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: disable-edge-download-ask.ps1

# ---------------------------------------------------------------------------


Write-Host "Creating registry key to disable Edge what to do with each download prompt"

$RegItem = @{
    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    Name = 'PromptForDownloadLocation'
}

# Create path if missing
$Path = Get-Item -Path $RegItem.Path -ErrorAction SilentlyContinue
if ($null -eq $Path) { New-Item -Path $RegItem.Path }


if ($null -eq (Get-ItemProperty @RegItem -ErrorAction SilentlyContinue)) {
    New-ItemProperty @RegItem -Value "0" -PropertyType DWord -Force | Out-Null
    Write-Host 'added Registry value' -f red
} else {
    set-ItemProperty @RegItem -Value "0"
    Write-Host "set PromptForDownloadLocation value to 0"
}
