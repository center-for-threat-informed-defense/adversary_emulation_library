# ---------------------------------------------------------------------------
# berlios-set-computer-descriptions.ps1 - set computer descriptions

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: berlios-set-computer-descriptions.ps1

# ---------------------------------------------------------------------------


# run on ad server
# Snake

Set-ADComputer -Identity "uosis" -Description "Zilvinas Workstation"
Set-ADComputer -Identity "azuolas" -Description "Egle Workstation"
Set-ADComputer -Identity "drebule" -Description "Exchange"
Set-ADComputer -Identity "berzas" -Description "File Server"
Set-ADComputer -Identity "berlios" -Description "AD Server"
