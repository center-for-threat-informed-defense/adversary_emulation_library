# ---------------------------------------------------------------------------
# brieftragerin-create-carbon-exchange-admin.ps1 - create carbon exchange admin

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: brieftragerin-create-carbon-exchange-admin.ps1

# ---------------------------------------------------------------------------

# Add necessary roles for Exchange Admin in Carbon scenario

$exchangeAdmin = "evals_domain_admin", "vendor_domain_admin"

Add-ADGroupMember -Identity "Schema Admins" -Members $exchangeAdmin
Add-ADGroupMember -Identity "Hygiene Management" -Members $exchangeAdmin
Add-ADGroupMember -Identity "Organization Management" -Members $exchangeAdmin
Add-ADGroupMember -Identity "Public Folder Management" -Members $exchangeAdmin
Add-ADGroupMember -Identity "Records Management" -Members $exchangeAdmin
Add-ADGroupMember -Identity "Server Management" -Members $exchangeAdmin
