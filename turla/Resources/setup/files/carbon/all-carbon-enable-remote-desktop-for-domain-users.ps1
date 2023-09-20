# ---------------------------------------------------------------------------
# all-carbon-enable-remote-desktop-for-domain-users.ps1 - enable remote desktop for domain users

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: all-carbon-enable-remote-desktop-for-domain-users.ps1

# ---------------------------------------------------------------------------


# Script to enable remote desktop for domain users
Import-Module ActiveDirectory

$domainName = "skt"
$remoteGroup = "Remote Desktop Users"
$domainUsers = "${domainName}\Domain Users"

Add-LocalGroupMember -Group $remoteGroup -Member $domainUsers
