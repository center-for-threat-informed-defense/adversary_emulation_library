# ---------------------------------------------------------------------------
# enable-exchange-for-domain-users.ps1 - enable exchange for domain users

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: enable-exchange-for-domain-users.ps1

# ---------------------------------------------------------------------------


# NOTE: You will get lots of red errors for users without email addresses, that is expected
Import-module activedirectory
get-aduser -Searchbase "CN=Users,DC=skt,DC=local"-filter 'Enabled -eq $true' -prop emailAddress| ForEach-Object {Enable-Mailbox -Identity $_.samaccountname -Alias $_.samaccountname |Set-Mailbox -EmailAddressPolicyEnabled $false -PrimarySmtpAddress $_.EmailAddress}

Import-module activedirectory
get-aduser -Searchbase "CN=Users,DC=nk,DC=local"-filter 'Enabled -eq $true' -prop emailAddress| ForEach-Object {Enable-Mailbox -Identity $_.samaccountname -Alias $_.samaccountname |Set-Mailbox -EmailAddressPolicyEnabled $false -PrimarySmtpAddress $_.EmailAddress}
