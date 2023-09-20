#!/usr/bin/env bash

# ---------------------------------------------------------------------------
# kali-send-email.sh - send scenario email

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: kali-send-email.sh

# ---------------------------------------------------------------------------

SUBJECT=send-email
VERSION=0.1.0

echoerr() { printf "%s\n" "$*" >&2 ; }
log()    { echoerr "[LOG]    $*" ; }

recipient_email="gunter@skt.local"
sender_email="noreply@sktlocal.it"
sender_name="NoReply"
email_subject="[!] Emergency System Update"
content_type="Content-Type: text/html"
smtp_server="stamp.innovationmail.net"
# not required on range
# smtp_username="dev"
# smtp_password="DevPass12345"

email_body=$(cat <<'MESSAGE'
<html>
<p><b>EMERGENCY SYSTEM UPDATE REQUESTED</b>:</p>

Your system has been identified as running a vulnerable version of NotFlash.</p>
<p><b>Affected User: Gunter</b></p>

<p>Please click <a href="http://anto-int.com/NTFVersion.exe">here</a> to apply this update <b>IMMEDIATELY</b>. </p>
<p>Failure to comply in a timely manner will categorize your system in non-compliant status and limit future accesses to internal network resources. </p>

<p>Sincerely,</p>
<p>IT</p>
</html>
MESSAGE
)

swaks --to ${recipient_email} --from ${sender_email} --server ${smtp_server} \
    --add-header "${content_type}" --header "From: ${sender_name} <${sender_email}>" --add-header "Subject: ${email_subject}" \
    --body "${email_body}"
