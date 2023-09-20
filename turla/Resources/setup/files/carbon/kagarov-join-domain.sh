#!/usr/bin/env bash

# ---------------------------------------------------------------------------
# kagarov-join-domain.sh - join domain

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: kagarov-join-domain.sh

# ---------------------------------------------------------------------------

if [[ $EUID > 0 ]]; then
  echo "Please run as root/sudo"
  exit 1
fi

echo "##########################################################################################"
echo "This script will leave skt.local domain, clear all sssd cache, rejoin skt.local domain, and test for success"
echo "You will be prompted for credentials for evals_domain_admin@skt.local user twice (once for leaving, once for rejoining)"
echo "##########################################################################################"
# note: will be prompted for carbon domain password twice (for leaving/rejoining domain)
realm leave -U evals_domain_admin skt.local

sss_cache -E
rm -f /var/lib/sss/db/{cache*,ccache*,timestamp*}

realm join -U evals_domain_admin skt.local

echo "print out group infor for Web Server Admins"
getent group "Web Server Admins@skt.local"

echo "print out adalwolfa group membership (web server admin group should be listed below"
id "adalwolfa@skt.local"
