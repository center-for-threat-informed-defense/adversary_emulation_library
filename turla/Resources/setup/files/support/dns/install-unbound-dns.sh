#!/usr/bin/env bash

# ---------------------------------------------------------------------------
# install-unbound-dns.sh - Install unbound dns server

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: install-unbound-dns.sh

# ---------------------------------------------------------------------------


# Check if running as sudo
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

apt-get update
apt-get install unbound -y
