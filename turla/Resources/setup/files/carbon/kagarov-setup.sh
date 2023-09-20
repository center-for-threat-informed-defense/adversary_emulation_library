#!/usr/bin/env bash

# ---------------------------------------------------------------------------
# kagarov-setup.sh - setup and install prereqs for joining domain

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: kagarov-setup.sh

# ---------------------------------------------------------------------------

# install pre-reqs for joining ubuntu host to domain
# join ubuntu host to domain

if [[ $EUID > 0 ]]; then
  echo "Please run as root/sudo"
  exit 1
fi

# configure DNS
sed -i 's/#Domains=/Domains=skt.local nk.local/g' /etc/systemd/resolved.conf
sed -i 's/#DNS=/DNS=10.20.10.9/g' /etc/systemd/resolved.conf
echo "10.20.10.9 bannik.skt.local bannik" >> /etc/hosts
systemctl restart systemd-resolved.service

# make hostname pretty
hostnamectl set-hostname kagarov.skt.local

# configure sudo
## add sudo perms for network admins
echo '%network\ admin@skt.local  ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/99-skt-sudo

# install needed deps
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y realmd libnss-sss libpam-sss sssd sssd-tools adcli samba-common-bin oddjob oddjob-mkhomedir packagekit apache2 etckeeper git wget

# perform some domain discovery, should detect skt domain
realm discover skt.local

# double check and print out current domain membership
realm list

# commented out version of domain join command if needed
# realm join -U evals_domain_admin skt.local
