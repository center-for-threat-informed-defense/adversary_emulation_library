#!/usr/bin/env bash

# ---------------------------------------------------------------------------
# kali-prereqs.sh - Install and configure prereqs for attack platform

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: kali-prereqs.sh

# ---------------------------------------------------------------------------

# Check if running as sudo
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# make directories
mkdir -p /opt/{day1,day2,watering_hole}

# install packages
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y kali-desktop-xfce xorg xrdp augeas-{tools,lenses} git etckeeper
apt install -y postfix ripmime mailutils procmail swaks
apt install -y php php-mysql ruby default-mysql-server mariadb-client-10.6 mariadb-server-10.6 apache2

# add user
useradd cradwell -m
