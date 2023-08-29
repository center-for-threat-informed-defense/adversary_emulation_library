#!/bin/bash

# ---------------------------------------------------------------------------
# cleanup_linux_rota.sh - Cleanup script for Rota Jakiro implant

 # Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
 # Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

 # http://www.apache.org/licenses/LICENSE-2.0

 # Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 # This project makes use of ATT&CK®
 # ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 

# Expected to execute from the /tmp folder on the infected linux host
# Usage: ./cleanup_linux_rota.sh

# Revision History:

# ---------------------------------------------------------------------------

rm -rf ~/.config/au-tostart
if [[ $? -eq 0 ]]; then
    echo "[+] Successfully removed au-tostart"
else

    echo "[!] Could not remove au-tostart"
fi
rm -rf ~/.gvfsd/
if [[ $? -eq 0 ]]; then
    echo "[+] Successfully removed .gvfsd folder"
else
    echo "[!] Could not remove .gvfsd folder"
fi
rm -rf ~/.dbus
if [[ $? -eq 0 ]]; then
    echo "[+] Successfully removed .dbus folder"
else
    echo "[!] Could not remove .dbus folder"
fi

head -n 5 ~/.bashrc > ~/.bashrc.tmp # remove last 5 lines of bashrc
cp ~/.bashrc.tmp ~/.bashrc
rm ~/.bashrc.tmp
if [[ $? -eq 0 ]]; then
    echo "[+] Successfully removed persistence in bashrc"
else
    echo "[!] Could not remove persistence in bashrc"
fi

# file locks
rm -rf ~/.X11/X0-lock
rm  ~/.X11/.X11-lock
if [[ $? -eq 0 ]]; then
    echo "[+] Successfully removed file locks"
else
    echo "[!] Could not removed file locks"
fi

ipcrm -M 0x0064b2e2
if [[ $? -eq 0 ]]; then
    echo "[+] Successfully removed IPC Sharedmemory Key"
else
    echo "[!] Could not removed IPC Sharedmemory Key"
fi
