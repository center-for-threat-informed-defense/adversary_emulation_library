#!/bin/bash

# ---------------------------------------------------------------------------
# cleanup_osx.oceanlotus.sh - Cleanup script for OSX.OceanLotus implant

 # Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
 # Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

 # http://www.apache.org/licenses/LICENSE-2.0

 # Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 # This project makes use of ATT&CK®
 # ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 

# Usage: ./cleanup_osx.oceanlotus.sh [PATH]

# Revision History:

# ---------------------------------------------------------------------------

printf "Identified executing directory as: $1\n\n"

function check_file_exists () {
    if test -f "$1"; then
        printf "[+] $1 exists, removing...\n"
        rm $1
        if test -f "$1"; then
            printf "  [!] Failed to remove $1 \n"
        else
            printf "  [+] $1 was removed successfully\n"
        fi
    else
        printf "[-] $1 does not exist\n"
    fi
}

dropped_files=("$HOME/Library/WebKit/com.apple.launchpad" "$HOME/Library/WebKit/b2NlYW5sb3R1czIz" "$HOME/Library/WebKit/osx.download" "$1/conkylan.doc" "/tmp/store")
for path in "${dropped_files[@]}"
do
    check_file_exists $path
done

if [[ $(launchctl list | grep com.apple.launchpad) ]]; then
    printf "[+] Persistence found, removing...\n"
    launchctl unload -w $HOME/Library/LaunchAgents/com.apple.launchpad
    if [[ $(launchctl list | grep com.apple.launchpad) ]]; then
        printf "[!] Failed to unload LaunchAgent persistence\n"
    else
        printf "[+] Unloaded LaunchAgent persistence\n"
    fi
else
    printf "[-] Persistence not found\n"
fi




plist_dir="$HOME/Library/LaunchAgents/com.apple.launchpad"

if test -d "$plist_dir"; then
    printf "[+] $plist_dir directory exists, removing...\n"
    rm -rf $plist_dir
    if test -d "$plist_dir"; then
        printf "  [!] Failed to remove directory $plist_dir \n"
    else
        printf "  [+] $plist_dir directory was removed successfully\n"
    fi
else
    printf "[-] $plist_dir direstory does not exist\n"
fi

log_files=$(ls /tmp/*.log 1> /dev/null 2>&1)
if [[ $? != 0 ]]; then
    printf "[-] No /tmp/*.log files found\n"
elif [[ $log_files ]]; then
    printf "[+] Removing *.log files in /tmp\n"
    rm /tmp/*.log
else
    printf "[-] No /tmp/*.log files found\n"
fi

ps aux | grep '[T]extEdit' | awk '{print $2}' | while read line; do
    printf "[+] TextEdit found, killing...\n"
    kill $line
done

ps aux | grep '[c]om.apple.launchpad' | awk '{print $2}' | while read line; do
    printf "[+] com.apple.launchpad found, killing...\n"
    kill $line
done
