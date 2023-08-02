#!/bin/bash

# ---------------------------------------------------------------------------
# cleanup_osx.oceanlotus.sh - Cleanup script for OSX.OceanLotus implant

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

dropped_files=("$HOME/Library/WebKit/com.apple.launchpad" "$1/Decoy.doc" "/tmp/store")
for path in "${dropped_files[@]}"
do
    check_file_exists $path
done

launchctl unload -w ~/Library/LaunchAgents/com.apple.launchpad
printf "[+] Unloaded LaunchAgent persistence\n"

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

printf "[+] Removing any .log files in /tmp\n"
rm /tmp/*.log

ps aux | grep '[T]extEdit' | awk '{print $2}' | while read line; do
    printf "[+] TextEdit found, killing...\n"
    kill $line
done

ps aux | grep '[c]om.apple.launchpad' | awk '{print $2}' | while read line; do
    printf "[+] com.apple.launchpad found, killing...\n"
    kill $line
done
