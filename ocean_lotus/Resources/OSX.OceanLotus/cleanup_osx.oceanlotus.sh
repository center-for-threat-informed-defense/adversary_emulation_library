#!/bin/bash

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

dropped_files=("$HOME/Library/LaunchAgents/com.apple.launchpad" "$HOME/Library/WebKit/com.apple.launchpad" "$1/Decoy.doc")
for path in "${dropped_files[@]}"
do
    check_file_exists $path
done

printf "[+] Removing any .log files in /tmp\n"
rm /tmp/*.log

TEXTEDIT_PID=$(ps aux | grep '[T]extEdit' | awk '{print $2}')
if [[ $TEXTEDIT_PID -gt 0 ]] ; then
    printf "[+] TextEdit found, killing...\n"
    kill $TEXTEDIT_PID
fi

