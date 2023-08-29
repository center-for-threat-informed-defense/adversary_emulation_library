#!/bin/bash
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
