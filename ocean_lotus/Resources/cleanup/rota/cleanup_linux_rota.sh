#!/bin/bash
rm -rf ~/.config/au-tostart
rm -rf ~/.gvfsd/
rm -rf ~/.dbus
head -n 5 ~/.bashrc > ~/.bashrc.tmp # remove last 5 lines of bashrc
cp ~/.bashrc.tmp ~/.bashrc
rm ~/.bashrc.tmp
rm rf ~/.X11
ipcrm -M 0x0064b2e2

