#!/bin/bash

if [ "$EUID" -ne 0 ]
    then 
        echo "You must be root to run this script. Please rerun as sudo"
    else
        # Install apache via APT
        apt install -y apache2

        # Allow it through the firewall
        ufw allow 'Apache'

        systemctl restart apache2

        # Make sure to copy the 'Marketing_Materials.zip' to the /var/www/html/ directory so that it can be accessed by the adversary
        echo "\u001b[31mMake sure to copy the 'Marketing_Materials.zip' to the /var/www/html/ directory so that it can be accessed by the adversary"
fi