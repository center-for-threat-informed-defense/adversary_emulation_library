#!/bin/bash

if [ "$EUID" -ne 0 ]
    then 
        echo "You must be root to run this script. Please rerun as sudo"
    else
        debconf-set-selections <<< "postfix postfix/mailname string dungeon.shirinfarhad.com"
        debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"

        # Install via apt-get
        apt-get install -y postfix ripmime mailutils procmail

        # Configure Postfix to use a maildir mailbox
        postconf -e "home_mailbox = Maildir/"

        # The following variables should be set to domain, IP and hostnames of your victim and attacker ranges
        # Configure postfix to use the domain 'shirinfarhad.com' and route mail to boom.box
        postconf -e "myorigin = shirinfarhad.com"
        postconf -e "myhostname = dungeon.shirinfarhad.com"
        postconf -e "relay_domains = boom.box, waterfalls.boom.box"
        postconf -e "mydestination = localhost.localdomain, localhost, shirinfarhad.com"
        echo "boombox.com     smtp:[10.1.0.6]" >> /etc/postfix/transport 

        # Restart postfix
        /etc/init.d/postfix restart

        # Update the firewall rules
        sudo ufw allow 'Postfix'
        sudo ufw allow 'Postfix SMTPS'
        sudo ufw allow 'Postfix Submission'

fi