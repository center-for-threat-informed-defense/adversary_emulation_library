#!/bin/bash

# Enable password-less sudo
echo "[+] enabling password-less sudo for user Gfawkes"
printf "\ngfawkes            ALL = (ALL) NOPASSWD: ALL\n" >> /etc/sudoers

# Enable SSH port forwarding
echo "[+] enabling SSH port forwarding"
printf "\nGatewayPorts yes\n" >> /etc/ssh/sshd_config
systemctl restart sshd.service

# Add low privilege SSH user
echo "[+] adding user: <ssh_user>"
useradd -m <attacker_ssh_user>
echo <attacker_ssh_user>:<attacker_ssh_user_password> | chpasswd

# Enable Metasploit database
echo "[+] enabling MSF database"
systemctl enable postgresql
systemctl start postgresql

# Stage files
echo "[+] staging files for download"
mkdir /var/files
cp /home/<attacker>/carbanak/Resources/step7/Java-Update.exe /var/files/
cp /home/<attacker>/carbanak/Resources/step10/tightvnc-2.8.27-gpl-setup-64bit.msi /var/files/
cp /home/<attacker>/carbanak/Resources/step10/vnc-settings.reg /var/files/
chmod 777 -R /var/files

# Copy prop files to bankfileserver
echo "[+] copying files to bankfileserver"
scp /home/<attacker>/carbanak/Resources/step5/network-diagram-financial.xml <domain_admin>@<bankfileserver_ip>:/var/tmp/network-diagram-financial.xml
scp /home/<attacker>/carbanak/Resources/step5/help-desk-ticket.txt <domain_admin>@<bankfileserver_ip>:/var/tmp/help-desk-ticket.txt

# Generate SSH key to bankfileserver
echo "[+] Generating SSH key"
ssh-keygen -t rsa -f "/home/<attacker>/carbanak/Resources/setup/ssh/id_rsa" -P ""

# copy SSH key to bankfileserver
echo "[+] Copying SSH public key to bankfileserver"
ssh-copy-id -i /home/<attacker>/carbanak/Resources/setup/ssh/id_rsa.pub <domain_admin>@<bankfileserver_ip>

# copy SSH keys to hrmanager
echo "[+] copying SSH keys to hrmanager"
smbclient -U '<domain_full>\<domain_admin>' //<hrmanager_ip>/C$ -c "put /home/<attacker>/carbanak/Resources/setup/ssh/id_rsa Users\\<domain_admin>.<domain>\\id_rsa; put /home/<attacker>/carbanak/Resources/setup/ssh/id_rsa.pub Users\\<domain_admin>.<domain>\\id_rsa.pub;"

# Copy setup scripts to Domain Controller
echo "[+] copying setup scripts to domain controller"
smbclient -U '<domain_full>\<domain_admin>' //<bankdc_ip>/C$ -c "put /home/<attacker>/carbanak/Resources/setup/set-defender.ps1 Users\\Public\\set-defender.ps1; put /home/<attacker>/carbanak/Resources/setup/set-OLEsecurity.ps1 Users\\Public\\set-OLEsecurity.ps1; put /home/<attacker>/carbanak/Resources/utilities/payment_transfer_system_delta.exe Users\\Public\\payment_transfer_system_delta.exe; put carbanak/Resources/setup/carbanak/setup-winhosts.ps1 Users\\Public\\setup-winhosts.ps1"

# Copy Payment Transfer System to CFO Workstation
echo "[+] copying setup scripts to domain controller"
smbclient -U '<domain_full>\<cfo_user>' //<cfo_ip>/C$ -c "put /home/<attacker>/carbanak/Resources/utilities/payment_transfer_system_delta.exe Users\\<cfo_user>.<domain>\\Desktop\payment_transfer_system_delta.exe;"