# Note: this script is invoked via sudo

# install apache web server and SSL module
# this is used for the PHP webshell TTPs
yum install httpd openssl php mod_ssl -y

# make firewall exceptions for HTTP and HTTPS, if required
# sudo firewall-cmd --permanent --add-service=http
# sudo firewall-cmd --permanent --add-service=https

# set apache web server to start on system boot
systemctl enable httpd

# relax SELinux to allow the apache user to write and execute files
# this command places SELinux in "audit only" mode for events originating from the apache user account
semanage permissive -a httpd_t

# restart apache to ensure TLS  and PHP modules load
systemctl restart httpd.service

# create directories needed for privEsc via SUID binary
mkdir -p /var/www/html/include/tools

# create check.sh, used for the SUID binary TTP
echo "ps auxf | grep -i httpd" > /var/www/html/include/tools/check.sh
echo "netstat -antp | grep -i httpd" >> /var/www/html/include/tools/check.sh
chmod 744 /var/www/html/include/tools/check.sh

# give apache user ownership of the html dir
chown -R apache:apache /var/www/html

# setup the SUID binary
mv /tmp/suid-binary /bin/backup
chown root:root /bin/backup
chmod 4755 /bin/backup

# generate SSH keys
ssh-keygen -t rsa -N '' -C 'SSH Key' -f '/home/fherbert/.ssh/id_rsa'

# Add some bash history activity to illustrate caladan connecting to gammu
printf "smbclient -U 'WORKGROUP\fherbert' //10.0.1.7/ADMIN$\n"