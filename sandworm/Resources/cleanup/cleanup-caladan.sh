# Run this script with sudo

# Cleanup Exaramel-Linux systemd persistence
systemctl disable syslogd.service
systemctl stop syslogd.service
rm -f /etc/systemd/system/syslogd.service

# Cleanup Exaramel Linux
# Exaramel-Linux seems to ignore pkill signals, so we do this
# gross 1 liner to get its pid and terminate it with kill -9
PID=`sudo ps aux | grep -i cent | grep root | awk '{print $2}'`
kill -9 $PID
rm -f /var/www/html/centreon_module_linux_app64

# Cleanup Exaramel-Linux crontab persistence
crontab -r

# Cleanup Exaramel-Linux socket
rm -f /var/www/html/configtx.json

# cleanup php webshell
rm -f /var/www/html/search.php

# cleanup check.sh
printf "ps auxf | grep -i httpd\nnetstat -antp | grep -i httpd\n" > /var/www/html/include/tools/check.sh