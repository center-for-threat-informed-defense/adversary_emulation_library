#!/bin/bash

# delete the wordpress files
echo "Deleting wordpress files"
rm -rf /srv/www/wordpress

# remove the apache config
echo "removing wordpress apache config"
a2dissite wordpress.conf
echo "restarting apache2"
service apache2 restart

#mysqlcleanpup
# delete the wordpress database
echo "dropping the wordpress database"
mysql -uroot -Bse "DROP DATABASE IF EXISTS wordpress;"
# delete the wordpress user
echo "dropping the wordpress user"
mysql -uroot -Bse "DROP USER IF EXISTS wordpressuser;"
#mysqlcleanup

#kill any background processes used in the site
echo "killing any processes named beef"
pgrep -f beef | xargs -r kill
