#!/bin/bash

# ---------------------------------------
# this defines the apache configuration for the wordpress site you're about to make

# command after the 'or' executes if the command before 'or' returns non-zero
systemctl is-active --quiet apache2 || service apache2 start

a2enmod rewrite
a2dissite 000-default
cp wordpress.conf /etc/apache2/sites-available
a2ensite wordpress.conf --quiet

service apache2 reload

# ----------------------------------------
# Now you gotta install Wordpress CLI. This command downloads the PHAR.
# PHARs are PHp ARchives. THe compact nature of Java and the stability of PHP. What's not to love?
curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar --silent

# Now we're gonna add it to your path!

chmod +x wp-cli.phar
mv wp-cli.phar /usr/local/bin/wp

# Now we've set up Wordpress CLI.
# ----------------------------------------

# Next we're gonna use it to install Wordpress.
# 1. Download the core wordpress program - wp core download
# 2. Create a config file for the database information - we config create
# 3. Make the database - we db create
# 4. Create the website! - wp core install

# NOTE1: We're deviating from this. We are manually calling MySQL to create the database and users, because of idiosycracies on current systems. The theoretical ideal install commands are preserved below.

# NOTE2: This script is expected to be run at superuser privs, and wordpress does not like that, so just to be extra cautious, we're using sudo to *deescalate* priviliges and perform install actions as the current user and not root.

# 1 - Download the core wordpress program
# does the www directory exist? if not,
if [ ! -d "/srv/www" ]; then
    mkdir /srv/www
fi

# make sure the regular user can r/w the wordpress install normally
chown -R $SUDO_USER /srv/www .*
sudo --user=$SUDO_USER wp core download --path=/srv/www/wordpress/ --quiet

# mysql_initialization

# same elegant 'or' operation as apache to start mysql if not active already
systemctl is-active --quiet mysql || service mysql start

# 2. create the database & user and grant appropriate privs to the user
# this step is supposed to be taken after setting the config file. However, directly calling MySQL has resolved multiple permissions issues regarding db create and config setups for current systems. COMMENT THIS OUT IF YOU ARE ON A SYSTEM WITHOUT SQL
mysql -uroot -Bse "CREATE DATABASE IF NOT EXISTS wordpress; CREATE USER IF NOT EXISTS 'wordpressuser'@'%' IDENTIFIED BY 'password'; GRANT ALL PRIVILEGES ON wordpress.* to 'wordpressuser'@'%';"

# Create a config file on which the database would theoretically be based. COMMENT THIS OUT IF YOU ARE ON A SYSTEM WITHOUT SQL
sudo --user=$SUDO_USER wp config create --dbname=wordpress --dbuser=wordpressuser --dbpass=password --path=/srv/www/wordpress --quiet

# UNCOMMENT IF YOU ARE ON A SYSTEM WITHOUT SQL
# Uncomment (and change 'from' location if necessary) if you're on a system that doesn't have a SQL install.
# cp wp-config.php /srv/www/wordpress/

# The following command is an *alternative* to the mysql statement above - it *also* requires SQL. It is the standard command but resulted in strange errors / permissions issues. We are instead using the mysql -uroot command above.
# sudo --user=$SUDO_USER wp db create --path=/srv/www/wordpress

# 4 - Make the website
sudo --user=$SUDO_USER wp core install --url=localhost --title="Welcome to my blog!" --admin_user=wpcli --admin_password=wpcli --admin_email=placeholder@mail.mail --skip-email --path=/srv/www/wordpress
# That's a throwaway email; turns out --admin-email is a required parameter. However, per the next parameter, nothing's gonna get sent to it.

# ----------------------------------------

# Core Install command is called above without a --quiet parameter so that it prints a "Wordpress install complete" message for the user. Thus ends the script.

# CTI REFERENCES
# Known adversary use of compromised Wordpress blogs
# https://unit42.paloaltonetworks.com/unit42-kazuar-multiplatform-espionage-backdoor-api-access/
# Use of wordpress blogs as staging bays for malicious downloads
# https://securelist.com/the-epic-turla-operation/65545/
