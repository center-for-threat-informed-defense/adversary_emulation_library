#!/usr/bin/python3

import argparse
import os
import subprocess
import sys

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

parser = argparse.ArgumentParser(description='Downloads the BEEF fingerprinting software, unzips it, and describes the necessary preparations your wordpress installation to hook an unsuspecting user.')
args = parser.parse_args()

# If there are any problems with the BEEF installation, full instructions separate from this script can be found here:
# https://github.com/beefproject/beef/blob/master/INSTALL.txt

# Download BEEF
subprocess.run(["wget", "https://github.com/beefproject/beef/archive/master.zip", "--quiet"], check=True)

# Initialize BEEF on machine
subprocess.run(["unzip", "-q", "master.zip"], check=True)
subprocess.run(["rm", "master.zip"], check=True)
os.chdir("beef-master")
subprocess.run(["ls"], check=True)
p1 = subprocess.Popen(["yes"], stdout=subprocess.PIPE)
p2 = subprocess.run(["./install", "-v"], stdin=p1.stdout)
os.chdir("..")

# Patch beef to output an md5 hash as session id instead of a random string
subprocess.run(["cp", "session.js", "beef-master/core/main/client/session.js"], check=True)

print(f"{bcolors.OKGREEN}BEEF should now be installed on your system, perhaps exiting with a message about updating Ruby.{bcolors.ENDC}")
print(f"{bcolors.WARNING}If you're running a default kali install or something similar, you might be missing a few ruby gems.{bcolors.ENDC}")

os.chdir("beef-master")

print(f"{bcolors.OKCYAN}Installing ruby dependencies{bcolors.ENDC}")
subprocess.run(["sudo", "gem", "install", "xmlrpc"], check=True)
subprocess.run(["sudo", "gem", "install", "unf"], check=True)
subprocess.run(["sudo", "gem", "install", "domain_name"], check=True)

print(f"{bcolors.OKCYAN}Running the bundle installation now:{bcolors.ENDC}")
subprocess.run(["bundle", "install"], check=True)
print(f"{bcolors.OKGREEN}All ruby dependencies successfully installed.\
\n\n{bcolors.WARNING}YOU MUST EDIT config.yaml.\
 Change hook_session_name to `ec`\
 and change the default username and password.\
\n\n{bcolors.UNDERLINE}You must change the default username and password, \
BEEF will not run with default creds.{bcolors.ENDC}\
\n\n{bcolors.WARNING}hook.js is located at [http_server_ip]:[port]/hook.js\n\n\
{bcolors.UNDERLINE}This defaults to [your IP address]:3000/hook.js, is configurable in\
 config.yaml, and should be updated in in-range.html.{bcolors.ENDC}\
\n\n{bcolors.OKGREEN}\n\nTo start BEEF, use the command\n\n./beef\
\n\n{bcolors.UNDERLINE}To access BEEF, the admin web panel is available at\
 http://localhost:3000/ui/panel unless you have changed its location in\
 config.yaml.{bcolors.ENDC}")

# Note: pulled python color terminal printing from https://stackoverflow.com/questions/287871/how-do-i-print-colored-text-to-the-terminal

# CTI References
# Use of evercookie (built into BEEF): https://recon.cx/2018/brussels/resources/slides/RECON-BRX-2018-Visiting-The-Snake-Nest.pdf
# USe of evercookie and list of other info grabbed (browser plugins, OS info, etc): https://www.welivesecurity.com/2020/03/12/tracking-turla-new-backdoor-armenian-watering-holes/
