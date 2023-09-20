#!/user/bin/python3

import subprocess
import argparse
import os
import ipaddress

# nice terminal output codes
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

# define the home path where installation is taking place
if (os.environ["HOME"]):
    home_path = os.environ["HOME"]
else:
    # which user are we today?
    output_logon = subprocess.run("whoami", capture_output=True, text=True)
    home_path = "/home/" + output_logon.stdout

# what are the current beef username and password? Find the lines.
# username
file_process = subprocess.Popen(["find", home_path, "-path", "*/beef-master/config.yaml"], stdout=subprocess.PIPE)

beef_config_location = file_process.stdout.read().decode("utf-8").strip()
user_result = subprocess.run(["grep", "user", beef_config_location], capture_output=True, text=True)

# password
pass_result = subprocess.run(["grep", "passwd", beef_config_location], capture_output=True, text=True)

# hook name
hook_result = subprocess.run(["grep", "hook_session_name", beef_config_location], capture_output=True, text=True)

# quick error handling here

if (user_result.returncode == 123) or (pass_result.returncode == 123):
    print(f"{bcolors.FAIL}Config file not found - maybe beef-master was moved or you're running this script from a different location. This script checks to see if you've changed default creds in BEEF's config, which is necessary.")
    exit()
# grab the actual results off the strings

beef_username = user_result.stdout.strip().split('"')[1]
beef_password = pass_result.stdout.strip().split('"')[1]
beef_hookname = hook_result.stdout.strip().split('"')[1]

print("Current BEEF username is {}".format(beef_username))
print("Current BEEF password is {}".format(beef_password))
print("Current BEEF hook name is {}".format(beef_hookname))

if (beef_username == "beef"):
    print(f"{bcolors.FAIL}Change the username in beef-master/config.yaml, beef won't run with default creds.")
else:
    print(f"{bcolors.OKGREEN}Username confirmed updated.")
if (beef_password == "beef"):
    print(f"{bcolors.FAIL}Change the password in beef-master/config.yaml, beef won't run with default creds.")
else:
    print(f"{bcolors.OKGREEN}Password confirmed updated.")
if (beef_hookname == "ec"):
    print(f"{bcolors.OKGREEN}Hook session name updated to ec.")
else:
    print(f"{bcolors.FAIL}Please change hook_session_name in config.yaml to `ec`")

print(f"{bcolors.WARNING}Please update your in-range.html file to confirm that it accurately reflects the current location of hook.js, which is determined via beef-master/config.yaml and defaults to [your IP address]:3000/hook.js.")

# Note: pulled python color terminal printing from https://stackoverflow.com/questions/287871/how-do-i-print-colored-text-to-the-terminal
