#!/bin/bash
# ---------------------------------------------------------------------------
# execution_penquin_test - Bash shell script to test the execution of the Penquin emulation software used for ATT&CK Evaluations Turla Round. 

#NOTE: Assumed execution from the Resources folder with sudo permissions

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 


# ---------------------------------------------------------------------------
PROGNAME=${0##*/}
VERSION="1.0"
TESTNUMBER=0

# PRETTIFY
# success/fail colors
GREEN='\033[1;32m'
PINK='\033[1;31m'
# other
CYAN='\033[1;36m'
PURPLE='\033[1;35m'
NC='\033[0m' # No Color

# This script requires root. If not root or  executing as sudo, it will exit. 
if [ "$EUID" -ne 0 ]
  then printf "\n${PINK}Please level up as root or use sudo\n\nTerminating...\n\n\n"
  exit
fi

printf "
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::___::::::::::::::::::::
:::::::::::::::::::::::::::::::::::::::::::::-'    \`-::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::-'          \`::::::::::::::::
:::::::::::::::::::::::::::::::::::::::-  '     ${PINK}_o)${NC}    \`:::::::::::::::
:::::::::::::::::::::::::::::::::::-'    |      ${PINK}//\ ${NC}    :::::::::::::::
::::::::::::::::::::::::::::::::-         .     ${PINK}V_/_${NC}    ,::::::::::::::
::::::::::::::::::::::::::::-'             .          ,::::::::::::::::
:::::::::::::::::::::::::-'                    `-`.___.-::::::::::::::::::
:::::::::::::::::::::-'                  _,,-::::::::::::::::::::::::::
::::::::::::::::::-'                _,--:::::::::::::::::::::::::::::::
::::::::::::::-'               _.--:::::::::::::::::::::::#####::::::::
:::::::::::-'             _.--::::::::::::::::::::::::::::#####:::::###
::::::::'      ##    ###.-:::::::###::::::::::::::::::::::#####:::::###
::::-'        _##_.::###:::::::::###::::::::::::::#####:##########:::##
:'          .:###:::#####::::::::###::::::::::::::#####:##########:::##
      ...--:::###::#######:::::::###:::::######:::#####:##########:::##
 _ .--::##::::###:#########::::::###:::::######:::#####:###############
'#########::::###:##########:::#######:::######:::#####:###############
'#########:::################:#########::######:::#####################
##########:::##########################::##############################
##########:::##########################################################
##########:::##########################################################
#######################################################################
#######################################################################
#######################################################################
#######################################################################
------------------------------------------------
Gotham: https://asciiart.website/index.php?art=comics/batman
Paranoid Penguin: https://jr.co.il/humor/ascii-art-penguin.txt
------------------------------------------------
\n
"
# HELPER FUNCTIONS
#######################################
# check_file_exists
# Helper fuction that uses Linux test function to print if a file exists or does not exists
# ERROR: print statement for failed test
#######################################
function check_file_exists () {
    if test -x "$1"; then 
        printf "${CYAN}$1 exists & has executable permissions${NC}\n"
    elif test -a "$FILE"; then 
        printf "${CYAN}$1 exists but does not have executable permissions${NC}\n"
    else 
        printf "${PINK}$1 does not exist${NC}\n"
    fi
}
# same fucntion as above but flipped for removal of files
function check_file_rm () {
    if test -f "$1"; then
    printf "${PINK}$1 exists${NC}\n"
     else 
    printf "${GREEN}✔ $1 does not exist${NC}\n"
     fi
}
#######################################
# check_exit_code
# Helper fuction that evaluates the exit code of the last run command
# ERROR: print statement for failed test
#######################################
function execute () {
    # read the command from an arguement
    $1
    if [ $? -eq 0 ]; then
        printf "${GREEN}✔ Success:${NC} $1\n"
    else [ $? -eq 0 ]
        printf "${PINK}ERROR: $1${NC}\n"
    fi
}
printf "${CYAN}=========================================================\n"
printf "${CYAN}Beginning Tests${NC}\n"
printf "${CYAN}=========================================================\n"

# =========================================================================
#   Setups and Tear Downs
# =========================================================================

printf "${NC}Setting up installation....\n${NC}\n"
# Move penquin to /root folder
execute "cp ./hsperfdata /root/hsperfdata"
sleep 1

# unzip penquin
sh -c 'cd /root/ && unzip -o hsperfdata'
if [ $? -eq 0 ]; then
    printf "${GREEN}✔ Success:${NC} $0\n"
else [ $? -eq 0 ]
    printf "${PINK}ERROR: $0${NC}\n"
fi

#verity executable file permissions
((TESTNUMBER++))
FILE=/root/hsperfdata
if test -x "$FILE"; then 
    printf "${GREEN}Test $TESTNUMBER Success!${CYAN} $FILE exists & has executable permissions${NC}\n"
elif test -a "$FILE"; then 
    printf "${PINK}Test $TESTNUMBER Fail: $FILE exists but does not have executable permissions${NC}\n"
else 
    printf "${PINK}Test $TESTNUMBER Fail: $FILE does not exist${NC}\n"
fi
sleep .5

# Execute Penquin in a separate process so that it doesn't affact the current script test
printf "${Purple}Executing...(for 8 seconds)...\n"
execute `sh -c 'cd /root/ && ./hsperfdata'`


# =========================================================================
#   Tests
# =========================================================================

printf "=========================================================\n"
printf "[${CYAN}Test 1${NC}]: Installation Check\n"
printf "=========================================================\n"

# Penquin installer checked during installation
printf "${NC}Testing dropped files....\n${NC}"
# cron executable (BPF listener)
check_file_exists /usr/bin/cron
# cron service file 
check_file_exists /etc/systemd/system/cron.service

printf "=========================================================\n"
printf "[${CYAN}Test 2${NC}]: Execution Checks\n"
printf "=========================================================\n"

printf "${NC}Checking cron service status...${NC}\n"
# Check cron status
((TESTNUMBER++))
SERVICE="cron"
if (systemctl is-active --quiet $SERVICE); then
    printf "${GREEN}Test $TESTNUMBER Success!${CYAN} $SERVICE is running${NC}\n"
else
    printf "${PINK}Test $TESTNUMBER Fail: $SERVICE is dead${NC}\n"
fi

# Check for process group id specific to where we expect our malicious cron to run
printf "checking for running cron process from ${PURPLE}usr/bin${NC} rather than ${PURPLE}usr/sbin${NC}...\n"
processID=0
processID=$(ps axo pgid,command | grep -i '/usr/bin/cron -f' | grep -v grep | awk '{print $1;exit;}')
((TESTNUMBER++))
if [ $processID -ne 0 ];then 
    printf "${GREEN}Test $TESTNUMBER Success! Cron is running under PGID: ${CYAN}$processID${NC}\n"
else 
    printf "${PINK}Test $TESTNUMBER Fail: No PGID returned${NC}\n"
fi

printf "checking raw socket connection...\n"
# Check secure for active raw sockets with cron running
((TESTNUMBER++))
if ss -l -a -n -p | awk '/p_raw/ && /cron/' &> /dev/null;then 
    printf "${GREEN}Test $TESTNUMBER Success! A raw socket is running with cron active${NC}\n"
else 
    printf "${PINK}Test $TESTNUMBER Fail: No sockets are open that are both cron & raw sockets${NC}\n"
fi
# =========================================================================
# End of all tests
# =========================================================================

printf "=========================================================\n"
printf "[${CYAN}All Tests Complete${NC}]\n"
printf "=========================================================\n"