#!/bin/bash
# ---------------------------------------------------------------------------
# clean_penquins - Bash shell script to clean up after the execution of the Penquin emulation software used for ATT&CK Evaluations Turla Round. 

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

# Prettify output

# success/fail colors
GREEN='\033[1;32m'
PINK='\033[1;31m'
# other
CYAN='\033[1;36m'
PURPLE='\033[1;35m'
NC='\033[0m' # No Color


# This script requires root. If not root or executing as sudo, it will exit. 
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
# FUNCTIONS
#######################################
# check_file_exists
# Helper function that uses Linux test function to print if a file exists or does not exists
# ERROR: print statement for failed test
#######################################
function check_file_exists () {
    if test -f "$1"; then
         printf "${GREEN}✔ $1 exists${NC}\n"
     else 
         printf "${PINK}$1 does not exist${NC}\n"
     fi
}
# same function as above but flipped for removal of files
function check_file_rm () {
    if test -f "$1"; then
    printf "${PINK}$1 exists${NC}\n"
     else 
    printf "${GREEN}✔ $1 does not exist${NC}\n"
     fi
}
#######################################
# check_exit_code
# Helper function that evaluates the exit code of the last run command
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
#######################################
# remove_dropped_files
# removes cron executable from /usr/bin/
# removes config file from /etc/systemd
# ERROR: exit 1 for each check/command with printf statements 
#######################################
function remove_dropped_files () {
    
    dropped_files=("/root/hsperfdata" "/usr/bin/cron" "/etc/systemd/system/cron.service")
    
    for path in "${dropped_files[@]}"
    do
        check_file_exists $path
        execute "rm $path"
        check_file_rm $path
    done
}

#######################################
# kill_processes
# removes cron executable from /usr/bin/
# removes config file from /etc/systemd
# ERROR: exit 1 for each check/command with printf statements 
#######################################
function kill_processes () {
    # Grab the PGID of the Penquin process specific to our cron instance running from usr/bin
    processID=0
    processID=$(ps axo pgid,command | grep -i '/usr/bin/cron -f' | grep -v grep | awk '{print $1;exit;}')
    if [ $processID -ne 0 ];then 
        printf "${NC}Cron is running under PGID: ${CYAN}$processID ${NC}\n"
    else 
        printf "${PINK}No PGID returned for /usr/bin/cron -f$ {NC}\n"
    fi
    
    # kill Penquin processes
    execute "kill -- -$processID"

    #Verify killed processes
    processID=$(ps axo pgid,command | grep -i '/usr/bin/cron -f' | grep -v grep | awk '{print $1;exit;}')
    if test -z "$processID" 
    then
        printf "${GREEN}Test  Success!${CYAN} Verified all proesses associated with the group id ${CYAN}$processID${NC}\n"
    else
        printf "${PINK}Test  Fail: $processID still exists ${NC}\n"    
    fi
}
#######################################
# check_cron_status
# uses systemctl is-active command to verify the service is active 
# provides printf statement for result
#######################################
function check_cron_status() {
        # Check cron status
    SERVICE="cron"
    if (systemctl is-active --quiet $SERVICE); then
        printf "${CYAN}$SERVICE is running${NC}\n"
    else
        printf "${CYAN}$SERVICE is NOT running${NC}\n"
    fi
}
#######################################
# reset_cron_service
# uses systemctl for all commands
# stops cron & checks the status
# reloads the cron service 
# starts cron & checks the status 
# ERROR: exit 1 for each check/command with printf statements 
#######################################
function reset_cron_service () { 
    # stop cron to stop
    execute `systemctl stop cron &> /dev/null`
    sleep 1

    # Check cron status
   check_cron_status

    # reload the service so it uses a different config file (default one)
    execute `systemctl daemon-reload &> /dev/null`
    sleep 1

    #start cron
    execute "systemctl start cron"
    sleep 1
    
    # Check cron status
    check_cron_status
}

# PROGRAM BODY

function main(){
    printf "${GREEN}Destroying all the Penquins...\n\n"

    # removes penquin & service config file
    printf "${PURPLE}Removing files on disk...\n"
    remove_dropped_files
    
    # Kills current running processes of penquin using the process group ID (PGID)
    printf "\n${PURPLE}Killing the cron processes...\n"
    kill_processes

    # resets the cron service
    printf "\n${PURPLE}Resetting the cron service (takes 3 seconds)...\n"
    reset_cron_service

    printf "${PURPLE}*********************     ${GREEN}Host Reset Complete    ${PURPLE}*********************\n\n"

}
main "$@"