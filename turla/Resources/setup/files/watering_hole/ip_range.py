#!/usr/bin/python

import ipaddress
import argparse

# Argument parsing - accepting a file and one or more ip addresses or ranges, along with a verbosity flag

parser = argparse.ArgumentParser(description='Create JS/PHP code that compares a specified range of IP addresses against the client, for purposes of running a script against the client if the client IP is included in the list of addresses.')
parser.add_argument("file", help="The HTML/PHP file to which you are adding an IP filtering script.")
parser.add_argument("-i", "--included", help="Path to the script which will be run against IP addresses that are provided - considered 'in range' or included. If this is not provided, an alert() will be used as placeholder.")
parser.add_argument("-o", "-e", "--excluded", help="Path to the script which will be run against IP addresses that are not provided - considered 'out of range' or excluded.")
parser.add_argument("ipaddress", action="extend", nargs='+', help="The IP address, list of addresses or netmasked range you'd like to fingerprint. This is the list of included IP addresses that the --included script file will be run against.")
parser.add_argument("-v", "--verbose", help="Increase verbosity of script - prints the file, the destination, and the list of IP addresses considered included.", action="store_true")
args = parser.parse_args()

# Parsing the IP addresses and catching errors

single_array_of_ip_addresses = []

for arg in args.ipaddress:
    try:
        single_array_of_ip_addresses += list(ipaddress.ip_network(arg))
    except ValueError:
        print("Either an invalid IP address was provided or a host bit was set when providing a mask.")
if not single_array_of_ip_addresses:
    print("No valid IP addresses provided. Exiting.")
    exit()
if (args.verbose):
    print("Here is a single list of all the ip addresses provided")
    for address in single_array_of_ip_addresses:
        print(address)

# Parsing the script files

if args.included:
    with open(args.included, 'r') as f:
        in_range_script = f.read()
else:
    print("No script provided for included IP addresses. Using alert() placeholder.")
    in_range_script = "<script>alert('Your IP address is in range.')</script>"
if args.excluded:
    with open(args.excluded, 'r') as f:
        out_of_range_script = f.read()
else:
    print("No script provided for excluded IP addresses, excluded IP addresses will not have scripts applied.")
    out_of_range_script = "";

# Constructing the php string to be prepended

php_start = "<?php "
php_array_start = "$array_of_addresses = array("

# List comprehension
php_list = ','.join(['"' + format(address) + '"' for address in single_array_of_ip_addresses])

php_array_end = ");"
php_end = "?>"

# This is the core - php code which will check if SERVER[REMOTE_ADDR] is in the allow list. If the client is "on the allowlist", you can proceed.
php_loop = "if (in_array(\"$_SERVER[REMOTE_ADDR]\", $array_of_addresses)) {echo \"" + in_range_script + "\";}else{echo \"" + out_of_range_script + "\";}"

php_string = php_start + php_array_start + php_list + php_array_end + php_loop + php_end

if (args.verbose):
    print("Here is the php injection string")
    print(php_string);

# Finally, actually writing the code to the file.

with open(args.file, 'r') as f:
    content = f.read()
with open(args.file, 'w') as f:
    f.write(php_string)
    f.write("\n")
    f.write(content)
