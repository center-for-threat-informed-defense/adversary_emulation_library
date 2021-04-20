#!/bin/bash
# this script generates SSL certs used by the C2 server

openssl req -new -x509 -keyout ./cert.key -out ./cert.pem -days 365 -nodes -subj "/C=US" >/dev/null 2>&1

echo -e "[*] Created certificate: cert.pem"
echo -e "[*] Created Private Key: cert.key"
