#!/usr/bin/env bash

# create an ssh key for scenario use
KEY_FILENAME="oceanlotus"

# Note: Since key will be used for Windows host, must be RSA key pair
if ! [ -s "${KEY_FILENAME}" ]; then
  ssh-keygen -b 4096 -t rsa -f ./${KEY_FILENAME} -q -N ""
  echo "Created new ssh keypair, filename: ${KEY_FILENAME}"
else
  echo "Key file ${KEY_FILENAME} already exists, exiting..."
  exit 1
fi

