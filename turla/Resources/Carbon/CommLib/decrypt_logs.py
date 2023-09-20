# ---------------------------------------------------------------------------
# decrypt_logs.py - Decrypts Carbon commslib log files.

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 

# Usage: 
# python3 decrypt_logs.py -p /path/to/commslib/log -o /plaintext/output/log/path

# Revision History:

# --------------------------------------------------------------------------- 

import argparse
import base64
import os
import logging

from Crypto.Cipher import CAST
from Crypto.Util.Padding import unpad

BLOCK_SIZE = 8

# assumes first block of ciphertext is IV
def cast128_decrypt(key, ciphertext):
    iv = ciphertext[0:BLOCK_SIZE]
    
    cipher = CAST.new(key, CAST.MODE_CBC, iv=iv)
    padded_plaintext = cipher.decrypt(ciphertext[BLOCK_SIZE:])
    return unpad(padded_plaintext, BLOCK_SIZE)

# base64 decode and cast128 decrypt each line
def decode_and_decrypt_log(key, log_path, output):
    with open(output, 'wb') as output_file:
        with open(log_path, 'rb') as log_file:
            for line in log_file:
                plaintext = cast128_decrypt(key, base64.b64decode(line))
                output_file.write(plaintext + b'\n')

    
if __name__ == '__main__':
    parser = argparse.ArgumentParser('Carbon Comms Lib Log Decryptor')
    parser.add_argument('-p', '--log-path', required=True, help='Provide path to the Carbon comms lib log file.')
    parser.add_argument('-o', '--output', required=True, help='Provide output path for decrypted log file.')
    parser.add_argument('-k', '--key', default='f2d4560891bd948692c28d2a9391e7d9', help='16-byte CAST-128 encryption key for config file. Must be a hex string')
    parser.add_argument('-l', '--log', dest='logLevel', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Set logging level', default='INFO')
    args = parser.parse_args()
    
    logging.basicConfig(level=getattr(logging, args.logLevel))
    logging.info('Output path set to %s', args.output)
    logging.info('Using CAST128 key %s', args.key)
    
    if args.key:
        key = bytes.fromhex(args.key)
        if len(key) == 16: 
            decode_and_decrypt_log(key, args.log_path, args.output)
            exit(0)
    logging.error('Invalid key provided. Please provide 16-byte key.')
    exit(1)
