# ---------------------------------------------------------------------------
# decrypt_logs.py - Decrypts the provided Snake usermodule log and saves to the specified output file.

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 

# Usage: python3 decrypt_logs.py -p /path/to/encrypted/log -o /path/to/save/output

# Revision History:

# ---------------------------------------------------------------------------

import argparse
import base64
import logging

xor = b'1f903053jlfajsklj39019013ut098e77xhlajklqpozufoghi642098cbmdakandqiox536898jiqjpe6092smmkeut02906'

if __name__ == '__main__':
    parser = argparse.ArgumentParser('Snake Usermodule Log Decryptor')
    parser.add_argument('-p', '--log-path', required=True, help='Provide path to the log file.')
    parser.add_argument('-o', '--output', required=True, help='Provide output path for decrypted log file.')
    parser.add_argument('-l', '--log', dest='logLevel', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Set logging level', default='INFO')
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.logLevel))
    logging.info('Reading in log file from %s', args.log_path)
    logging.info('Output path set to %s', args.output)

    with open(args.output, 'wb') as output_file:
        with open(args.log_path) as file:
            for line in file:
                decoded = base64.b64decode(line)
                decrypted_line = bytes(a ^ b for a, b in zip(decoded, xor))
                output_file.write(decrypted_line + b'\n')


    
        
