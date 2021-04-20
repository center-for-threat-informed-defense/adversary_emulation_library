#!/usr/bin/python3

# Python code to encrypt, compress, and base64 encode shellcode from a file

import argparse
import gzip
from base64 import b64encode
import os

def xor(data, key):
    # xor encrypt shellcode
    output_str = ""
    for i in range(len(data)):
        current = data[i]
        current_key = key[i%len(key)]
        output_str += chr((current) ^ ord(current_key))

    return bytearray(output_str, 'latin-1')

def getShellcode(fileName):
    # Open shellcode file and read bytes
    try:
        with open(fileName, 'rb') as shellcodeFileHandle:
            shellcodeBytes = shellcodeFileHandle.read()
            shellcodeFileHandle.close()
        print("--- Shellcode file -{}- successfully loaded".format(fileName))
    except IOError:
        print("!!! Could not open and read -{}-".format(fileName))
        quit()

    print("--- Shellcode size: {} bytes".format(len(shellcodeBytes)))
    
    return shellcodeBytes

def encryptShellcode(shellcodeBytes, key):
    # XOR Encrypt Shellcode
    encryptedShellcode = xor(shellcodeBytes, key) 
    print("--- Encrypted shellcode size: {} bytes".format(len(encryptedShellcode)))
    try:
        f = open("reverseencrypted.raw", "wb+")
        f.write(encryptedShellcode)
        f.close()
    except:
        print("!!! Unable to write encrypted shellcode to file.")
        quit()

    return encryptedShellcode

def compressShellcode(encryptedShellcode):
    # Use gzip to compress shellcode
    try:
        compressedShellcode = gzip.compress(encryptedShellcode)
    except:
        print("!!! Unable to compress shellcode.")
        quit()

    return compressedShellcode

def writeEncodedToFile(compressedShellcode, outfile):
    # Base64 encode the shellcode and write out to file
    try:
        encodedShellcode = b64encode(bytearray(compressedShellcode))
    except:
        print("!!! Unable to encode shellcode.")
        quit()

    try:
        f = open(outfile, "wb+")
        numChars = f.write(encodedShellcode)
        f.close()
        print("--- Encoded shellcode written to {}.".format(outfile))
    except IOError:
        print("!!! Could not write encoded shellcode to file.")
        
if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("shellcodeFileName", help="File name of the raw shellcode to be encrypted/compressed/encoded")
    parser.add_argument("key", help="Key to XOR encrypt the shellcode")
    parser.add_argument("outfile", help="Name of file where encrypted/compressed/encoded shellcode will be output")
    args = parser.parse_args() 
    
    shellcodeBytes = getShellcode(args.shellcodeFileName)
    encryptedShellcode = encryptShellcode(shellcodeBytes, args.key)
    compressedShellcode = compressShellcode(encryptedShellcode)    
    writeEncodedToFile(compressedShellcode, args.outfile)    
                
       
