 # ---------------------------------------------------------------------------
 # gen_h_file.py - Generate xor-ed versions of Snake binaries

 # Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
 # Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

 # http://www.apache.org/licenses/LICENSE-2.0

 # Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 # This project makes use of ATT&CK®
 # ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 
 
 # Usage: python3 gen_h_file <input-filename> <output-filename> [hfile|bin]
 
 # Revision History:
 
 # --------------------------------------------------------------------------- 

import sys

xor_key = 0xd3

def xor_bytes_to_bin(fname, outfile=None):
    """
    Given a file 'fname' ingests bytes and XOR's with xor_key
    Optionally writes to output file "outfile"
    Returns bytearray object
    """
    with open(fname, "rb") as f:
        bin_file = f.read()

    ba_len = len(bin_file)
    ba = bytearray(ba_len)

    for i in range(0,ba_len):
        ba[i] = bin_file[i] ^ xor_key

    if (outfile):
        with open(outfile,"wb") as f:
            f.write(ba)
    
    return ba

def xor_bytes_to_hfile(fname,outfile):
    """
    Given a file 'fname' ingest and XOR bytes, output as C++ compliant header file
    """
    with open(fname, "rb") as f:
        bin_file = f.read()

    bin_arr = [format(b ^ xor_key, '#04x') for b in bin_file]

    with open(outfile, "w") as f:
        pragmaOnce = "#pragma once\n"
        includes = "#include <ntifs.h>\n"
        payloadPath = "inline UNICODE_STRING PAYLOAD_PATH = RTL_CONSTANT_STRING(L\"\\\\??\\\\C:\\\\Windows\\\\msnsvcx64.dll\");\n"

        f.write(pragmaOnce)
        f.write(includes)
        f.write(payloadPath)
        f.write("inline unsigned char DllPayload_dll[] = {")

        binLen = len(bin_arr)
        
        # writes our list as a usable C array
        for i in range(binLen):
            if (i % 12 == 0):
                f.write("\n  ")
            f.write(bin_arr[i])
            if (i == binLen - 1):
                f.write("\n")
            else:
                f.write(",")
                if (i % 12 != 11):
                    f.write(" ")
            
        
        f.write("};\n")
        f.write("inline unsigned int DllPayload_dll_len = %d;\n" % len(bin_arr))

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Please provide an input filename and output filename. Ex: './gen_dll_hfile.py infile.dll outfile.dll \"hfile\"'")
        sys.exit()
    fname = sys.argv[1]
    outfile = sys.argv[2]
    hfile_or_bin = sys.argv[3]

    if hfile_or_bin == "bin":
        xor_bytes_to_bin(fname,outfile)
    else:
        xor_bytes_to_hfile(fname,outfile)

