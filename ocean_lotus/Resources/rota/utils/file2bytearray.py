# ---------------------------------------------------------------------------
# file2bytearray.py - Convert file to a C style byte arra

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: file2bytearray.py  -f $NAME_OF_BINARY_HERE

# Revision History:
# ---------------------------------------------------------------------------

#!/usr/bin/env python3
import argparse
import sys

def convert2bytearray(fName: str):
    """
    Convert string data to C style char array.
    @param fName: file name to read in.

    @return string of a c-style byte array
    """
    data = read_file(fName)
    var_fName = fName.lower().replace(" ", "_") \
        .replace("-", "_") \
        .replace(".", "_")

    b_array_size = len(data)
    b_array = f"char {var_fName} [{b_array_size}] = {{"

    for i, letter in enumerate(data):
        if i == len(data)-1:  # for the last iteration...
            b_array += (hex(ord(letter)) + "}")
        else:
            b_array += (hex(ord(letter)) + ",")

    return b_array


def read_file(fName: str):
    """
    Read in file specified by user arg.

    @param fName: file name to read in
    @return string
    """
    try:
        with open(fName, "r") as fin:
            return fin.read()
    except FileNotFoundError as error:
        print(f"[!] Error: {error}")
        sys.exit(1)

if __name__ == "__main__":

    args = argparse.ArgumentParser()
    args.add_argument("-f", "--file", required=True,
                      help="specify file to convert to c-style byte array")

    parser = args.parse_args()
    print(convert2bytearray(parser.file))
