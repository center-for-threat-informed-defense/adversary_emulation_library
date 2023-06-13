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


def encryption():
    """
    TODO
    """
    pass

if __name__ == "__main__":

    args = argparse.ArgumentParser()
    args.add_argument("-f", "--file", required=True,
                      help="specify file to convert to c-style byte array")

    parser = args.parse_args()
    print(convert2bytearray(parser.file))
