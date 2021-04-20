#!/usr/bin/env python3

import argparse
import hashlib
import os
import sys

"""
       Filename:  get_file_hashes.py

    Description:  This script will get all files in a directory (recursive)
                  and hash the files with a user specified algorithm.
                  Supported algorithms include MD5, SHA-1, SHA-256, and SHA-512.
                  This program prints output to the console by default.
                  Output may be written to a file using shell redirection.

                  Example Usage:
                  $ python3 get_file_hashes.py -i ./Documents/ --md5

        Version:  1.0
        Created:  April 5th, 2021

      Author(s):  Michael C. Long II
   Organization:  MITRE Engenuity

  References(s): N/A
"""


def get_file_paths(target_dir):
    """ Returns a list of files with their full path """
    dir_listing = os.listdir(target_dir)
    all_files = list()
    for file in dir_listing:
        full_path = os.path.join(target_dir, file)
        if os.path.isdir(full_path):
            all_files = all_files + get_file_paths(full_path)
        else:
            all_files.append(full_path)
    return all_files


def get_sha512_sums(file_bytes):
    """ Hashes bytes with the SHA-512 algorithm """
    return hashlib.sha512(file_bytes).hexdigest()


def get_sha256_sums(file_bytes):
    """ Hashes bytes with the SHA-256 algorithm """
    return hashlib.sha256(file_bytes).hexdigest()


def get_sha1_sums(file_bytes):
    """ Hashes bytes with the SHA-1 algorithm """
    return hashlib.sha1(file_bytes).hexdigest()


def get_md5_sums(file_bytes):
    """ Hashes bytes with the MD5 algorithm """
    return hashlib.md5(file_bytes).hexdigest()


def main():
    """ Script entry point """

    # Setup command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--indir", required=True,
                        help="Directory to hash")
    parser.add_argument("--md5", action="store_true",
                        help="Hash input files with MD5 algorithm")
    parser.add_argument("--sha1", action="store_true",
                        help="Hash input files with SHA-1 algorithm")
    parser.add_argument("--sha256", action="store_true",
                        help="Hash input files with SHA-256 algorithm")
    parser.add_argument("--sha512", action="store_true",
                        help="Hash input files with SHA-512 algorithm")
    args = parser.parse_args()

    target_dir = args.indir

    # get full path for each file in directory (recursive)
    files_to_hash = get_file_paths(target_dir)
    file_hash = ""

    for file in files_to_hash:
        with open(file, "rb") as fh:
            file_bytes = fh.read()

            # Hash each file using the specified algorithm
            if args.md5:
                file_hash = get_md5_sums(file_bytes)

            elif args.sha1:
                file_hash = get_sha1_sums(file_bytes)

            elif args.sha256:
                file_hash = get_sha256_sums(file_bytes)

            elif args.sha512:
                file_hash = get_sha512_sums(file_bytes)

            else:
                print("[-] Unexpected error; check usage.")
                parser.print_help()
                break

            print(f"{file_hash} {file}")


if __name__ == "__main__":
    main()