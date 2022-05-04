#!/usr/bin/env python3

"""
       Filename:  crypt_executables.py

    Description:  This script will crawl the target directory and
                  automatically zip compress/decompress either executables
                  (.exe and .dll) or zip-compresed files using a password.

                  Example Usage:
                  1. python3 crypt_executables.py -i emu_plan_dir --encrypt -p malware
                  2. python3 crypt_executables.py -i emu_plan_dir --decrypt -p malware
                  3. python3 crypt_executables.py -i emu_plan_dir --encrypt -p malware --delete --quiet
                  4. python3 crypt_executables.py -i emu_plan_dir --decrypt -p malware --delete --quiet

        Version:  1.0
        Created:  April 6th, 2021

      Author(s):  Michael C. Long II
   Organization:  MITRE Engenuity

  References(s): N/A
"""

import argparse
import getpass
import os
import sys
import warnings


try:
    import pyminizip
except ImportError:
    print("[-] Error - Unable to import 'pyminizip'.")
    print("[-] Verify you have installed dependencies:")
    print("\t\t  Ubuntu:    apt-get install zlib1g")
    print("\t\t   MacOS:    homebrew install zlib")
    print("\t\tAll OS's:    pip3 install pyminizip")
    print()
    print("[-] See URL for more info: https://github.com/smihica/pyminizip")
    sys.exit(-1)


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


def zip_encrypt_file(file_to_encrypt, password):
    """ Zip compress file with password """
    dst_file = file_to_encrypt + ".zip"
    print("[+] Zip-Encrypting file: ", file_to_encrypt)

    # Ignore deprecation warnings so we don't flood the console with garbage
    # This is a known issue in pyminizip; see: https://github.com/smihica/pyminizip/issues/34
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        pyminizip.compress(file_to_encrypt, None, dst_file, password, 0)


def zip_decrypt_file(file_to_decrypt, password):
    """ Zip decompress file with password """
    print("[i] Decompressing file: ", file_to_decrypt)
    dst_directory = os.path.dirname(file_to_decrypt)
    # Ignore deprecation warnings so we don't flood the console with garbage
    # This is a known issue in pyminizip; see: https://github.com/smihica/pyminizip/issues/34
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        try:
            pyminizip.uncompress(file_to_decrypt, password, dst_directory, 0)
        except Exception as e:
            print("[-] Error when decrypting %s: %s" % (file_to_decrypt, e))


def delete_file(file_to_delete, quiet):
    """ Delete file from filesystem """
    response = "y"
    if not quiet:
        print(f"[!] Delete file? {file_to_delete}")
        response = input("[Y/N]> ")
        response = response.lower().strip()

    if response == "y":
        print(f"[!] Deleting flie: {file_to_delete}")
        os.remove(file_to_delete)

    else:
        print(f"Skipping file deletion")


def main():
    """ Script entry point """

    # Setup command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--indir", required=True,
                        help="Directory to locate executables or zip files")
    parser.add_argument("-p", "--password", required=False,
                        help="Password to encrypt/decrypt files")
    parser.add_argument("-e", "--encrypt", action="store_true",
                        help="Zip-Encrypt files")
    parser.add_argument("-d", "--decrypt", action="store_true",
                        help="Zip-Decrypt files")
    parser.add_argument("--delete", action="store_true",
                        help="Delete source files after encrypting/decrypting")
    parser.add_argument("--quiet", action="store_true",
                        help="Delete unencrypted files without prompts (dangerous!)")
    args = parser.parse_args()

    target_dir = args.indir

    password = args.password
    if not password:
        print("[i] Enter encryption/decryption password:")
        password = getpass.getpass("> ")

    cwd = os.getcwd()

    # get full path for each file in directory (recursive)
    files_to_crypt = get_file_paths(target_dir)

    for file in files_to_crypt:
        if args.encrypt:
            if file.endswith(".exe") or file.endswith(".dll"):
                zip_encrypt_file(file, password)
                if args.delete:
                    delete_file(file, args.quiet)

        elif args.decrypt:
            if file.endswith(".zip"):
                zip_decrypt_file(file, password)
                os.chdir(cwd)
                if args.delete:
                    delete_file(file, args.quiet)

        else:
            print("[-] Unexpected error; check usage.")
            parser.print_help()
            break


if __name__ == "__main__":
    main()
