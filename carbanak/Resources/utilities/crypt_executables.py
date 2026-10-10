#!/usr/bin/env python3

"""
       Filename:  crypt_executables.py

    Description:  This script will crawl the target directory and
                  automatically compress/decompress executables
                  (.exe and .dll) using either password-protected ZIP
                  archives or the CaRT format.

                  Example Usage:
                  1. python3 crypt_executables.py -i emu_plan_dir --encrypt -p malware
                  2. python3 crypt_executables.py -i emu_plan_dir --decrypt -p malware
                  3. python3 crypt_executables.py -i emu_plan_dir --encrypt -p malware --delete --quiet
                  4. python3 crypt_executables.py -i emu_plan_dir --decrypt -p malware --delete --quiet
                  5. python3 crypt_executables.py -i emu_plan_dir --encrypt --format cart --extensions .exe .dll .so
                  6. python3 crypt_executables.py -i emu_plan_dir --decrypt --format cart

        Version:  1.1
        Created:  April 6th, 2021
        Updated:  October 8th, 2026

      Author(s):  Michael C. Long II
   Organization:  The MITRE Corporation

  Dependencies:
      rustyzipper: https://pypi.org/project/rustyzipper/
      CaRT: https://pypi.org/project/cart/
"""

import argparse
import getpass
from pathlib import Path


def get_file_paths(target_dir: Path, suffixes: tuple[str, ...]) -> list[Path]:
    """Return a list of files with their full path."""
    return [
        file
        for file in target_dir.rglob("*")
        if file.is_file() and file.suffix.lower() in suffixes
    ]


def zip_encrypt_file(src_file: Path, password: str) -> None:
    """ZIP-compress and password-protect a file."""
    from rustyzipper import compress_file

    dst_file = src_file.parent / f"{src_file.name}.zip"

    print("[+] Zip-Encrypting file:", src_file)

    compress_file(
        str(src_file),
        str(dst_file),
        password=password,
    )


def zip_decrypt_file(src_file: Path, password: str) -> None:
    """Decompress a password-protected ZIP file."""
    from rustyzipper import decompress_file

    print("[i] Decompressing file:", src_file)

    dst_directory = src_file.parent

    decompress_file(
        str(src_file),
        str(dst_directory),
        password=password,
    )


def cart_pack_file(src_file: Path) -> None:
    """CaRT-compress and encrypt a file."""
    from cart import pack_file

    dst_file = src_file.parent / f"{src_file.name}.cart"

    print("[+] CaRT-Encrypting file:", src_file)

    pack_file(
        src_file,
        dst_file,
    )


def cart_unpack_file(src_file: Path) -> None:
    """Decompress and decrypt a CaRT file."""
    from cart import unpack_file

    dst_file = src_file.with_suffix("")

    print("[i] CaRT-Decrypting file:", src_file)

    unpack_file(
        src_file,
        dst_file,
    )


def delete_file(file_to_delete: Path, quiet: bool) -> None:
    """Delete file from filesystem."""
    response = "y"
    if not quiet:
        print(f"[!] Delete file? {file_to_delete}")
        response = input("[Y/N]> ").lower().strip()

    if response == "y":
        print(f"[!] Deleting file: {file_to_delete}")
        file_to_delete.unlink()

    else:
        print("Skipping file deletion")


def main() -> None:
    """Script entry point."""

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-i",
        "--indir",
        type=Path,
        required=True,
        help="Directory to locate executables or archive files",
    )

    parser.add_argument(
        "-p",
        "--password",
        required=False,
        help="Password/key used to encrypt/decrypt ZIP files",
    )
    action_group = parser.add_mutually_exclusive_group(required=True)

    action_group.add_argument(
        "-e",
        "--encrypt",
        action="store_true",
        help="Encrypt files",
    )

    action_group.add_argument(
        "-d",
        "--decrypt",
        action="store_true",
        help="Decrypt files",
    )

    default_ext = (".dll", ".exe")
    parser.add_argument(
        "--extensions",
        nargs="*",
        default=default_ext,
        help=f"File extensions to encrypt (default {', '.join(default_ext)}). Ignored for decryption.",
    )

    parser.add_argument(
        "--delete",
        action="store_true",
        help="Delete source files after encrypting/decrypting",
    )

    parser.add_argument(
        "-f",
        "--format",
        default="zip",
        choices=["zip", "cart"],
        help="Format to store files: ZIP or CaRT",
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Delete source files without prompting (dangerous!)",
    )

    args = parser.parse_args()

    target_dir = args.indir

    if not target_dir.is_dir():
        parser.error(f"Not a directory: {target_dir}")

    password = args.password

    if not password and args.format == "zip":
        print(f"[i] Enter encryption/decryption password")
        password = getpass.getpass("> ")

    if args.decrypt:
        suffixes = (".zip",) if args.format == "zip" else (".cart",)
    else:
        suffixes = tuple(
            x.lower() if x.startswith(".") else f".{x}".lower() for x in args.extensions
        )

    files_to_crypt = get_file_paths(target_dir, suffixes)

    if not files_to_crypt:
        print("[!] No files to encrypt or decrypt.")

    for file in files_to_crypt:
        if args.encrypt:
            if args.format == "zip":
                zip_encrypt_file(file, password)
            else:
                cart_pack_file(file)

        elif args.decrypt:
            if args.format == "zip":
                zip_decrypt_file(file, password)
            else:
                cart_unpack_file(file)

        if args.delete:
            delete_file(file, args.quiet)


if __name__ == "__main__":
    main()
