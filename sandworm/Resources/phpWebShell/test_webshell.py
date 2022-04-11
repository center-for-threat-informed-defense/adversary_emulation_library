#!/usr/bin/python3
import inspect
import subprocess
import sys
import time
import urllib.request
import os

from os import error

def setup():
    # start php web server
    try:
        subprocess.Popen(["php", "-S", "127.0.0.1:8081"])
    except error as e:
        print("[-] failure in function: ", inspect.stack()[0][3])
        print(e)
        print("Do you have 'php' installed? Try 'php --help'; if its not there, install it.")
        sys.exit(-1)
    time.sleep(1)


def test_webshell():
    url = "http://127.0.0.1:8081/webShell.php?cmd=echo+it_worked!>success.txt"
    try:
        urllib.request.urlopen(url)
    except error as e:
        print("[-] failure in function: ", inspect.stack()[0][3])
        print(e)
        sys.exit(-1)

    # confirm test file is present
    want = "it_worked!"
    got = ""

    try:
        file = open("success.txt", "r")
        got = file.read()
        file.close()
    except error as e:
        print("[-] failure in function: ", inspect.stack()[0][3])
        print(e)
        sys.exit(-1)

    got = got.rstrip()
    if got != want:
        print("[-] failure in function: ", inspect.stack()[0][3])
        print(f"expected '{want}', got '{got}'")
        sys.exit(-1)

def test_obfuscated_webshell():
    url = "http://127.0.0.1:8081/obfuscated_webShell.php?Y21k=echo+it_worked!>success.txt"
    try:
        urllib.request.urlopen(url)
    except error as e:
        print("[-] failure in function: ", inspect.stack()[0][3])
        print(e)
        sys.exit(-1)

    # confirm test file is present
    want = "it_worked!"
    got = ""

    try:
        file = open("success.txt", "r")
        got = file.read()
        file.close()
    except error as e:
        print("[-] failure in function: ", inspect.stack()[0][3])
        print(e)
        sys.exit(-1)

    got = got.rstrip()
    if got != want:
        print("[-] failure in function: ", inspect.stack()[0][3])
        print(f"expected '{want}', got '{got}'")
        sys.exit(-1)


def teardown():
    # kill php
    try:
        subprocess.Popen(["pkill", "-9", "php"])
    except error as e:
        print("[-] unable to kill php")
        print(e)
        sys.exit(-1)

    try:
        os.remove("success.txt")
    except error as e:
        print("[-] unable to delete 'success.txt'")
        print(e)
        sys.exit(-1)


def main():
    print("[i] Starting PHP web server")
    setup()

    print("[i] Testing webShell.php")
    test_webshell()
    print("[+] Test passed")

    print("[i] Testing obfuscated_webShell.php")
    test_obfuscated_webshell()
    print("[+] Test passed")
    
    print("[i] Cleaning up test artifacts")
    teardown()

    print("[+] All tests passed - hooray!")

if __name__ == "__main__":
    main()