#! /usr/bin/python3

import os
import subprocess

def main():
    
    # set setuid permissions
    os.system("sudo chown root:root suid-binary")
    os.system("sudo chmod 4755 suid-binary")

    # run test comand, 'whoami' with suid-binary
    proc = subprocess.Popen(["./suid-binary", "whoami"], stdout=subprocess.PIPE)
    got = proc.stdout.read().decode("utf-8").rstrip()

    # output of whoami should be 'root'
    want = "root"
    if got != want:
        print(f"Test fail - expected {want}, got {got}")
        return -1
    
    print("Test passed!")
    print("Deleting suid binary for your safety")
    os.system("make clean")
    return 0

if __name__ == "__main__":
    main()