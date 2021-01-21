#!/usr/bin/env python3
import fileinput
import re
import os

def main():
  server = input("Enter callback server http[s]://IP:PORT: ")

  for filename in os.listdir():
    extension = os.path.splitext(filename)[1]

    if extension != ".ps1" and extension != ".txt":
      continue

    with fileinput.FileInput(filename, inplace=True) as FILE:
        for line in FILE:
                            # http://IP:PORT or https://IP:PORT
            print(re.sub(r'https?:\/\/((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\d{1,6}', server, line), end='')

  print("Done!")

if __name__ == "__main__":
  main()
