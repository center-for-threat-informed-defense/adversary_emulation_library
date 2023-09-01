# File ops Utility

## Overview

The file ops utility is a small Python script that assists in encoding URLs and files used in the emulation of Blind Eagles attack chain. It has three main functions pertinent to this emulation:

* The URL function takes in a URL and replaces characters in the string with Unicode replacements. The function also reverses the string before writing it to a file called `url.txt`. The content of this file will be used in the VBS loader and passed as an argument to the `VAI` method of `fiber.dll`.

* The process_fsociety_file function takes in the path to fsociety.dll. The function will encode the file in Base64, replace the letter `A` with a unicode string, and return the string reversed. Then the payload is written to a file called `Rump.xls`. This file is downloaded from a Discord CDN as part of the infection chain.

* The process_asyncrat_file function takes in the path to an AsyncRAT client executable. The function will then encode the file in Base64 and return the string reversed. The string is then written to a file called `asy.txt`. This file is also downloaded from a Discord CDN as part of the infection chain.

## Usage

```
file-ops.py -h
usage: file-ops.py [-h] [-u URL] [-f FILE] [-r RAT] [-b FIBER]

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     URL to transform
  -f FILE, --file FILE  Path to fsociety file to encode
  -r RAT, --rat RAT     Path to AsyncRAT payload to encode
  -b FIBER, --fiber FIBER
                        Path to fiber file to encode
```

