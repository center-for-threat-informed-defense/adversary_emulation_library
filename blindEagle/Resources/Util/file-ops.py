'''
# ---------------------------------------------------------------------------
** file-ops
**      About:
**          Utility script to perform various encoding, string replacement, and reversing of URLs and payloads
**      Result:
**          Output should be a string or file that can be used in accordance with the emulation plan

 # Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
 # Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

 # http://www.apache.org/licenses/LICENSE-2.0

 # Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 # This project makes use of ATT&CK®
 # ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 

# Revision History:

# ---------------------------------------------------------------------------
'''

import argparse
import base64


parser = argparse.ArgumentParser()

def parse_arguments():
    parser.add_argument("-u", "--url", help="URL to transform", required=False)
    parser.add_argument("-f", "--file", help="Path to fsociety file to encode", required=False)
    parser.add_argument("-r", "--rat", help="Path to AsyncRAT payload to encode", required=False)
    parser.add_argument("-b", "--fiber", help="Path to fiber file to encode", required=False)
    return parser.parse_args()

def process_url(url: str):
    replaced = url.replace('b', '(ø+(*').replace('c', '}░ú(}!').replace('d', '▶ø�}4').replace('e', '(◀▲*∞').replace('x', '@@�░@+@◀').replace('h', '⇝*@☟▲(*↓').replace('t', '�П}�√☞☀ø').replace('1', '(ú∞(]').replace('2', 'ú*@@(øú(').replace(':', '◀+→↓}ð☟▶').replace('/', '▶:#☞*●*4')
    return replaced[::-1]

def process_fsociety_file(path: str):
    with open(path, "rb") as fh:
        content = fh.read()
        b64text = base64.b64encode(content)
        b64textReplaced = str(b64text).replace("A", "♛➤❤")
        return b64textReplaced[::-1]
    
def process_asyncrat_file(path: str):
    with open(path, "rb") as fh:
        content = fh.read()
        b64text = base64.b64encode(content)
        return b64text[::-1]
    
def process_fiber_file(path: str):
    with open(path, "rb") as fh:
        content = fh.read()
        return base64.b64encode(content)
    
def main():
    args = parse_arguments()
    if args.url:
        processed = process_url(args.url)
        with open("url.txt", "w", encoding="utf-8") as fh:
            fh.write(processed)
    elif args.file:
        processed = process_fsociety_file(args.file)
        with open("Rump.xls", "w", encoding="utf-8") as fh:
            fh.write(processed)
    elif args.rat:
        processed = process_asyncrat_file(args.rat)
        with open("asy.txt", "w", encoding="utf-8") as fh:
            fh.write(processed.decode("utf-8"))
    elif args.fiber:
        processed = process_fiber_file(args.fiber)
        with open("new_rump_vb.net.txt", "w", encoding="utf-8") as fh:
            fh.write(processed.decode("utf-8"))
    else:
        print(parser.error(parser.usage))

if __name__ == "__main__":
    main()

