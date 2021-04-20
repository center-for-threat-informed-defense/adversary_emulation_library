import argparse
import sys
import yaml


def get_argparse():
    desc = "Emulation Plan Placeholder Substitution Script"
    argparser = argparse.ArgumentParser(description=desc)

    argparser.add_argument(
        "document",
        type=str,
        help="Path to README.md file containing placeholder variables."
    )

    argparser.add_argument(
        "-placeholder_values",
        type=str,
        default="placeholder_values.yml",
        help="Location of the YAML file containing the values to substitute for placeholders."
    )

    return argparser


def substitute_values(contents, substitutions):
    for sub in substitutions:
        value = sub['value'] if sub['value'] else sub['default']
        contents = contents.replace(sub['name'], value)
    return contents


if __name__ == "__main__":
    parser = get_argparse()
    args = parser.parse_args()

    print("[+] Input Document: %s\tSubstitution Values File: %s" % (args.document, args.placeholder_values))

    try:
        with open(args.document, 'rt') as doc:
            contents = doc.read()
    except IOError as e:
        print('[-] Error on opening/reading from document:')
        print(e)
        sys.exit()

    try:
        with open(args.placeholder_values, encoding='utf-8') as substitution_file:
            substitutions = list(yaml.load_all(substitution_file, Loader=yaml.FullLoader))
    except IOError as e:
        print('[-] Error on opening/reading substitutions file:')
        print(e)
        sys.exit()

    new_contents = substitute_values(contents, substitutions[0])
    try:
        with open(args.document, 'wt') as doc:
            doc.write(new_contents)
    except IOError as e:
        print('[-] Error on opening/writing to document:')
        print(e)
        sys.exit()

    print('[+] Successfully replaced values!')