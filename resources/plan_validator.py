# Copyright (c) 2020, MITRE Engenuity. Approved for public release.
# See LICENSE for complete terms

# pip install jsonschema ruamel.yaml

import jsonschema
from ruamel import yaml

import argparse
import difflib
import json
import pprint
import re


def get_argparse():
    desc = "Emulation Plan JSON Schema Validator"
    argparser = argparse.ArgumentParser(description=desc)

    argparser.add_argument(
        "input_document",
        type=str,
        help="Path to YAML file subject to validation."
    )

    argparser.add_argument(
        "-schema_document",
        type=str,
        default="format_schema.json",
        help="Location of the Emulation Plan JSON Schema."
    )

    return argparser


def validate_document_against_jsonschema(yaml_path, schema_path):
    """Raises SchemaError or ValidationError Exception if
    there is a problem with the schema or YAML document."""
    with open(yaml_path, mode="r", encoding="utf-8") as f:
        yaml_object = yaml.safe_load(f)

    with open(schema_path, mode="r", encoding="utf-8") as f:
        schema_object = json.load(f)

    jsonschema.validate(yaml_object, schema_object)


def best_practice_comment_round_trip(yaml_path):
    """Round-trips the YAML document. If comments (#) are
    incorrectly escaped or not using literal style they will
    affect tools parsing the content. Also catches indentation changes,
    extra spaces in unneeded areas, other minor stylistic changes."""
    with open(yaml_path, mode="r", encoding="utf-8") as f:
        yaml_str1 = f.read()

    yaml_object = yaml.round_trip_load(yaml_str1, preserve_quotes=True)
    yaml_str2 = yaml.round_trip_dump(yaml_object, width=300)

    results = list(
        difflib.Differ().compare(
            yaml_str1.splitlines(keepends=True),
            yaml_str2.splitlines(keepends=True)
        )
    )

    for item in results:
        if item.startswith(("+ ", "- ", "? ")):
            pprint.pprint(item)

    assert yaml_str1 == yaml_str2


def test_command_builder(yaml_path):
    """It will test and replace areas of the YAML that use commands
    to guarantee no undefined input_arguments"""
    with open(yaml_path, mode="r", encoding="utf-8") as f:
        yaml_object = yaml.round_trip_load(f.read(), preserve_quotes=True)

    bad_entries = {}

    def flag_bad_entries(step, section, cmd, input_args, entry_map):
        """Replaces #{variable} with value.
        Checks for any undefined variables."""
        for argument_name, argument_value in input_args.items():
            cmd = cmd.replace("#{%s}" % argument_name, argument_value)

        if re.findall(r"#{.*?}", cmd):
            if section not in entry_map:
                entry_map[section] = []
            entry_map[section].append((step["id"], cmd))

    for item in yaml_object:
        input_arguments = {}

        for arg, val in item.get("input_arguments", {}).items():
            input_arguments[arg] = val.get("default", "NOT_SET")

        for executor in item.get("executors", []):
            executor_cmd = executor["command"]
            cleanup_cmd = executor.get("cleanup_command", "")

            flag_bad_entries(item, "executors", executor_cmd, input_arguments, bad_entries)
            flag_bad_entries(item, "executors", cleanup_cmd, input_arguments, bad_entries)

        for dependency in item.get("dependencies", []):
            prereq_cmd = dependency["prereq_command"]
            get_prereq_cmd = dependency.get("get_prereq_cmd", "")

            flag_bad_entries(item, "dependencies", prereq_cmd, input_arguments, bad_entries)
            flag_bad_entries(item, "dependencies", get_prereq_cmd, input_arguments, bad_entries)

        for platform, platform_value in item.get("platforms", {}).items():
            for os_name, os_value in platform_value.items():
                cmd_value = os_value["command"]
                cleanup_value = os_value.get("cleanup", "")

                flag_bad_entries(item, "platforms", cmd_value, input_arguments, bad_entries)
                flag_bad_entries(item, "platforms", cleanup_value, input_arguments, bad_entries)

    if bad_entries:
        pprint.pprint(bad_entries)

    assert not bad_entries


if __name__ == "__main__":
    parser = get_argparse()
    args = parser.parse_args()

    print("[+] Input Document: %s\tSchema: %s" % (args.input_document, args.schema_document))
    validate_document_against_jsonschema(args.input_document, args.schema_document)
    print("\t[+] JSON Schema Validation passed")
    best_practice_comment_round_trip(args.input_document)
    print("\t[+] YAML Round-trip passed")
    test_command_builder(args.input_document)
    print("\t[+] Check Commands builder passed")
    print("[+] Finished Execution")
