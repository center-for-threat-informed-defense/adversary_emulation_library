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

    for item in yaml_object:
        input_arguments = {}

        for arg, val in item.get("input_arguments", {}).items():
            input_arguments[arg] = val.get("default", "NOT_SET")

        for executor in item.get("executors", []):
            executor_cmd = executor["command"]
            for arg, val in input_arguments.items():
                executor_cmd = executor_cmd.replace("#{%s}" % arg, val)
            if re.findall(r"#{.*?}", executor_cmd):
                if "executors" not in bad_entries:
                    bad_entries["executors"] = []
                bad_entries["executors"].append((item["id"], executor_cmd))

        for dependency in item.get("dependencies", []):
            prereq_cmd = dependency["prereq_command"]
            get_prereq_cmd = dependency.get("get_prereq_command", "")

            for arg, val in input_arguments.items():
                prereq_cmd = prereq_cmd.replace("#{%s}" % arg, val)

            for arg, val in input_arguments.items():
                get_prereq_cmd = get_prereq_cmd.replace("#{%s}" % arg, val)

            if re.findall(r"#{.*?}", prereq_cmd):
                if "dependencies" not in bad_entries:
                    bad_entries["dependencies"] = []
                bad_entries["dependencies"].append((item["id"], prereq_cmd))

            if re.findall(r"#{.*?}", get_prereq_cmd):
                if "dependencies" not in bad_entries:
                    bad_entries["dependencies"] = []
                bad_entries["dependencies"].append((item["id"], get_prereq_cmd))

        for platform, platform_value in item.get("platforms", {}).items():
            for os_name, os_value in platform_value.items():
                cmd_value = os_value["command"]

                for arg, val in input_arguments.items():
                    cmd_value = cmd_value.replace("#{%s}" % arg, val)

                if re.findall(r"#{.*?}", cmd_value):
                    if "platforms" not in bad_entries:
                        bad_entries["platforms"] = []
                    bad_entries["platforms"].append((item["id"], cmd_value))

    if bad_entries:
        pprint.pprint(bad_entries, indent=4)

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
