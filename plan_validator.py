# Copyright (c) 2020, MITRE Engenuity. Approved for public release.
# See LICENSE for complete terms

# pip install jsonschema pyyaml

import jsonschema
import yaml

import argparse
import json


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


def validate_document(yaml_path, schema_path):
    """Raises SchemaError or ValidationError Exception if
    there is a problem with the schema or YAML document."""
    with open(yaml_path, mode="r", encoding="utf-8") as f:
        yaml_object = yaml.safe_load(f)

    with open(schema_path, mode="r", encoding="utf-8") as f:
        schema_object = json.load(f)

    jsonschema.validate(yaml_object, schema_object)


if __name__ == "__main__":
    parser = get_argparse()
    args = parser.parse_args()
    print("[+] Input: %s\tSchema: %s" % (args.input_document, args.schema_document))
    validate_document(args.input_document, args.schema_document)
    print("[+] Validation complete")
