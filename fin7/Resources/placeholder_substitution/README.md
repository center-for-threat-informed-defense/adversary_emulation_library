# Placeholder Substitution Script

The emulation plans contain placeholders, such as `<domain>`, that represent values unique to the target environment that the plans are to be tested against. This script can used to easily substitute those placeholders with the target-specific values.

## Substitution Values

`substitute_placeholders.py` uses the contents of `placeholder_values.yml` to determine the substitutions to perform within the specified document.

`placeholder_values.yml` is populated with all of the placeholders present in both of the Carbanak Scenario plans, along with `default` values for each placeholder.
If `substitute_placeholders.py` is used without making any changes to `placeholder_values.yml`, the placeholders within the specified script will be replaced with the default values.

To specify a custom value, enter the value within the `value` field for a placeholder. The script will then use this custom value instead of the `default` value.

For example:

```
- name: <domain>
  description: The name of the target institution's domain.
  default: financial
  value: ""  <-- replace the empty quotes with the string you wish to use
```

## Usage

```
python3 ./substitute_placeholders.py [-placeholder_values ./placeholder_values.yml] ../../../Scenario_1/README.md
``` 