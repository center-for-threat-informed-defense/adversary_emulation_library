import sys
import re
import yaml
from pathlib import Path

"""
Convert CTID Adversary Emulation Plan's YAML to MITRE CALDERA Plugin.

Prepare:
1. Save this script
2. Clone the CTID "adversary_emulation_library" repository
    $ git clone git@github.com:center-for-threat-informed-defense/adversary_emulation_library.git
3. Clone the MITRE CALDERA version 2.8.0 repository and setup it
    $ git clone https://github.com/mitre/caldera.git --recursive --branch 2.8.0 
    $ cd caldera
    $ sudo apt install -y python3-pip
    $ pip3 install -r requirements.txt

How to convert:
1. Open a command shell terminal 
2. Execute this script, for example to convert FIN6 emulation plan:
    $ python3 ctid_aep_to_caldera.py "[ctid_directory]'/fin6/Emulation_Plan/FIN6.yaml "[caldera_directory]"/plugins/ctid_fin6
   (The last argument specifies where plugins are stored, and the directory name becomes your caldera plugin name.)

How to enable the MITRE CALDERA Plugin:
1. Start the MITRE CALDERA server
    $ cd "[caldera_directory]"
    $ python3 server.py --insecure
2. Login to the MITRE CALDERA as a red team using a Google Chrome browser
    URL: http://localhost:8888/
    username: red
    password: admin
3. Move your mouse cursor on "navigate" menu and click "configuration" in "Advanced"
4. Click the "enable" button on the right of your plugin name in "Plugins"
5. Restart the MITRE CALDERA Server

How to edit abilities:
1. Login to the MITRE CALDERA as a red team using a Google Chrome browser
2. Move your mouse cursor on "navigate" menu and click "adversaries" in "Campaigns"
3. Select a emulation plan name in the "Select an existing profile" pull-down menu
4. Drag and drop abilities to change their order
5. Click The "?" button on the upper right of each ability to edit details

"""

__license__ = "Apache License 2.0"
__copyright__ = "FUJITSU SYSTEM INTEGRATION LABORATORIES LTD."
__author__ = "Kazuhisa SHIRAKAMI"
__author_email__ = "k.shirakami@fujitsu.com"
__status__ = "prototype"
__version__ = "1.0.2"
__date__ = "07 September 2020"




class AdversaryEmulationPlan:

    def __init__(self, yaml_path):
        with open(yaml_path, encoding='utf-8') as f:
            first_item, *abilities = yaml.safe_load(f)
        emulation_plan_details = first_item['emulation_plan_details']
        self.id = emulation_plan_details['id']
        self.name = emulation_plan_details['adversary_name']
        self.description = emulation_plan_details['adversary_description']
        self.abilities = abilities
        self.ability_ids = [ability['id'] for ability in abilities]
        self._adjust_multiline_commands()

    def _adjust_multiline_commands(self):
        for ability in self.abilities:
            platforms = ability.get('platforms', {})
            for platform, executors in platforms.items():
                for executor, properties in executors.items():
                    if 'command' not in properties:
                        continue
                    joiner = ' && ' if executor == 'cmd' else '; '
                    command = properties['command'].strip().split('\n')
                    properties['command'] = joiner.join(command)


class CalderaPlugin:

    def __init__(self, path):
        path = Path(path)
        self.path = path.parent / path.name.replace(' ', '_').lower()
        self.script_path = self.path / 'hook.py'

    def adversary_path(self, adversary):
        return self.path / 'data' / 'adversaries' / f'{adversary.id}.yml'

    def ability_path(self, ability):
        path = self.path / 'data' / 'abilities'
        if 'tactic' in ability:
            path /= ability['tactic']
        path /= f'{ability["id"]}.yml'
        return path

    def script_template(self, adversary):
        return f"""\
from app.utility.base_world import BaseWorld

name = '{adversary.name}'
description = '{adversary.description}'
address = None
access = BaseWorld.Access.RED


async def enable(services):
    pass
"""

    def save_adversary(self, adversary):
        profile = {
            'id': adversary.id,
            'name': adversary.name,
            'description': adversary.description,
            'atomic_ordering': adversary.ability_ids,
        }
        path = self.adversary_path(adversary)
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            yaml.dump(profile, stream=f, sort_keys=False)

    def save_ability(self, ability):
        path = self.ability_path(ability)
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            yaml.dump([ability], stream=f, sort_keys=False)

    def save_script(self, adversary):
        path = self.script_path
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(self.script_template(adversary))


def convert(ctid_yaml_path, plugin_path):
    adversary = AdversaryEmulationPlan(ctid_yaml_path)
    caldera_plugin = CalderaPlugin(plugin_path)
    caldera_plugin.save_adversary(adversary)
    for ability in adversary.abilities:
        caldera_plugin.save_ability(ability)
    caldera_plugin.save_script(adversary)


def main():
    if len(sys.argv) != 3:
        print(f"Usage:", sys.argv[0], "<ctid_yaml_path>", "<plugin_path>")
        exit(1)
    convert(ctid_yaml_path=sys.argv[1], plugin_path=sys.argv[2])

if __name__ == '__main__':
    main()
