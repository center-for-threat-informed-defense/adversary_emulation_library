# Carbanak Adversary Emulation

This adversary emulation plan is derived from the original [Carbanak](https://attack.mitre.org/groups/G0008/) content developed and used in the [2020 ATT&CK Evaluations](https://attackevals.mitre-engenuity.org/carbanak-fin7/). It's format has been updated in collaboration with the [Center for Threat-Informed Defense](https://mitre-engenuity.org/center-for-threat-informed-defense/) to consolidate MITRE Engenuity emulation resources under a single [Adversary Emulation Library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library), and further standardize plan formats. This emulation plan has not been tested with CALDERA's Emu plugin and interoperability is not guaranteed.

**Carbanak** is a threat group that has been found to target banks. It also refers to malware of the same name (Carbanak). It is sometimes referred to as FIN7, but these appear to be two groups using the same Carbanak malware and are therefore tracked separately.<sup>[1](https://www.fireeye.com/blog/threat-research/2017/03/fin7_spear_phishing.html) [2](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html) [3](https://www.fireeye.com/blog/threat-research/2017/06/behind-the-carbanak-backdoor.html) [4](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html) </sup>

The **Intelligence Summary** summarizes 19 publicly available sources as well as the results of an [open call for contributions](https://medium.com/mitre-attack/announcing-2020s-attack-evaluation-6755650b68c2), to describe Carbanak, their motivations, objectives, and observed target industries. It further describes a representative Carbanak Operational Flow along with their publicly attributed Tactics, Techniques, and Procedures (TTPs) mapped to ATT&CK.

The **Operations Flow** chains techniques together into a logical order that commonly occurs across Carbanak operations. This Carbanak emulation plan features two distinct scenarios described below.

Please note that the FIN7 portion of this plan contains two additional scenarios used during the 2020 ATT&CK Evaluations and can also be found within the [CTID Adversary Emulation Library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library).

- **Scenario 1**: This scenario begins with a legitimate user executing a malicious payload delivered via spearphishing attacks targeting financial institutions. Following initial compromise, Carbanak expands access to other hosts through privilege escalation, credential access, and lateral movement with the goal of compromising money processing services, automated teller machines, and financial accounts. As Carbanak compromises potentially valuable targets, they establish persistence so that they can learn the financial organization's internal procedures and technology. Using this information, Carbanak transfers funds to bank accounts under their control, completing their mission.

- **Scenario 2**: This scenario emulates the same Carbanak TTP's as scenario 1; however, changes were made to support environments with protective security controls enabled. This scenario is designed so that specific TTP's are decoupled from dependencies to enable all steps to be executed, even if previous steps are blocked.

The Carbanak emulation plan is a human-readable, step-by-step / command-by-command implementation of Carbanak TTPs. Structurally, the plan is organized into an infrastructure section, and two scenarios, as defined in the Operations Flow. The infrastructure section explains how to prepare the environment to execute both scenarios. The human-readable plan is accompanied by a machine-readable plan implemented in YAML. The YAML includes select steps, commands, and syntax for the Carbanak detections scenario. Please note that the YAML file is not a 1-to-1 replication of the human-readable plan as the ATT&CK Evaluations Carbanak scenario was created before the CTID Emulation Library format was created.

## Resources

Please note that binary executable files hosted in [Resources](/Resources/) have been added to password protected zip files.  The password for these files is "malware."

We provide a [script](/Resources/utilities/crypt_executables.py) to automatically decrypt these files:

```
$ cd carbanak

$ python3 Resources/utilities/crypt_executables.py -i ./ -p malware --decrypt
```

## YARA Rules

[YARA rules](/yara-rules) are provided to assist the community in researching, preventing, and detecting malware specimens used in this emulation plan.

## Acknowledgements

We would like to formally thank the people that contributed to the content, review, and format of this document. This includes the MITRE ATT&CK and MITRE ATT&CK Evaluations teams, the organizations and people that provided public intelligence and resources, as well as the following organizations that participated in the community cyber threat intelligence contribution process:

- Microsoft

Special thanks to the following projects for providing tools and source code that were used in this emulation:

- [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
- [Impacket](https://github.com/SecureAuthCorp/impacket)
- [Putty Tools](https://www.putty.org)
- [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/)
- [TinyMet](https://github.com/SherifEldeeb/TinyMet)
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
- [SharpWeb](https://github.com/djhohnstein/SharpWeb)
- [killswitch-GUI](https://github.com/killswitch-GUI/SetWindowsHookEx-Keylogger)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)

## Table of Contents

- [Intelligence Summary](/Intelligence_Summary.md)
- [Operations Flow](/Operations_Flow.md)
- [Emulation Plan](/Emulation_Plan)
  - [Scenario 1 - Infrastructure](/Emulation_Plan/Scenario_1/Infrastructure.md)
  - [Scenario 1 - Detections](/Emulation_Plan/Scenario_1)
  - [Scenario 2 - Infrastructure](/Emulation_Plan/Scenario_2/Infrastructure.md)
  - [Scenario 2 - Protections](/Emulation_Plan/Scenario_2)
  - [YAML](/Emulation_Plan/yaml)
- [File Hashes](/hashes)
- [YARA Rules](/yara-rules)
- [Issues](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/issues)
- [Change Log](/CHANGE_LOG.md)

## Liability / Responsible Usage
This content is only to be used with appropriate prior, explicit authorization for the purposes of assessing security posture and/or research.

## Notice
© 2021 MITRE Engenuity. Approved for Public Release. Document number AT0016

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at:

* [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

This project makes use of ATT&CK®

[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/)
