# FIN7 Adversary Emulation

This adversary emulation plan is derived from the original [FIN7](https://attack.mitre.org/groups/G0046/) content developed and used in the [2020 ATT&CK Evaluations](https://attackevals.mitre-engenuity.org/carbanak-fin7/). It's format has been updated in collaboration with the [Center for Threat-Informed Defense](https://mitre-engenuity.org/center-for-threat-informed-defense/) to consolidate MITRE Engenuity emulation resources under a single [Adversary Emulation Library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library), and further standardize plan formats. This emulation plan has not been tested with CALDERA's Emu plugin and interoperability is not guaranteed.


**FIN7** appears to be a financially motivated threat group that has primarily targeted the U.S. retail, restaurant, and hospitality sectors since mid-2015. They often use point-of-sale malware. A portion of FIN7 was operated out of a front company called Combi Security.<sup>[11](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)</sup> FIN7 is sometimes referred to as Carbanak Group, but these appear to be two groups using the same Carbanak malware and are therefore tracked separately.
<sup>[26](https://www.fireeye.com/blog/threat-research/2017/03/fin7_spear_phishing.html),
[25](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html),
[21](https://www.fireeye.com/blog/threat-research/2017/06/behind-the-carbanak-backdoor.html),
[11](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)</sup>

The **Intelligence Summary** summarizes 26 publicly available sources as well as the results of an [open call for contributions](https://medium.com/mitre-attack/announcing-2020s-attack-evaluation-6755650b68c2) to describe FIN7, their motivations, objectives, and observed target industries. It further describes a representative FIN7 operational flow along with their publicly attributed Tactics, Techniques, and Procedures (TTPs) mapped to ATT&CK.

The **Operations Flow** chains techniques together into a logical order that commonly occurs across FIN7 operations. This FIN7 emulation plan features two distinct scenarios described below.

Please note that the Carbanak portion of this plan contains two additional scenarios used during the 2020 ATT&CK Evaluations and can also be found within the [CTID Adversary Emulation Library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library).

- **Scenario 1**: This scenario emulates FIN7 targeting a hotel manager network to gain access to credit card information. The scenario begins with FIN7 achieving initial access to the network after an unwitting user executes a malicious .LNK file. FIN7 then pivots to a privileged IT administrator workstation. From this system, FIN7 keylogs credentials needed to access an accounting workstation. FIN7 then pivots to the accounting workstation, establishes persistence, and deploys malware to scrape credit card information from process memory.

- **Scenario 2**: This scenario emulates the same FIN7 TTP's as scenario 1; however, changes were made to support environments with Protective security controls enabled. This scenario is designed so that specific TTP's are decoupled from dependencies to enable all steps to be executed, even if previous steps are blocked.

The FIN7 emulation plan is a human-readable, step-by-step / command-by-command implementation of FIN7 TTPs. Structurally, the plan is organized into an infrastructure section, and two scenarios (Detections and Protections respectively). The infrastructure section explains how to prepare the environment to execute both scenarios. The human-readable plan is accompanied by a machine-readable plan implemented in YAML. The YAML includes all steps, commands, and syntax for both Scenario 1 and Scenario 2. The YAML template was nuanced to ensure that each step within the YAML is directly coupled with its equivalent human-readable version.

## Resources

Please note that binary executable files hosted in [Resources](/fin7/Resources/) have been added to password protected zip files.  The password for these files is "malware."

We provide a [script](/fin7/Resources/utilities/crypt_executables.py) to automatically decrypt these files:

```
$ cd carbanak

$ python3 Resources/utilities/crypt_executables.py -i ./ -p malware --decrypt
```
## YARA Rules

[YARA rules](/fin7/yara-rules) are provided to assist the community in researching, preventing, and detecting malware specimens used in this emulation plan.

## Acknowledgements

We would like to formally thank the people that contributed to the content, review, and format of this document. This includes the MITRE ATT&CK and MITRE ATT&CK Evaluations teams, the organizations and people that provided public intelligence and resources, as well as the following organizations that participated in the community cyber threat intelligence contribution process:

- Microsoft

Special thanks to the following projects for providing tools and source code that were used in this emulation:

- [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
- [sRDI](https://github.com/monoxgas/sRDI)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [PAExec](https://www.poweradmin.com/paexec/)

## Table of Contents

- [Intelligence Summary](/fin7/Intelligence_Summary.md)
- [Operations Flow](/fin7/Operations_Flow.md)
- [Emulation Plan](/fin7/Emulation_Plan)
  - [Scenario 1 - Infrastructure](/fin7/Emulation_Plan/Scenario_1/Infrastructure.md)
  - [Scenario 1 - Detections](/fin7/Emulation_Plan/Scenario_1)
  - [Scenario 2 - Infrastructure](/fin7/Emulation_Plan/Scenario_2/Infrastructure.md)
  - [Scenario 2 - Protections](/fin7/Emulation_Plan/Scenario_2)
  - [YAML](/fin7/Emulation_Plan/yaml)
- [File Hashes](/fin7/hashes)
- [YARA Rules](/fin7/yara-rules)
- [Issues](/issues)
- [Change Log](/fin7/CHANGE_LOG.md)

## Liability / Responsible Usage

This content is only to be used with appropriate prior, explicit authorization for the purposes of assessing security posture and/or research.

## Notice

© 2021 MITRE Engenuity. Approved for Public Release. Document number AT0016.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

This project makes use of ATT&CK®

[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/)
