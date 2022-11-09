# OilRig 

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Based on open-source intelligence, the ATT&CK ® Evaluations team created the below scenario leveraging techniques seen from OilRig in the wild. We have adapted the scenario based on tools and resources available at the time.

## Adversary Overview 🛢️
**Objectives:** [OilRig](https://attack.mitre.org/groups/G0049/) is a cyber threat actor with operations aligning to the strategic objectives of the Iranian government. <sup>[1](https://cyware.com/blog/apt34-the-helix-kitten-cybercriminal-group-loves-to-meow-middle-eastern-and-international-organizations-48ae)</sup> <sup>[2](https://unit42.paloaltonetworks.com/threat-brief-iranian-linked-cyber-operations/)</sup> OilRig has been operational since at least 2014 and has a history of widespread impact, with operations directed against financial, government, energy, chemical, telecommunications and other sectors around the globe. <sup>[3](https://www.fortinet.com/blog/threat-research/please-confirm-you-received-our-apt)</sup>  OilRig commonly leverages spearphishing and social engineering tactics in their operations, as well as PowerShell backdoors. <sup>[4](https://www.mandiant.com/resources/blog/targeted-attack-in-middle-east-by-apt34)</sup> <sup>[5](https://www.attackiq.com/2022/07/11/oilrig-attack-graphs-emulating-the-iranian-threat-actors-global-campaigns/)</sup> <sup>[6](https://securelist.com/oilrigs-poison-frog/95490/)</sup> The group continues to evolve its tradecraft to evade detection, and utilizes a combination of proprietary malware, customized versions of publicly available tools, and off-the-shelf, multi-purpose software. 

Associated Groups: COBALT GYPSY, IRN2, APT34, Helix Kitten



## Emulation Overview 📖 
This scenario follows OilRig’s multi-phase approach to exfiltrating sensitive data from a targeted server. OilRig leverages spearphishing to gain initial access onto an administrator’s workstation and deploys their SideTwist malware. Once persistence is established on the victim network, the attackers will escalate privileges and move laterally onto an EWS server. Further enumeration of the EWS server will lead to OilRig’s identification of a SQL server storing confidential critical infrastructure data. Characteristics of this campaign include: custom webshells, Windows and Microsoft 365 exploitation, and key attacker objective on obtaining control of the SQL server to steal victim files.<br>

![Operations Flow Diagram](./Resources/images/OpsFlow.png)

## Quick Links
### For Engineers 🧑‍💻
#### Resources

The [Resources Folder](./Resources/) contains the emulated software source code.

The [Binaries.zip](./Resources/Binaries/binaries.zip) contains all executables in one zip file for easy download. The password is `malware`.

All other pre-built executables have been removed. To rebuild the binaries, follow the documentation for the respective binary. A [build script](./Resources/setup/build_implants) has been provided for building all binaries on a Kali Linux host.

This scenario also utilizes `Mimikatz`, `Plink` and `PsExec` as payloads:
- [Mimikatz](https://github.com/gentilkiwi/mimikatz/wiki)
- [Plink](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html)
- [PsExec.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)

#### YARA Rules

[YARA rules](./YARA_Rules/managedservicesR1.yar) are provided to assist the community in researching, preventing, and detecting malware specimens used in this emulation plan.

#### Emulation Key Software

- [SideTwist](./Resources/SideTwist/)- SideTwist is a C-based backdoor that has been used by [OilRig](https://attack.mitre.org/groups/G0049/) since at least 2021 and is purposed for downloading, uploading, command execution, and persistence.

- [TwoFace](./Resources/TwoFace/) - TwoFace is a webshell written in C# used by OilRig for lateral movement since at least 2017.

- [VALUEVAULT](./Resources/VALUEVAULT/) - VALUEVAULT is a Golang version of the Windows Vault Password Dumper credential theft tool developed by Massimiliano Montoro and has been used by OilRig since at least 2019.

- [RDAT](./Resources/RDAT/) - RDAT is a backdoor used by OilRig for data collection and exfiltration since at least 2017.

#### Scenario Walkthrough

- [Emulation Scenario](./Emulation_Plan/README.md) - Step by step walkthrough of scenario's procedures.

### For Analysts 🔎

- [Operation Flow](./Operations_Flow/Operations_Flow.md/) - High-level summary of the scenario & infrastructure with diagrams. 
- [Intelligence Summary](./Intelligence_Summary/Intelligence_Summary.md) - General overview of the Adversary with links to reporting used throughout the scenario. 

## Connect with us 🗨️

We 💖 feedback! Let us know how using ATT&CK Evaluation results has helped you and what we can do better.

Email: evals@mitre-engenuity.org <br>
Twitter: https://twitter.com/MITREengenuity <br>
LinkedIn: https://www.linkedin.com/company/mitre-engenuity/

## Liability / Responsible Usage

This content is only to be used with appropriate prior, explicit authorization for the purposes of assessing security posture and/or research.

## Notice

© 2022 MITRE Engenuity. Approved for Public Release. Document number AT0037.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

This project makes use of ATT&CK®

[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/)
