# Sandworm
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Based on open-source intelligence, the ATT&CK &reg; Evaluations team created the below scenario leveraging techniques seen from Sandworm in the wild. We have adapted the scenario based on tools and resources available at the time. 

## Adversary Overview 🏜️ 🪱

Sandworm Team <sup>[1]</sup> is a destructive threat group attributed to Russia's General Staff of the Armed Forces, Main Intelligence Directorate (GRU) that has been reportedly active since 2009.<sup>[2] [3]</sup>
In 2015 Sandworm used a BlackEnergy variant and the KillDisk module against three Ukrainian power distribution companies causing a power outage during the Christmas holidays. The outage left over 225,000 Ukrainian citizens without power in the middle of winter.<sup>[4]</sup> Sandworm is known for conducting large scale, well funded, destructive, and aggressive campaigns such as Olympic Destroyer, CrashOverride/Industroyer, and NotPetya.<sup>[5] [6] [7] [8]</sup> NotPetya, a destructive worm-like wiper malware disguised as ransomware, resulted in a global infection that caused nearly $1 billion in losses to three victim organizations alone.<sup>[2] [9]</sup> The "Sandworm" name was derived from references to the novel Dune found throughout the malware code, initially used to attribute other pieces of malware to the adversary. <sup>[10]</sup>

Associated Names: ELECTRUM, Telebots, IRON VIKING, BlackEnergy (Group), Quedagh, VOODOO BEAR

[1]:https://attack.mitre.org/groups/G0034/
[2]:https://www.justice.gov/opa/pr/six-russian-gru-officers-charged-connection-worldwide-deployment-destructive-malware-and
[3]:https://www.justice.gov/opa/press-release/file/1328521/download
[4]:https://www.cisa.gov/uscert/ics/alerts/IR-ALERT-H-16-056-01
[5]:https://www.digitalshadows.com/blog-and-research/mapping-mitre-attck-to-sandworm-apts-global-campaign/#:~:text=SandWorm%20is%20an%20APT%20group,aggressive%20and%20sometimes%20destructive%20cyberattacks.
[6]:http://blog.talosintelligence.com/2018/02/olympic-destroyer.html
[7]:https://www.dragos.com/wp-content/uploads/CrashOverride-01.pdf
[8]:https://blogs.vmware.com/security/2017/06/carbon-black-threat-research-technical-analysis-petya-notpetya-ransomware.html
[9]:https://securelist.com/expetrpetyanotpetya-is-a-wiper-not-ransomware/78902/
[10]:https://www.mandiant.com/resources/ukraine-and-sandworm-team

## Emulation Overview
![Operations Flow Diagram](./Resources/images/SoftwareFlow.jpeg)

# Quick Links
### For Engineers 🧑‍💻

### Resources

The [Resources Folder](./Resources/) contains the emulated software source code. Executables are provided in password protected zip files located in the specified software folder.  The password is `malware`.

We provide a [script](./Resources/utilities/crypt_executables.py) to automatically decrypt these files:

```
$ cd sandworm

$ python3 Resources/utilities/crypt_executables.py -i ./ -p malware --decrypt
```
### YARA Rules

[YARA rules](./yara-rules) are provided to assist the community in researching, preventing, and detecting malware specimens used in this emulation plan.

### Emulation Key Software 💻

- [P.A.S. webshell](./Resources/phpWebShell/)

- [Exaramel](./Resources/Exaramel)

- [NotPetya](./Resources/NotPetya/)

- [OraDump/LaZagne Varient](./Resources/browser-creds/)

- [Win64/Spy.KeyLogger.G](./Resources/keylogger/)

### Scenario Walkthrough
- [Detection Scenario](./Emulation_Plan/Scenario_1/) - Step by Step walkthrough of Scenario's procedures (9 steps). 
- [Protection Scenario](./Emulation_Plan/Scenario_2/) - Step by Step walkthrough of Scenario's procedures (3 tests)

## For Analysts 🔎
- [Operation Flow](./Operations_Flow/Operations_Flow.md/) - High-level summary of the scenario & infrastructure with diagrams. 
- [Intelligence Summary](./Intelligence_Summary/Intelligence_Summary.md) - General overview of the Adversary with links to reporting used throughout the scenario. 

## Acknowledgements

We would like to formally thank the people that contributed to the content, review, and format of this document. This includes the MITRE ATT&CK and MITRE ATT&CK Evaluations teams, the organizations and people that provided public intelligence and resources, as well as the following organizations that participated in the community cyber threat intelligence contribution process:

- Cynet

## Connect with Us 🗨️

We 💖 feedback! Let us know how using ATT&CK Evaluation results has helped you and what we can do better. 

Email: <evals@mitre-engenuity.org><br>
Twitter: https://twitter.com/MITREengenuity<br>
LinkedIn: https://www.linkedin.com/company/mitre-engenuity/<br>

## Liability / Responsible Usage

This content is only to be used with appropriate prior, explicit authorization for the purposes of assessing security posture and/or research.

## Notice

© 2022 MITRE Engenuity. Approved for Public Release. Document number AT0016.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

This project makes use of ATT&CK®

[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/)

