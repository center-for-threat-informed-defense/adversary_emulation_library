[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# OceanLotus

Based on open-source intelligence, the [Center for Threat-Informed Defense](https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/) team created the below scenario leveraging techniques seen from OceanLotus in the wild. We have adapted the scenario based on tools and resources available at the time.

## Adversary Overview 
**Objectives:** [OceanLotus](https://attack.mitre.org/groups/G0050/) is a cyber threat actor aligning to the interests of the Vietnamese government. OceanLotus has been operational since at least that began 2014 targeting private corporations in the manufacturing, consumer product, and hospitality sectors as well as foreign governments, political dissidents, and journalists. <sup>[1](https://www.mandiant.com/resources/blog/cyber-espionage-apt32)</sup> OceanLotus leverages commerically available tools and custom malware to execute strategic web compromises against victim networks. Specifically, the group’s campaigns usually involve phishing and watering hole attacks, spyware, DLL side-loading, DNS tunneling, and data exfiltration. Between February 2018 and November 2020, OceanLotus launched several spyware attacks against Vietnamese human rights activists, bloggers, and nonprofit organizations, believed to be a result of the government’s efforts to censor pro-democratic rhetoric.<sup>[2](https://www.amnestyusa.org/wp-content/uploads/2021/02/Click-and-Bait_Vietnamese-Human-Rights-Defenders-Targeted-with-Spyware-Attacks.pdf)</sup>

Associated Groups: APT32, SeaLotus, APT-C-00


## Emulation Overview 📖
This scenario focuses on macOS and Linux environments therefore no Windows hosts are used in this scenario. 

👋 Not emulated. The user recieves an email with an attached document, they download the document. Note: Having the document pre-exist does bypass initial Gatekeeper checks. Due to time constraints and lack of recent CTI reporting on macOS, we prioritized an assumed breach approach to focus on follow-on actions. 

Hope Potter (hpotter), double-clicks the conkylan.app (unicorn in Vietnamese) believing it to be a word document. The Word document is actually an Application bundle. Once opened, the app launches a decoy word document, executes a shell script, drops the second stage payload files, connects to the command and control server, and establishes persistence. OceanLotus then performs discover, identifies the user manages a file server using SSH with non password protected SSH keys. Using these remote services, OceanLotus downloads and executs Rota Jakiro on the Linux file server. Once persistence is established through modifing desktop autostart files and bashrc configuration files, OceanLotus performs discovery using shared objects for all mounted drives connected to the server. Finding none, OceanLotus collects all pdf and exfils the documents for later analysis. 
<br>

![Diagram walking through how OceanLotus infects a macOS, moves to a Linux host and exfils data](./Resources/images/OperationsFLowBlackBG.jpeg)


## Quick Links
### For Engineers 💻
#### Resources
The [Resources Folder](./Resources/) contains the emulated software source code.

The [Binaries.zip](./Resources/Binaries/binaries.zip) contains all executables in one zip file for easy download. The password is `malware`.

All other pre-built executables have been removed. To rebuild the binaries, follow the documentation for the respective implant.

#### YARA Rules

[YARA rules](./YARA_Rules/oceanlotus.yar) are provided to assist the community in researching, preventing, and detecting malware specimens used in this emulation plan.

#### Emulation Key Software

- [OSX.OceanLotus](./Resources/OSX.OceanLotus/)- OSX.OceanLotus is a macOS backdoor written in C++ & Objective-c that has been used by [OceanLotus](https://attack.mitre.org/groups/G0050/) since at least 2015. OSX.OceanLotus uses a modular communication library to communicate with the C2 via HTTP and can conduct downloading, uploading, command execution, and persistence.

- [Rota Jakiro](./Resources/rota/) - Rota Jakiro is Linux backdoor that has been used by [OceanLotus](https://attack.mitre.org/groups/G0050/) since at least 2021. Rota Jakiro communicates with the C2 over TCP and is distintive in it's use of shared objects for managing capabilities. Rota Jakiro only runs one instance of itself per host and can conduct downloading, uploading, and persistence.  


#### Scenario Walkthrough
- [Emulation Scenario](./Emulation_Plan/OceanLotus_Scenario.md) - Step by step walkthrough of scenario's for purple team operation.


### For Analysts 🔎

- [Operation Flow](./Operations_Flow/Operations_Flow.md/) - High-level summary of the scenario & infrastructure with diagrams. 
- [Intelligence Summary](./Intelligence_Summary/Intelligence_Summary.md) - General overview of the Adversary with links to reporting used throughout the scenario.

>Note: Review each implant's readme for technical details and supporting CTI reporting when developing the implant. 

## Connect with us 🗨️

We 💖 feedback! Let us know how using this plan has helped you and what we can do better.

Email: ctid@mitre-engenuity.org <br>
Twitter: https://twitter.com/MITREengenuity <br>
LinkedIn: https://www.linkedin.com/company/mitre-engenuity/

Also see the guidance for contributors if are you interested in contributing or simply
reporting issues.

## How Do I Contribute?

We welcome your feedback and contributions. 

### CTI Contributions
We are trying something new using OceanLotus as our testcase. We wanted to find a way to increase information shareing while also giving credit to contributors. Check out our [Contributing Wiki](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/wiki/Contributing#contribute-open-source-intelligence-for-an-adversary) for more information on how to contribute CTI (open-source). 

### Code Contributions
When emulating an adversary our CTI teams often propose an open-source based CTI Emulation Plan that is rich in ATT&CK techniques, uses a plethora of interesting implants, and is complex in nature. When translating this plan into development work, this plan is often pruned and simplified by the Red Team to fit the scope of develoment time and resources available. Afterall, we are a small team with only a couple of months to emulate a large, well-funded, specialized, development team that has years to develop these implants. On average ~30-40% of the proposed CTI Emulation Plan is actually developed. Rather than throwing this plan away (which is what we usually do) we are opening this up to the community. We would love for you to contribute a feature, functionality, or step from our proposed emulation plan. There are a couple of catches, it must be well integrated, tested, documented, and cited. Don't forget to check out the issues! We hope to have some smaller items to enable others to become familiar with our code base. 
Happy hacking!

For all other contributions, please see the guidance for contributors if you are interested in [contributing or simply reporting issues.](/CONTRIBUTING.md)

Please submit [issues](https://github.com/center-for-threat-informed-defense/ocean-lotus/issues) for any technical questions/concerns or contact [ctid@mitre-engenuity.org](mailto:ctid@mitre-engenuity.org?subject=subject=Question%20about%20ocean-lotus) directly for more general inquiries.

## Liability / Responsible Usage

This content is only to be used with appropriate prior, explicit authorization for the purposes of assessing security posture and/or research.

## Notice

Copyright 2023 MITRE Engenuity. Approved for public release. Document number REPLACE_WITH_PRS_NUMBER

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
file except in compliance with the License. You may obtain a copy of the License [here](http://www.apache.org/licenses/LICENSE-2.0).

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

This project makes use of ATT&CK®

[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/))
