# Ocean Lotus

Based on open-source intelligence, the [Center for Threat-Informed Defense](https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/) team created the below scenario based on tools and resources available at the time.

## Adversary Overview 
**Objectives:** [OceanLotus](https://attack.mitre.org/groups/G0050/) is a cyber threat group that began operations since 2014 and whose campaigns align with Vietnamese state interests, targeting private corporations in the manufacturing, consumer product, and hospitality sectors as well as foreign governments, political dissidents, and journalists. <sup>[1](https://www.mandiant.com/resources/blog/cyber-espionage-apt32)</sup> OceanLotus leverages commerically available tools and custom malware to execute strategic web compromises against victim networks. Specifically, the group’s campaigns usually involve phishing and watering hole attacks, spyware, DLL side-loading, DNS tunneling, and data exfiltration. Between February 2018 and November 2020, OceanLotus launched several spyware attacks against Vietnamese human rights activists, bloggers, and nonprofit organizations, believed to be a result of the government’s efforts to censor pro-democratic rhetoric.<sup>[2](https://www.amnestyusa.org/wp-content/uploads/2021/02/Click-and-Bait_Vietnamese-Human-Rights-Defenders-Targeted-with-Spyware-Attacks.pdf)</sup>

Associated Groups: APT32, SeaLotus, APT-C-00


## Emulation Overview 📖
This scenario specifically focuses on macOS and Linux environments, starting with a compromised macOS host. OceanLotus uses a multi-phased approach in exfiltrating sensitive data from a targeted victim, by first facilitating a watering hole attack and gaining initial access to the victim's workstation. To establish persistance, the attackers disguise the OSX backdoor as a fake Word document, sent via email to the victim. When the fake document is opened, a bash script is executed in the background that performs the backdoor capabilities of collecting OS information and registering with their C2 server. OceanLotus then searched for ssh keys and known host files, moving laterally to a discovered Linux server.<br>

<!-- TODO Add the folder structure (Resource, Binaries, Key Software, etc.) to main repo -->

## Quick Links
### For Engineers 💻
#### Resources


#### YARA Rules


#### Emulation Key Software


#### Scenario Walkthrough


### For Analysts 🔎


## Connect with us 🗨️

We 💖 feedback! Let us know how using this plan has helped you and what we can do better.

Email: ctid@mitre-engenuity.org <br>
Twitter: https://twitter.com/MITREengenuity <br>
LinkedIn: https://www.linkedin.com/company/mitre-engenuity/

Also see the guidance for contributors if are you interested in contributing or simply
reporting issues.

## How Do I Contribute?

We welcome your feedback and contributions to help advance
Ocean Lotus. Please see the guidance for contributors if are you
interested in [contributing or simply reporting issues.](/CONTRIBUTING.md)

Please submit
[issues](https://github.com/center-for-threat-informed-defense/ocean-lotus/issues) for
any technical questions/concerns or contact
[ctid@mitre-engenuity.org](mailto:ctid@mitre-engenuity.org?subject=subject=Question%20about%20ocean-lotus)
directly for more general inquiries.

## Liability / Responsible Usage

This content is only to be used with appropriate prior, explicit authorization for the purposes of assessing security posture and/or research.

## Notice

<!-- TODO Add PRS prior to publication. -->

Copyright 2023 MITRE Engenuity. Approved for public release. Document number REPLACE_WITH_PRS_NUMBER

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
