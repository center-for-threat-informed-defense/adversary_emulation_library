# APT29 Adversary Emulation

This adversary emulation plan is derived from the original [APT29](https://attack.mitre.org/groups/G0016/) content developed and used in the [2019 ATT&CK Evaluations](https://attackevals.mitre-engenuity.org/APT29/). It's format has been updated in collaboration with the [Center for Threat-Informed Defense](https://mitre-engenuity.org/center-for-threat-informed-defense/) to consolidate MITRE Engenuity emulation resources under a single [Adversary Emulation Library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library), and further standardize plan formats.  

APT29 is thought to be an organized and well-resourced cyber threat actor whose collection objectives appear to align with the interests of the Russian Federation.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf),[14](https://www.us-cert.gov/sites/default/files/publications/JAR_16-20296A_GRIZZLY%20STEPPE-2016-1229.pdf)</sup>  The group is reported to have been operating as early as 2008 and may have logged operational successes as recently as 2020.

The Intelligence Summary summarizes 16 publicly available sources as well as the results of an [open call for contributions](https://medium.com/mitre-attack/open-invitation-to-share-cyber-threat-intelligence-on-apt29-for-adversary-emulation-plan-831c8c929f31), to describe APT29, their motivations, objectives, and observed target industries. It further describes a representative APT29 Operational Flow along with their publicly attributed Tactics, Techniques, and Procedures (TTPs) mapped to ATT&CK.

The Operations Flow chains techniques together into a logical order that commonly occur across APT29 operations. In the case of APT29, we break out their operations into two distinct scenarios:

- Scenario 1: This scenario starts with a "smash-and-grab" then rapid espionage mission that focuses on gathering and exfiltrating data, before transitioning to stealthier techniques to achieve persistence, further data collection, credential access, and lateral movement. The scenario ends with the execution of previously established persistence mechanisms.

- Scenario 2: This scenario consists of a stealthier and slower approach to compromising the initial target, establishing persistence, harvesting credentials, then finally enumerating and compromising the entire domain. The scenario ends with a simulated time-lapse where previously established persistence mechanisms are executed.

The APT29 emulation plan is a human-readable, step-by-step / command-by-command implementation of APT29 TTPs. Structurally, the plan is organized into an infrastructure section, and two scenarios, as defined in the Operations Flow. The infrastructure section explains how to prepare the environment to execute both scenarios.  The human-readable plan is accompanied by a machine-readable plan implemented in YAML. The YAML includes all steps, commands, and syntax for both Scenario 1 and Scenario 2. The YAML template was nuanced to ensure that each step within the YAML is directly coupled with its equivalent in the human-readable version.

## Acknowledgements

We would like to formally thank the people that contributed to the content, review, and format of this document. This includes the MITRE ATT&CK and MITRE ATT&CK Evaluations teams, the organizations and people that provided public intelligence and resources, as well as the following organizations that participated in the community cyber threat intelligence contribution process:

- Kaspersky
- Microsoft
- SentinelOne

## Table of Contents

- [Intelligence Summary](/apt29/Intelligence_Summary.md)
- [Operations Flow](/apt29/Operations_Flow.md)
- [Emulation Plan](/apt29/Emulation_Plan/README.md)
  - [Scenario 1 - Infrastructure](/apt29/Emulation_Plan/Scenario_1/Infrastructure.md)
  - [Scenario 1](/apt29/Emulation_Plan/Scenario_1/README.md)
  - [Scenario 2 - Infrastructure](/apt29/Emulation_Plan/Scenario_2/Infrastructure.md)
  - [Scenario 2](/apt29/Emulation_Plan/Scenario_2/README.md)
  - [YAML](/apt29/Emulation_Plan/yaml)
- [Archive](/apt29/Archive)
- [Issues](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/issues)
- [Change Log](/apt29/CHANGE_LOG.md)

## Liability / Responsible Usage

This content is only to be used with appropriate prior, explicit authorization for the purposes of assessing security posture and/or research.

## Notice

Copyright 2020 MITRE Engenuity. Approved for public release. Document number AT0008.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

This project makes use of ATT&CK®

[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/)
