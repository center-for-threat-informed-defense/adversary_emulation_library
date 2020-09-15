# FIN6 Adversary Emulation

This repository contains an adversary emulation plan for [FIN6](https://attack.mitre.org/groups/G0037/). This is the first emulation plan in a [library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library) published by MITRE Engenuity's [Center for Threat Informed Defense](https://mitre-engenuity.org/center-for-threat-informed-defense/) in cooperation with our participants. See our recent [blog](https://medium.com/mitre-engenuity/fin6-adversary-emulation-plan-775d8c5ebe9b) annouccing the release of this emulation plan. 

FIN6 is thought to be a financially motivated cyber-crime group. The group has aggressively targeted and compromised high-volume POS systems in the hospitality and retail sectors since at least 2015. FIN6 has targeted e-commerce sites and multinational organizations. Most of the group’s targets have been located in the United States and Europe, but include companies in Australia, Canada, Spain, India, Kazakhstan, Serbia, and China.<sup>[5](https://exchange.xforce.ibmcloud.com/threat-group/f8409554b71a79792ff099081bc5ac24)</sup>

The Intelligence Summary summarizes 15 publicly available sources to describe FIN6, their motivations, objectives, and observed target industries. It further describes the typical FIN6 Operational Flow along with their publicly attributed Tactics, Techniques, and Procedures (TTPs) mapped to ATT&CK.  In reviewing the plan, you may notice TTPs that do not currently map to the ATT&CK framework's FIN6 group profile.  This information has been provided to the ATT&CK team for analysis and potential incorporation.  

The Operations Flow chains techniques together into a logical order of the major steps that commonly occur across FIN6 operations. In the case of FIN6, we describe their operations in two major phases:

- Phase 1: The primary focus of this phase is initial access and placement within the target environment, and exfiltrating relevant data identified during this phase (e.g. text files resulting from Discovery and credentials).
- Phase 2: This phase consists of the specific objectives or effects of the operation. We provide three potential options for specific objectives, based on historical FIN6 operations.

The FIN6 emulation plan is a human-readable, step-by-step / command-by-command implementation of FIN6 TTPs. Structurally, the plan is organized into 2 phases, as defined in the Operations Flow. The human-readable plan is accompanied by a machine-readable plan implemented in YAML. The YAML includes all steps, commands, and syntax for both Phase 1 and Phase 2. The YAML template was nuanced to ensure that each step within the YAML is directly coupled with its equivalent in the human-readable version. 

## Table of Contents

* [Intelligence Summary](/fin6/Intelligence_Summary.md)
* [Operations Flow](/fin6/Operations_Flow.md)
* [Emulation Plan](/fin6/Emulation_Plan/README.md)
  - [Phase 1](/fin6/Emulation_Plan/Phase1.md)
  - [Phase 2](/fin6/Emulation_Plan/Phase2.md)
  - [YAML](/fin6/Emulation_Plan/FIN6.yaml)
* [Issues](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/issues)

## Liability / Responsible Usage

This content is only to be used with appropriate prior, explicit authorization for the purposes of assessing security posture and/or research.

## Notice

Copyright 2020 MITRE Engenuity. Approved for public release. Document number CT0006

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

This project makes use of ATT&CK®

[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/)
