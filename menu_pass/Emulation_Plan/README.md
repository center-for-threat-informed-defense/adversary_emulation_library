# menuPass Adversary Emulation

menuPass is thought to be motivated by collection objectives that align with Chinese national interests.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> <sup>[6](https://www.justice.gov/opa/press-release/file/1121706/download)</sup> <sup>[12](https://us-cert.cisa.gov/ncas/alerts/TA17-117A)</sup> <sup>[14](https://crowdstrike.com/blog/two-birds-one-stone-panda/)</sup> <sup>[17](https://intrusiontruth.wordpress.com/2018/08/15/apt10-was-managed-by-the-tianjin-bureau-of-the-chinese-ministry-of-state-security/)</sup> The group's targeting is consistent with China's strategic objectives as stated in the Five-Year Plan (FYP) / Made in China 2025 Plan.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> While most of the group's targets have been located in the United States and Japan, the group has also been linked to intrusions in at least 12 other countries.<sup>[1](https://unit42.paloaltonetworks.com/unit42-menupass-returns-new-malware-new-attacks-japanese-academics-organizations/)</sup> <sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> <sup>[5](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)</sup> <sup>[6](https://www.justice.gov/opa/press-release/file/1121706/download)</sup> <sup>[8](https://www.accenture.com/t20180423T055005Z_s_/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf)</sup> <sup>[9](https://fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html)</sup> <sup>[10](https://recordedfuture.com/apt10-cyberespionage-campaign/)</sup> <sup>[11](https://blog.trendmicro.com/trendlabs-security-intelligence/chessmaster-cyber-espionage-campaign/)</sup> <sup>[12](https://us-cert.cisa.gov/ncas/alerts/TA17-117A)</sup> <sup>[13](https://blogs.blackberry.com/en/2019/06/threat-spotlight-menupass-quasarrat-backdoor)</sup>

The Intelligence Summary summarizes 32 publicly available sources to describe menuPass, their motivations, objectives, and observed target industries. It further describes the typical menuPass Operational Flow along with their publicly attributed Tactics, Techniques, and Procedures (TTPs) mapped to ATT&CK. In reviewing the plan, you may notice TTPs that do not currently map to the ATT&CK framework's menuPass group profile. This information has been provided to the ATT&CK team for analysis and potential incorporation.

The Operations Flow chains techniques together into a logical flow of the major Steps that commonly occur across menuPass operations. At a macro level, the publicly available reporting attributed to menuPass can be organized into two categories.  One being reporting specific to menuPass activities directed against MSP subscriber networks.  The other being activity that generally was initiated by spearphishing and leveraged a command-and-control framework to achieve operational objectives.  Thus, we have organized the menuPass emulation plan into two scenarios.

- Scenario 1: This scenario is designed to emulate activity attributed to menuPass that is specific to the group's efforts targeting MSP subscriber networks.  The intent of this scenario is to assess your organization's ability to protect, detect, and defend execution, tool ingress, discovery, credential access, lateral movement, persistence, collection, and exfiltration.
- Scenario 2: This scenario is designed to emulate activity attributed to menuPass that entails the pursuit of operational objectives using a command-and-control framework. This scenario is intended to assess your organization's ability to protect, detect, and defend execution, discovery, privilege escalation, credential access, lateral movement, exfiltration, C2, and persistence using a command-and-control framework.

The menuPass emulation plan is a human-readable, step-by-step / command-by-command implementation of menuPass TTPs. Structurally, the plan is organized into 2 scenarios, as defined in the Operations Flow. The human-readable plan is accompanied by a machine-readable plan implemented in YAML. The YAML includes all steps, commands, and syntax for Scenario 1. The YAML template was nuanced to ensure that each step within the YAML is directly coupled with its equivalent in the human-readable version.

## Table of Contents

- [Intelligence Summary](/menuPass/Intelligence_Summary.md)
- [Operations Flow](/menuPass/Operations_Flow.md)
- [Emulation Plan](/menuPass/Emulation_Plan/README.md)
  - [Resource Development](/menuPass/Emulation_Plan/ResourceDevelopment.md)
  - [Infrastructure](/menuPass/Emulation_Plan/Infrastructure.md)
  - [Scenario 1](/menuPass/Emulation_Plan/Scenario1.md)
  - [Scenario 2](/menuPass/Emulation_Plan/Scenario2.md)
  - [YAML](/menuPass/Emulation_Plan/yaml)
- [Issues](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/issues)
- [Change Log](/menuPass/CHANGE_LOG.md)

## Liability / Responsible Usage

This content is only to be used with appropriate prior, explicit authorization for the purposes of assessing security posture and/or research.

## Notice

Copyright 2021 MITRE Engenuity. Approved for public release. Document number CT0012.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

This project makes use of ATT&CK®

[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/)
