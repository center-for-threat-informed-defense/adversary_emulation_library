# APT29 Emulation (ARCHIVED)

This content was developed as part of the APT29 ATT&CK Evaluations and includes both the resources used to [manually execute the emulation](https://attackevals.mitre-engenuity.org/APT29/scope) as well as a plug-in developed for [CALDERA](https://github.com/mitre/caldera) (2.6.6).

For more details about the APT29 ATT&CK Evaluations, including results, visit https://attackevals.mitre-engenuity.org/APT29/

## Adversary Overview

[APT29/The Dukes/Cozy Bear/YTTRIUM](https://attack.mitre.org/groups/G0016/) (hereinafter referred to as just APT29) is a threat group that has been attributed to the Russian government and has operated since at least 2008.[1](https://blog-assets.f-secure.com/wp-content/uploads/2020/03/18122307/F-Secure_Dukes_Whitepaper.pdf) [14](https://www.us-cert.gov/sites/default/files/publications/JAR_16-20296A_GRIZZLY%20STEPPE-2016-1229.pdf) This group has been attributed to major breaches targeting U.S. governments/organizations such as the Democratic National Committee, as well as various international ministries and agencies.[15](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/) [16](https://securelist.com/the-cozyduke-apt/69731/) APT29 has also been known to “cast a wide net” in terms of targeting, seemingly making this group a universal threat. 

In terms of operational tradecraft, APT29 is distinguished by their commitment to stealth and sophisticated implementations of techniques via an arsenal of custom malware. APT29 typically accomplishes goals via custom compiled binaries and alternate (at least at the time) execution methods such as PowerShell and WMI. APT29 has also been known to employ various operational cadences (smash-and-grab vs. slow-and-deliberate) depending on the perceived intelligence value and/or infection method of victims.

## Liability / Responsible Usage

This content is only to be used with appropriate prior, explicit authorization for the purposes of assessing security posture and/or research.

## Notice

Copyright 2020 The MITRE Corporation

Approved for Public Release; Distribution Unlimited. Case Number 19-03607-2.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This project makes use of ATT&CK®

[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/)
