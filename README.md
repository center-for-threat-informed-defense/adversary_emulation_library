# Adversary Emulation Library

In collaboration with Center Participants, the [Center for Threat-Informed Defense
(Center)](https://ctid.mitre-engenuity.org/) maintains a library of adversary emulation
plans to allow organizations to evaluate their defensive capabilities against the
real-world threats they face. Emulation plans are an essential component in testing
current defenses for organizations that are looking to prioritize their defenses around
actual adversary behavior. Focusing our energies on developing a set of common emulation
plans that are available to all means that organizations can use their limited time and
resources to focus on understanding how their defenses actually fare against real-world
threats.

The library contains two types of adversary emulation plans: full emulation and micro
emulation.

**Full emulation plans** are a comprehensive approach to emulating a specific adversary,
e.g. [FIN6](/fin6/), from initial access to exfiltration. These plans emulate a wide
range of ATT&CK tactics & techniques and are designed to emulate a real breach from the
designated adversary.

**Micro emulation plans** are a focused approach to emulating compound behaviors seen
across multiple adversaries, e.g. [webshells](/micro_emulation_plans/src/webshell).
These plans emulate a small amount of ATT&CK techniques that are typically performed as
part of one adversary action.

Also see our blogs on the [Adversary Emulation
Library](https://medium.com/mitre-engenuity/introducing-the-all-new-adversary-emulation-plan-library-234b1d543f6b)
and [Micro Emulation
Plans](https://medium.com/mitre-engenuity/ahhh-this-emulation-is-just-right-introducing-micro-emulation-plans-7bf4c26451d3).

Available adversary emulation plans are listed below:

|       Full Emulation Plans       | Intelligence Summary                                                                                                                                                                                                                                                                                                                                                                                                   |
| :------------------------------: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|          [FIN6](/fin6/)          | [FIN6 is thought to be a financially motivated cyber-crime group. The group has aggressively targeted and compromised high-volume POS systems in the hospitality and retail sectors since at least 2015...](/fin6/Intelligence_Summary.md)                                                                                                                                                                             |
|         [APT29](/apt29/)         | [APT29 is thought to be an organized and well-resourced cyber threat actor whose collection objectives appear to align with the interests of the Russian Federation...](/apt29/Intelligence_Summary.md)                                                                                                                                                                                                                |
|     [menuPass](/menu_pass/)      | [menuPass is thought to be threat group motivated by collection objectives, with targeting that is consistent with Chinese strategic objectives...](/menu_pass/Intelligence_Summary.md)                                                                                                                                                                                                                                |
|   [Carbanak Group](/carbanak/)   | [Carbanak is a threat group who has been found to manipulate financial assets, such as by transferring funds from bank accounts or by taking over ATM infrastructures...](/carbanak/Intelligence_Summary.md)                                                                                                                                                                                                           |
|          [FIN7](/fin7/)          | [FIN7 is a financially-motivated threat group that has been associated with malicious operations dating back to late 2015. The group is characterized by their persistent targeting and large-scale theft of payment card data from victim systems...](/fin7/Intelligence_Summary.md)                                                                                                                                  |
|      [Sandworm](/sandworm/)      | [Sandworm Team is a destructive threat group attributed to Russia's General Staff of the Armed Forces, Main Intelligence Directorate (GRU) that has been reportedly active since 2009. Sandworm is known for conducting large scale, well funded, destructive, and aggressive campaigns such as Olympic Destroyer, CrashOverride/Industroyer, and NotPetya...](/sandworm/Intelligence_Summary/Intelligence_Summary.md) |
| [Wizard Spider](/wizard_spider/) | [Wizard Spider is a Russia-based e-crime group originally known for the Trickbot banking malware. In August 2018, Wizard Spider added capabilities to their Trickbot software enabling the deployment of the Ryuk ransomware. This resulted in "big game hunting" campaigns, focused on targeting large organizations for high-ransom return rates.](/wizard_spider/Intelligence_Summary/Intelligence_Summary.md)..    |
|        [OilRig](/oilrig/)        | [OilRig is a cyber threat actor with operations aligning to the strategic objectives of the Iranian government. OilRig has been operational since at least 2014 and has a history of widespread impact, with operations directed against financial, government, energy, chemical, telecommunications and other sectors around the globe...](/oilrig/Intelligence_Summary/Intelligence_Summary.md)                      |
|   [Blind Eagle](/blind_eagle/)   | [Blind Eagle is a South American threat actor focused on Colombia-based institutions, including entities in the financial, manufacturing, and petroleum sectors. Largely opportunistic in their motives, Blind Eagle leverages commodity RATs modified to fit the environment...](/blind_eagle/Intelligence_Summary/Intelligence_Summary.md)                                                                           |
|         [Turla](/turla/)         | [Active since at least the early 2000s, Turla is a sophisticated Russian-based threat group that has infected victims in more than 50 countries. Turla leverages novel techniques and custom tooling and open-source tools to elude defenses and persist on target networks...](/turla/Intelligence_Summary/Intelligence_Summary.md)                                                                                   |
|   [OceanLotus](/ocean_lotus/)    | [OceanLotus is a cyber threat actor aligning to the interests of the Vietnamese government. First seen in 2012, OceanLotus, OceanLotus targets private corporations in the manufacturing, consumer product, and hospitality sectors as well as foreign governments, political dissidents, and journalists....](/ocean_lotus/Intelligence_Summary/Intelligence_Summary.md)                                              |

|                            Micro Emulation Plans                             | Intelligence Summary                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| :--------------------------------------------------------------------------: | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [File Access and File Modification](/micro_emulation_plans/src/file_access/) | Emulate file access and modification behaviors commonly associated with [TA0009 Collection](https://attack.mitre.org/tactics/TA0009/) as well as [T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/). (Data source: [DS0022 File](https://attack.mitre.org/datasources/DS0022/))                                                                                                                                                            |
|            [Named Pipes](/micro_emulation_plans/src/named_pipes/)            | Emulates the creation and use of named pipes [commonly abused by malware](https://labs.withsecure.com/blog/detecting-cobalt-strike-default-modules-via-named-pipe-analysis/) (Data source: [DS0023 Named Pipe](https://attack.mitre.org/datasources/DS0023/))                                                                                                                                                                                                         |
|       [Windows Registry](/micro_emulation_plans/src/windows_registry/)       | Emulates a few common methods that adversaries use to modify the Windows Registry. (Data Source: [DS0024 Windows Registry](https://attack.mitre.org/datasources/DS0024/))                                                                                                                                                                                                                                                                                             |
|              [Web Shells](/micro_emulation_plans/src/webshell/)              | Emulates the compound behavior of planting a web shell ([T1505.003 Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)) and then executing arbitrary commands through it ([T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/))                                                                                                                                                                    |
|      [Process Injection](/micro_emulation_plans/src/process_injection/)      | Emulates the compound behavior of [T1055 Process Injection](https://attack.mitre.org/techniques/T1055/) followed by execution of arbitrary commands ([T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/))                                                                                                                                                                                                                           |
|         [User Execution](/micro_emulation_plans/src/user_execution/)         | Emulates the compound behavior of delivering a malicious `.one`, `.doc`, `.lnk`, or `.iso` file (e.g. via [T1566.001 Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)) and then executing arbitrary commands after a user invokes the file ([T1204.002 User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/) and [T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)). |
|     [Active Directory Enumeration](/micro_emulation_plans/src/ad_enum/)      | Emulate multiple [TA0007 Discovery](https://attack.mitre.org/tactics/TA0007/) behaviors through commonly abused interfaces and services such as Active Directory (AD)                                                                                                                                                                                                                                                                                                 |
|     [Reflective Loading](/micro_emulation_plans/src/reflective_loading/)     | Emulates an adversary performing running malicious code within an arbitrary process to perform [T1620 Reflective Code Loading](https://attack.mitre.org/techniques/T1620/)                                                                                                                                                                                                                                                                                            |
|       [Remote Code Execution](/micro_emulation_plans/src/apache_rce/)        | Emulates an adversary performing remote code execution against a vulnerable web server as documented in [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)                                                                                                                                                                                                                                                                         |
|           [Log Clearing](/micro_emulation_plans/src/log_clearing)            | Emulates an adversary clearing Windows Event Log, as described in [T1070.001 Indicator Removal: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)                                                                                                                                                                                                                                                                                             |
|         [Data Exfiltration](/micro_emulation_plans/src/data_exfil/)          | Emulates the compound behaviors of an adversary finding, staging, archiving, and extracting sensitive files, as described in [TA0010 Exfiltration](https://attack.mitre.org/tactics/TA0010/)                                                                                                                                                                                                                                                                          |
|        [DLL Sideloading](/micro_emulation_plans/src/dll_sideloading/)        | Emulates an adversary executing an otherwise legitimate/benign application in order to hijack its modules/libraries to instead inject their malicious payload, as described in [T1574.002 Hijack Execution Flow: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)                                                                                                                                                                                    |

## Philosophy

These adversary emulation plans are based on known-adversary behaviors and designed to
empower red teams to manually emulate a specific threat actor in order to test and
evaluate defensive capabilities from a threat-informed perspective. This approach
empowers defenders to operationalize cyber threat intelligence to better understand and
combat real-world adversaries. Rather than focusing on static signatures, these
intelligence-driven emulation plans provide a repeatable means to test and tune
defensive capabilities and products against the evolving Tactics, Techniques, and
Procedures (TTPs) of threat actors and malware.

## Adversary Emulation Background

Adversary emulation enables organizations to view their security through the eyes of a
cyber adversary with the goal of improving defenses across the adversary’s lifecycle. As
defenders this expands our attention and focus beyond just the final actions of the
adversary achieving their operational objective to rather understand and appreciate
every distinct behavior (that could have been detected and/or mitigated) leading up to
that point.

Each emulation plan is rooted in intelligence reports and other artifacts that capture
and describe breaches and campaigns publicly attributed to a specific named threat
actor. To develop each plan, we research and model each threat actor, focusing not only
on what they do (ex: gather credentials from victims) but also how (using what specific
tools/utilities/commands?) and when (during what stage of a breach?). We then develop
emulation content that mimics the underlying behaviors utilized by the threat actor
(i.e. not an exact representation, rather capturing the pertinent elements that
accurately generate appropriate test telemetry for defenders). This approach results in
nuanced emulation plans, each capturing unique scenarios and perspectives that we can
leverage as threat-informed defenders.

## Getting Started with Full Adversary Emulation Plans

As is the case with traditional red teaming and penetration testing, adversary emulation
is a specific style of offensive assessment performed to help us test and tune our
defenses. In this case, our objective is to operationalize cyber threat intelligence
describing behaviors observed in specific campaigns or malware samples. From this
intelligence, we select and execute a subset of behaviors (and their variations) to
assess our defenses from the perspective of the specific threat.

As described in the next section, each emulation plan captures specific threat
scenarios. These scenarios can be executed end-to-end, or individual behaviors can be
tested. Organizations can also choose to further customize the scenarios and/or
behaviors within each emulation plan to better fit their specific environment,
priorities, or to be shaped by additional intelligence.

In summary, each full emulation plan should be perceived as input to an offensive
assessment/red team. The content can be used as strict instructions to follow, or as
just a starting point to be built upon and personalized.

### Full Emulation Plan Structure

Each emulation plan focuses on a specific named threat actor. The README of each
individual plan provides a curated summary of available cyber threat intelligence,
composed of an intelligence overview of the actor (describing who they target, how, and
why where possible) as well as the scope of their activity (i.e. breadth of techniques
and malware used). All presented information is cited back to relevant publicly
available cyber threat intelligence and communicated and annotated via
[ATT&CK](https://attack.mitre.org/).

Within each emulation plan, the operational flow provides a high-level summary of the
captured scenario(s). These scenarios will vary based on the adversary and available
intelligence, but typically follow a sequential progression of how the actor breaches
then works towards achieving their operational objectives within a victim environment
(espionage, data/system destruction, etc.).

The content to execute the scenario(s) is broken down into step-by-step procedures
provided in both human and machine-readable formats. Scenarios can be executed
end-to-end or as individual tests. The human-readable formats provide additional
relevant background where possible as well as any setup prerequisites, while the
machine-readable format is designed to be programmatically parsed (ex: read,
reformatted, and ingested into an automated agent, such as
[CALDERA](https://github.com/mitre/caldera) and/or breach simulation frameworks).

Detailed documenation for our full emulation plan structure can be found
[here.](/structure/emulation_plan_structure.md)

## Getting Started with Micro Emulation Plans

Similar to full emulation plans, micro emulation plans are a type of adversary emulation
that is designed to help us test and tune our defenses. However, these plans can be
executed without a red team and without the need for an offensive assessment. Each plan
is still composed of an intelligence overview for the behaviors being emulated, however
we are emulating behaviors that are common across multiple adversaries as opposed to a
singular adversary.

These plans are easy to execute, with no dependencies needed or special configuration of
your environment. All plans can be executed from either a standalone or networked
machine. They can be executed manually or integrated into automation software. We have
provided an example of how to execute a plan with
[CALDERA](/micro_emulation_plans/caldera-integration/), but these plans can be broadly
applied to other platforms.

Each micro plan has default runtime options, however, detailed instructions can be found
on the `README` for each plan on how to customize execution to fit your specific needs.
We have included the source code and `BUILD` instructions for each plan, so that they
can be modified and recompiled, as needed.

The micro plans can be downloaded from the [Releases
page](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/releases).

## Future Work

The threat landscape changes every day, as new groups/malware emerge and known
adversaries adapt and evolve. The Center will continue to populate and maintain this
library to match this growth curve through dedicated research efforts that aim to either
create or update plans based on a specific adversary.

## Questions and Feedback

Please submit issues for any technical questions/concerns or contact
ctid@mitre-engenuity.org directly for more general inquiries.

Also see the guidance for contributors if are interested in
[contributing.](/CONTRIBUTING.md)

## Liability / Responsible Usage

This content is only to be used with appropriate prior, explicit authorization for the
purposes of assessing security posture and/or research.

## Notice

Copyright 2020-2021 MITRE Engenuity. Approved for public release. Document number CT0005

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.

This project makes use of ATT&CK®

[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/)
