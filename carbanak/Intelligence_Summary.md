# Carbanak Intelligence Summary

## ATT&CK Group ID: [G0008](https://attack.mitre.org/groups/G0008/)

## Associated Groups: [Anunak](https://www.fox-it.com/en/news/blog/anunak-aka-carbanak-update/), [Carbon Spider](https://www.crowdstrike.com/blog/state-criminal-address/)

**Objectives:** Carbanak is a threat group who has been found to manipulate financial assets, such as by transferring funds from bank accounts or by taking over ATM infrastructures and instructing them to dispense cash at predetermined time intervals.<sup>[1](https://www.bitdefender.com/files/News/CaseStudies/study/262/Bitdefender-WhitePaper-An-APT-Blueprint-Gaining-New-Visibility-into-Financial-Threats-interactive.pdf)</sup> The group is reported to have been operating as early as 2013 and is still currently active (2021).<sup>[2](https://threatpost.com/alleged-mastermind-behind-carbanak-crime-gang-arrested/130831/)</sup>

**Target Industries:** Carbanak has targeted financial institutions and associated infrastructure. Geographically, Carbanak has compromised targets in over 30 countries, to include Russia, Germany, Ukraine, China, USA, Poland, Bulgaria, Brazil, Iceland, Spain, and more.<sup>[6](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf)</sup> 

**Operations:** Carbanak is known for persistence and operational patience, waiting before executing illicit funds transfers during their campaigns. Carbanak has taken advantage of system users by launching spearphishing attacks in order to get their malware on target. Carbanak has abused the trust of digital signatures by creating a fake identity in order to obtain valid certificates from a certification authority (CA)<sup>[4](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/operation-grand-mars-a-comprehensive-profile-of-carbanak-activity-in-201617/)</sup> for their variant of the Anunak malware, which is also called Carbanak.<sup>[7](https://www.fireeye.com/blog/threat-research/2017/06/behind-the-carbanak-backdoor.html)</sup>  In addition to custom malware, Carbanak has been known to use administrative tools native to the Windows environment, including PowerShell, WMI, and RDP. 

Carbanak is reported to begin most breaches with spearphishing ([T1566.001](https://attack.mitre.org/techniques/T1566/001/)) and social engineering in order to get a legitimate user to download a Microsoft Word document with malicious files embedded in the document. These embedded files allow Carbanak to establish command and control. They are also known to host malicious files on Google Docs and PasteBin ([T1101.002](https://attack.mitre.org/techniques/T1102/002/))<sup>[4](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/operation-grand-mars-a-comprehensive-profile-of-carbanak-activity-in-201617/)</sup> to further expand their command and control. Once on target, Carbanak has been found to rely on using valid accounts ([T1078](https://attack.mitre.org/techniques/T1078/)) to perform most of their actions.<sup>[6](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf)</sup> The group is known to move laterally and escalate their privileges across networks to find critical systems that manage financial transactions.<sup>[1](https://www.bitdefender.com/files/News/CaseStudies/study/262/Bitdefender-WhitePaper-An-APT-Blueprint-Gaining-New-Visibility-into-Financial-Threats-interactive.pdf)</sup> Carbanak has been found to target hosts that have specific banking software that would facilitate the illicit funds transfers.<sup>[6](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf) </sup>The group is reported to then establish persistence using Windows native tools, such as scheduled tasks ([T1053.005](https://attack.mitre.org/techniques/T1053/005/)) and auto-run services ([T1543.003](https://attack.mitre.org/techniques/T1543/003/)), or other non-malicious tools, such as VNC ([T1021.005](https://attack.mitre.org/techniques/T1021/005/)).<sup>[4](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/operation-grand-mars-a-comprehensive-profile-of-carbanak-activity-in-201617/),[8](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/new-carbanak-anunak-attack-methodology/)</sup> From there, Carbanak is known to wait up to four months from initial access before stealing money,<sup>[5](https://securelist.com/the-great-bank-robbery-the-carbanak-apt/68732/)</sup> using this time to expand access and gather instructions for how to initiate the transfers.

Carbanak is sometimes referred to as FIN7, but these appear to be two groups using the same Carbanak malware and are therefore tracked separately.<sup>[9](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html)</sup> As such, activity attributed to FIN7 is beyond the scope of this emulation plan.

---

## Software

Name | Associated Names | Software Type | Availability | Emulation Notes|
|:---:|:---|:---|:---|:---|
Carbanak ([S0030](https://attack.mitre.org/software/S0030/)) | Anunak, Sekur, Carberp | Backdoor | | Carbanak has used Carbanak as a post-exploitation tool to cement their foothold and maintain access to victim environments.<sup>[6](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf)</sup>
GGLDR | | Backdoor | | Carbanak has used a VBScript named "ggldr" that uses Google Apps Script, Sheets, and Forms services for C2.<sup>[13](https://www.forcepoint.com/blog/x-labs/carbanak-group-uses-google-malware-command-and-control)</sup>
Mimikatz ([S0002](https://attack.mitre.org/software/S0002/)) | | Windows Credential Dumper | Openly Available | Carbanak has used Mimikatz to faciliate privilege escalation.<sup>[6](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf), [8](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/new-carbanak-anunak-attack-methodology/)</sup>
netsh ([S0108](https://attack.mitre.org/software/S0108/)) | | System Administration | Present on Windows OS installations by default | Carbanak may use netsh to add local firewall rule exceptions.<sup>[14](https://www.group-ib.com/resources/threat-research/Anunak_APT_against_financial_institutions.pdf)</sup>
PsExec ([S0029](https://attack.mitre.org/software/S0029/)) | | Remote Execution | Openly Available | Carbanak has used PsExec to support execution of remote commands<sup>[10](https://go.rsa.com/l/797543/2019-10-11/35g2/797543/11231/The_Shadows_Of_Ghosts_Carbanak_Report.pdf)</sup>

---

## Carbanak ATT&CK Navigator

#### The following behaviors are in scope for an emulation of actions attributed to Carbanak as referenced by [MITRE ATT&CK](https://attack.mitre.org/groups/G0008/) and in the [referenced reporting](#references).

![/Attack_Layers/Carbanak_G0008.png](/carbanak/Attack_Layers/Carbanak_G0008.png)

## [Scenario 1](/carbanak/Emulation_Plan/Scenario_1/README.md)

#### The following behaviors are in scope for an emulation of actions attributed to Carbanak, as implemented in Scenario 1, in the [referenced reporting](#references).

![/Attack_Layers/Carbanak_Scenario1.png](/carbanak/Attack_Layers/Carbanak_Scenario1.png)

## [Carbanak](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0030%2FS0030-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by the Carbanak group using Carbanak malware, exclusively based on current intelligence within ATT&CK for the given software.

![/Attack_Layers/Carbanak_S0030.png](/carbanak/Attack_Layers/Carbanak_S0030.png)

## [Mimikatz](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0002%2FS0002-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by Carbanak using Mimikatz, exclusively based on current intelligence within ATT&CK for the given software.

![/Attack_Layers/Mimikatz_S0002.png](/carbanak/Attack_Layers/Mimikatz_S0002.png)

## [netsh](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0108%2FS0108-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by Carbanak using netsh, exclusively based on current intelligence within ATT&CK for the given software.

![/Attack_Layers/netsh_S0108.png](/carbanak/Attack_Layers/netsh_S0108.png)

## [PsExec](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0002%2FS0002-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by Carbanak using Mimikatz, exclusively based on current intelligence within ATT&CK for the given software.

![/Attack_Layers/PsExec_S0029.png](/carbanak/Attack_Layers/PsExec_S0029.png)
---

## References

The Intelligence Summary summarizes 19 publicly available sources, as well as the results of an [open call for contributions](https://medium.com/mitre-attack/announcing-2020s-attack-evaluation-6755650b68c2). The following organizations participated in the community cyber threat intelligence contribution process:

- Microsoft

ID | Source | Publisher | Date |
|:---:|:---|:---|:---|
1 | [An APT Blueprint: Gaining New Visibility into Financial Threats](https://www.bitdefender.com/files/News/CaseStudies/study/262/Bitdefender-WhitePaper-An-APT-Blueprint-Gaining-New-Visibility-into-Financial-Threats-interactive.pdf)| [Bitdefender](https://www.bitdefender.com/)| May 2019
2 | [Alleged Mastermind Behind Carbanak Crime Gang Arrested](https://threatpost.com/alleged-mastermind-behind-carbanak-crime-gang-arrested/130831/) | [threatpost](https://threatpost.com) | March 2018
3 | [Arrests Put New Focus on Carbon Spider Adversary Group](https://www.crowdstrike.com/blog/arrests-put-new-focus-on-carbon-spider-adversary-group/) | [CrowdStrike](https://www.crowdstrike.com) | August 2018
4 | [Operation Grand Mars: a comprehensive profile of Carbanak activity in 2016/17](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/operation-grand-mars-a-comprehensive-profile-of-carbanak-activity-in-201617/) | [Trustwave](https://www.trustwave.com) | January 2017
5 | [The Great Bank Robbery: the Carbanak APT](https://securelist.com/the-great-bank-robbery-the-carbanak-apt/68732/) | [Kaspersky](https://securelist.com/) | February 2015
6 | [Carbanak APT: The Great Bank Robbery](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf) | [Kaspersky](https://securelist.com/) | February 2015
7 | [Behind the Carbanak Backdoor](https://www.fireeye.com/blog/threat-research/2017/06/behind-the-carbanak-backdoor.html) | [FireEye](https://www.fireeye.com/) | June 2017
8 | [New Carbanak/Anunak Attack Methodology](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/new-carbanak-anunak-attack-methodology/) | [Trustwave](https://trustwave.com) | November 2016 
9 | [FIN7 Evolution and the Phishing LNK](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html) | [FireEye](https://www.fireeye.com/) | April 2017
10 | [The Shadows of Ghosts Carbanak](https://go.rsa.com/l/797543/2019-10-11/35g2/797543/11231/The_Shadows_Of_Ghosts_Carbanak_Report.pdf) | [RSA](https://www.rsa.com) | November 2017
11 | [ The Carbanak/FIN7 Syndicate: A Historical Overview of an Evolving Threat](https://www.rsa.com/en-us/blog/2017-11/the-carbanak-fin7-syndicate) | [RSA](https://www.rsa.com) | November 2017
12 | [Carbanak Continues To Evolve: Quietly Creeping into Remote Hosts](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/carbanak-continues-to-evolve-quietly-creeping-into-remote-hosts/) | [Trustwave](https://trustwave.com) | April 2017
13 | [Carbanak Group uses Google for malware command-and-control](https://www.forcepoint.com/blog/x-labs/carbanak-group-uses-google-malware-command-and-control) | [Forcepoint](https://www.forcepoint.com) | January 2017
14 |  [Anunak: APT against financial institutions](https://www.group-ib.com/resources/threat-research/Anunak_APT_against_financial_institutions.pdf) | [Group-IB](https://www.group-ib.com/) & [Fox-IT](https://www.fox-it.com/en/) | April 2014
15 | [Здравствуйтэ, Carbanak! A look inside the Carbanak source code](https://www.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s04-hello-carbanak.pdf) | [FireEye](https://www.fireeye.com/) | October 2018
16 | [CARBANAK Week Part Two: Continuing the CARBANAK Source Code Analysis](https://www.fireeye.com/blog/threat-research/2019/04/carbanak-week-part-two-continuing-source-code-analysis.html) | [FireEye](https://www.fireeye.com/) | April 2019
17 | [CARBANAK Week Part Four: The CARBANAK Desktop Video Player](https://www.fireeye.com/blog/threat-research/2019/04/carbanak-week-part-four-desktop-video-player.html) | [FireEye](https://www.fireeye.com/) | April 2019
18 | [Anatomy of an Attack: CARBANAK](https://www.rsa.com/en-us/blog/2017-12/anatomy-of-an-attack-carbanak) | [RSA](https://www.rsa.com) | December 2017
19 | [Cyberthreats to financial institutions 2020: Overview and predictions](https://securelist.com/financial-predictions-2020/95388/) | [Kaspersky](https://securelist.com/) | December 2019

---

## Additional Plan Resources

- [Intelligence Summary](/carbanak/Intelligence_Summary.md)
- [Operations Flow](/carbanak/Operations_Flow.md)
- [Emulation Plan](/carbanak/Emulation_Plan)
  - [Scenario 1 - Infrastructure](/carbanak/Emulation_Plan/Scenario_1/Infrastructure.md)
  - [Scenario 1 - Detections](/carbanak/Emulation_Plan/Scenario_1)
  - [Scenario 2 - Infrastructure](/carbanak/Emulation_Plan/Scenario_2/Infrastructure.md)
  - [Scenario 2 - Protections](/carbanak/Emulation_Plan/Scenario_2)
  - [YAML](/carbanak/Emulation_Plan/yaml)
- [File Hashes](/carbanak/hashes)
- [YARA Rules](/carbanak/yara-rules)
- [Issues](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/issues)
- [Change Log](/carbanak/CHANGE_LOG.md)
