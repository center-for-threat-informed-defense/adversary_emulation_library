# APT29 Intelligence Summary

## ATT&CK Group ID: [G0016](https://attack.mitre.org/groups/G0016/)

## Associated Groups: [YTTRIUM](https://www.microsoft.com/security/blog/2018/12/03/analysis-of-cyberattack-on-u-s-think-tanks-non-profits-public-sector-by-unidentified-attackers/), [The Dukes](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf), [Cozy Bear](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/), [CozyDuke](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/)

**Objectives:**  APT29 is thought to be an organized and well-resourced cyber threat actor whose collection objectives align with the interests of the Russian Federation.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf),[14](https://www.us-cert.gov/sites/default/files/publications/JAR_16-20296A_GRIZZLY%20STEPPE-2016-1229.pdf)</sup>  The group is reported to have been operating as early as 2008 and may have logged operational successes as recently as 2020.  APT29's objective over time and across a diverse target set appears to have been the exfiltration of information that could be used to inform strategic decision making.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf)</sup>

**Target Industries:**  APT29 operations have been directed against government agencies, embassies, political parties, defense contractors, non-governmental organizations, law enforcement, media, pharmaceutical companies, and think tanks.  Geographically, APT29 has aggressed targets in the United States, Germany, Uzbekistan, South Korea, Turkey, Uganda, Poland, Chechnya, Georgia, Kazakhstan, Kyrgyzstan, Azerbaijan, Uzbekistan, Czech Republic, Belgium, Portugal, Romania, Ireland, and Hungary.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf),</sup><sup>[8](https://www.fireeye.com/blog/threat-research/2018/11/not-so-cozy-an-uncomfortable-examination-of-a-suspected-apt29-phishing-campaign.html),</sup><sup>[11](https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/),</sup><sup>[12](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/),</sup><sup>[15](https://securelist.com/the-cozyduke-apt/69731/),</sup><sup>[16](https://www.microsoft.com/security/blog/2018/12/03/analysis-of-cyberattack-on-u-s-think-tanks-non-profits-public-sector-by-unidentified-attackers/)</sup>

**Operations:**  In terms of operational tradecraft, APT29 is distinguished by their commitment to stealth and use of sophisticated techniques. APT29 is reported to have exploited zero-day vulnerabilities and has pursued actions on the objective using suites of custom malware, coupled with alternate execution methods such as PowerShell and WMI.  APT29 has also been known to employ various operational cadences (smash-and-grab vs. slow-and-deliberate) depending on the target's perceived intelligence value.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf)</sup>

APT29 is reported to have attained initial access by exploiting public-facing applications ([T1190](https://attack.mitre.org/techniques/T1190)), phishing ([T1566.001](https://attack.mitre.org/techniques/T1566/001/),[T1566.002](https://attack.mitre.org/techniques/T1566/002/)), and supply chain compromise ([T1195](https://attack.mitre.org/techniques/T1195)).  The group is reported to have implemented at least two operational cadences, smash-and-grab and slow-and-deliberate.  Different suites of tools and TTPs were employed for each one of these cadences. If a target was determined to be of value, the attackers are reported to have modified TTPs, and deployed a stealthier toolset with the intent or establishing long-term persistent access.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf)</sup>

The objective of smash-and-grab operations appears to have been rapid collection and exfiltration.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf)</sup>  As such, soon after achieving an initial foothold, APT29 actors are reported to have performed host-based situational awareness checks, and immediately sought to collect and exfiltrate data.  If the host was determined to be of value, a stealth toolkit was deployed and persisted.  The attackers are reported to have moved through the network, exfiltrating data and persisting on hosts deemed to be valuable.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf)</sup>

In their smaller more targeted campaigns, APT29 has utilized a different toolset incrementally modified to attempt to evade published intelligence about their operations.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf)</sup>

---
## APT29 ATT&CK Navigator

#### The following behaviors are in scope for an emulation of actions attributed to APT29 as referenced by [MITRE ATT&CK](https://attack.mitre.org/groups/G0016/).

![/Attack_Layers/APT29_Scenario1.png](/apt29/Attack_Layers/APT29_G0016.png)


## [Scenario 1](/Emulation_Plan/Scenario_1/README.md)

#### The following behaviors are in scope for an emulation of actions attributed to APT29, as implemented in Scenario 1, in the [referenced reporting](#references).

![/Attack_Layers/APT29_Scenario1.png](/apt29/Attack_Layers/APT29_Scenario1.png)

## [Scenario 2](/Emulation_Plan/Scenario_2/README.md)

#### The following behaviors are in scope for an emulation of actions attributed to APT29, as implemented in Scenario 2, in the [referenced reporting](#references).

![/Attack_Layers/APT29_Scenario2.png](/apt29/Attack_Layers/APT29_Scenario2.png)

## [CosmicDuke](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0050%2FS0050-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by APT29 using CosmicDuke, exclusively based on current intelligence within ATT&CK for the given software.

![/Attack_Layers/CosmicDuke_S0050.png](/apt29/Attack_Layers/CosmicDuke_S0050.png)

## [MiniDuke](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0051%2FS0051-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by APT29 using MiniDuke, exclusively based on current intelligence within ATT&CK for the given software.

![/Attack_Layers/MiniDuke_S0051.png](/apt29/Attack_Layers/MiniDuke_S0051.png)

## [SeaDuke](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0053%2FS0053-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by APT29 using SeaDuke, exclusively based on current intelligence within ATT&CK for the given software.

![/Attack_Layers/SeaDuke_S0053.png](/apt29/Attack_Layers/SeaDuke_S0053.png)

## [CozyCar](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0046%2FS0046-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by APT29 using CozyCar, exclusively based on current intelligence within ATT&CK for the given software.

![/Attack_Layers/CozyCar_S0046.png](/apt29/Attack_Layers/CozyCar_S0046.png)

## [HammerToss](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0037%2FS0037-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by APT29 using HammerToss, exclusively based on current intelligence within ATT&CK for the given software.

![/Attack_Layers/HAMMERTOSS_S0037.png](/apt29/Attack_Layers/HAMMERTOSS_S0037.png)

## [PowerDuke](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0139%2FS0139-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by APT29 using PowerDuke, exclusively based on current intelligence within ATT&CK for the given software.

![/Attack_Layers/HAMMERTOSS_S0037.png](/apt29/Attack_Layers/PowerDuke_S0139.png)

## [POSHSPY](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0150%2FS0150-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by APT29 using POSHSPY, exclusively based on current intelligence within ATT&CK for the given software.

![/Attack_Layers/HAMMERTOSS_S0037.png](/apt29/Attack_Layers/POSHSPY_S0150.png)

## [CloudDuke]()

#### The following behaviors are in scope for an emulation of actions performed by APT29 using CloudDuke, exclusively based on current intelligence within ATT&CK for the given software.

![/Attack_Layers/HAMMERTOSS_S0037.png](/apt29/Attack_Layers/CloudDuke_S0054.png)

---
## Software

Name | Associated Names | Software Type | Availability | Emulation Notes|
|:---:|:---|:---|:---|:---|
CloudDuke ([S0054](https://attack.mitre.org/software/S0054)) | MiniDionis, CloudLook | Downloader, Loader, Backdoor | | APT29 has used CloudDuke as a backdoor to execute remote commands.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf)</sup> |
Cobalt Strike ([S0154](https://attack.mitre.org/software/S0154))| | Threat Emulation Software | Commercial | A Cobalt Strike beacon was used in a suspected APT29 phishing campaign.<sup>[8](https://www.fireeye.com/blog/threat-research/2018/11/not-so-cozy-an-uncomfortable-examination-of-a-suspected-apt29-phishing-campaign.html)</sup> |
CosmicDuke ([S0050](https://attack.mitre.org/software/S0050)) | TinyBaron, BotgenStudios, NemesisGemina | Information Stealer | | APT29 has used CosmicDuke to perform information gathering and data exfiltration.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf)</sup> |
CozyCar ([S0046](https://attack.mitre.org/software/S0046)) | CozyDuke, CozyBear, Cozer, EuroAPT | Modular Malware Platform | | APT29 has used spear-phishing to infect victims with CozyCar and has used it to gather initial information on victims to determine which ones to continue pursuing further with a different tool.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf)</sup> |
GeminiDuke ([S0049](https://attack.mitre.org/software/S0049)) | | Information Stealer | | APT29 has used GeminiDuke to collect victim computer configuration information.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf)</sup> |
HAMMERTOSS ([S0037](https://attack.mitre.org/software/S0037)) | HammerDuke, NetDuke | Backdoor | | APT29 has used HammerDuke to leave persistent backdoors on compromised networks. C2 communication has occurred over HTTP(S) as well as through Twitter.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf)</sup> |
meek ([S0175](https://attack.mitre.org/software/S0175)) | | Tor Plugin | Openly Available | APT29 has used the Meek plugin for Tor to hide traffic.<sup>[5](https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016)</sup> |
Mimikatz ([S0002](https://attack.mitre.org/software/S0002)) | | Windows Credential Dumper | Openly Available | APT29 has used CozyDuke to download Mimikatz, along with script files to execute Mimikatz.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf)</sup> |
MiniDuke ([S0051](https://attack.mitre.org/software/S0051)) | | Backdoor, Downloader | | APT29 has used MiniDuke as a backdoor to remotely execute commands on compromised systems.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf)</sup> |
OnionDuke ([S0052](https://attack.mitre.org/software/S0052)) | | Malware Toolset| | APT29 has used OnionDuke to steal credentials, gather information, and perform denial of service attacks.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf)</sup> |
PinchDuke ([S0048](https://attack.mitre.org/software/S0048)) | | Information Stealear | | APT29 has used PinchDuke to steal information such as system configuration information, user credentials, and user files.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf)</sup> |
POSHSPY ([S0150](https://attack.mitre.org/software/S0150)) | | Backdoor | | APT29 has used POSHSPY as a secondary backdoor that uses PowerShell and Windows Management Instrumentation.|
PowerDuke ([S0139](https://attack.mitre.org/software/S0139)) | | Backdoor | | APT29 has delivered PowerDuke through malicious document macros. |
PsExec ([S0029](https://attack.mitre.org/software/S0029)) | | Remote Execution | Openly Available | APT29 has used CozyDuke to download PsExec, along with script files to execute PsExec.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf)</sup> |
SDelete ([S0195](https://attack.mitre.org/software/S0195)) | | Secure Delete Application | Openly Available | APT29 has used SDelete to attempt to cover their tracks.<sup>[5](https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016)</sup> |
SeaDuke ([S0053](https://attack.mitre.org/software/S0053)) | SeaDaddy, SeaDesk | Backdoor | | APT29 appears to have used SeaDuke as a secondary backdoor and to target both Windows and Linux systems.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf)</sup> |
Tor ([S0183](https://attack.mitre.org/software/S0183)) | | Proxy Tool | Openly Available | APT29 has used TOR to hide their remote access.<sup>[5](https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016)</sup> |

---

## References

This Intelligence Summary summarizes 16 publicly available sources, as well as the results of an [open call for contributions](https://medium.com/mitre-attack/open-invitation-to-share-cyber-threat-intelligence-on-apt29-for-adversary-emulation-plan-831c8c929f31). The following organizations participated in the community cyber threat intelligence contribution process:

- Kaspersky
- Microsoft
- SentinelOne

ID | Source | Publisher | Date |
|:---:|:---|:---|:---|
1 |[The Dukes: 7 Years of Russian Cyberespionage](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf)|[F-Secure](https://www.f-secure.com/us-en)| September 2017 |
2 |[COSMICDUKE: Cosmu with a twist of MiniDuke](https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163405/CosmicDuke.pdf)|[F-Secure](https://www.f-secure.com/us-en)| July 2014  |
3 |[The MiniDuke Mystery: PDF 0-day Government Spy Assembler 0x29A Micro Backdoor](https://securelist.com/the-miniduke-mystery-pdf-0-day-government-spy-assembler-0x29a-micro-backdoor/31112/)|[Kaspersky](https://securelist.com/)| February 2013 |
4 |[Unit 42 Technical Analysis: Seaduke](https://unit42.paloaltonetworks.com/unit-42-technical-analysis-seaduke/)|[Palo Alto](https://unit42.paloaltonetworks.com/)| July 2015 |
5 |[DerbyCon: No Easy Breach](https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016)|[FireEye](https://www.fireeye.com/)| September 2016 |
6 |[HAMMERTOSS: Stealthy Tactics Define a Russian Cyber Threat Group](https://www.fireeye.com/blog/threat-research/2015/07/hammertoss_stealthy.html)|[FireEye](https://www.fireeye.com/)| July 2015 |
7 |[State of the Hack S2E01: #NoEasyBreach REVISITED](https://www.fireeye.com/blog/products-and-services/2019/02/state-of-the-hack-no-easy-breach-revisited.html)|[FireEye](https://www.fireeye.com/)| January 2019 |
8 |[Not So Cozy: An Uncomfortable Examination of a Suspected APT29 Phishing Campaign](https://www.fireeye.com/blog/threat-research/2018/11/not-so-cozy-an-uncomfortable-examination-of-a-suspected-apt29-phishing-campaign.html)|[FireEye](https://www.fireeye.com/)| November 2018 |
9 |[VirusTotal Submission 2f39dee2ee608e39917cc022d9aae399959e967a2dd70d83b81785a98bd9ed36](https://www.virustotal.com/gui/file/2f39dee2ee608e39917cc022d9aae399959e967a2dd70d83b81785a98bd9ed36)|[VirusTotal](https://www.virustotal.com/gui/intelligence-overview)| January 2015 |
10 |[Dissecting One of APT29’s Fileless WMI and PowerShell Backdoors (POSHSPY)](https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html)|[FireEye](https://www.fireeye.com/)| April 2017 |
11 |[PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs](https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/)|[Volexity](https://www.volexity.com/)| November 2016 |
12 |[Crowdstrike's work with the Democratic National Committee: Setting the record straight](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/)|[CrowdStrike](https://www.crowdstrike.com/)| June 2016 |
13 |["Forkmeiamfamous": Seaduke, latest weapon in the Duke armory](https://web.archive.org/web/20181008161626/https://www.symantec.com/connect/blogs/forkmeiamfamous-seaduke-latest-weapon-duke-armory)|[Symantec](https://securitycloud.symantec.com/)| July 2015 |
14 |[GRIZZLY STEPPE - Russian Malicious Cyber Activity](https://www.us-cert.gov/sites/default/files/publications/JAR_16-20296A_GRIZZLY%20STEPPE-2016-1229.pdf)|[CISA](https://www.cisa.gov/) / [FBI](https://www.fbi.gov/)| December 2016 |
15 |[The CozyDuke APT](https://securelist.com/the-cozyduke-apt/69731/)|[Kaspersky](https://securelist.com/)| April 2015 |
16 |[Analysis of cyberattack on U.S. think tanks, non-profits, public sector by unidentified attackers](https://www.microsoft.com/security/blog/2018/12/03/analysis-of-cyberattack-on-u-s-think-tanks-non-profits-public-sector-by-unidentified-attackers/)|[Microsoft](https://www.microsoft.com/)| December 2018 |

---

## Additional Plan Resources

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
