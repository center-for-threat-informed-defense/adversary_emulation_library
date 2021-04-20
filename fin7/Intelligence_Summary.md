# FIN7 Intelligence Summary
--- 
## ATT&CK Group ID: [GOO46](https://attack.mitre.org/groups/G0046/)

**Objectives**: 
FIN7 is a financially-motivated threat group that has been associated with malicious operations dating back to late 2015.<sup>[25](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html)</sup> The group is characterized by their persistent targeting and large-scale theft of payment card data from victim systems, often using social engineering and spearphishing [(T1566)](https://attack.mitre.org/techniques/T1566/) with well-disguised lures to distribute their malware.<sup>[9](https://www.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s05-att&cking-fin7.pdf),[11](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html),[12](https://www.justice.gov/opa/press-release/file/1084361/download),[26](https://www.fireeye.com/blog/threat-research/2017/03/fin7_spear_phishing.html)</sup> Beyond the monetization of victim payment card data, FIN7 has used other diverse monetization tactics, including targeting finance departments within victim organizations and targeting individuals with access to material non-public information that the actors could use to gain a competitve advantage in stock trading.<sup>[11](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html),[26](https://www.fireeye.com/blog/threat-research/2017/03/fin7_spear_phishing.html)</sup>

**Target Industries**: 
FIN7 operations have been directed against victims within the following sectors in the United States and Europe:  restaurants, hospitality, casinos and gaming, energy, finance, high-tech, software, travel, education, construction, retail, telecommunications, government, and business services.<sup>[11](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)</sup>

**Operations**: 
Regarding their operational tradecraft, FIN7 is distinguished by their techincal innovation, using novel techniques and displaying characteristics of a well-rounded operation. FIN7 has been reported to employ limited use of exploits while blending publicly available and unique or altered tools.<sup>[9](https://www.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s05-att&cking-fin7.pdf)</sup> The group has leveraged hidden shortcut files (LNK files) [(T1204.002)](https://attack.mitre.org/techniques/T1204/002/) to initiate infection and VBScript functionality launched by mshta.exe [(T1218.005)](https://attack.mitre.org/techniques/T1218/005/) to infect the victim.<sup>[25](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html)</sup> This is a departure from previously established usage of weaponized Office macros [(T1059.005)](https://attack.mitre.org/techniques/T1059/005/) and highlights the group's ability to adapt to evade detction.<sup>[11](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)</sup>

FIN7 has been reported to use the Carbanak backdoor as a post-exploitation tool since as early as 2015.<sup>[11](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)</sup> The group has also used creative persistence mechanisms, such as application shimming [(T1546.011)](https://attack.mitre.org/techniques/T1546/011/), to spawn a Carbanak backdoor and seprately to install a payment card harvesting utility.<sup>[11](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html),[24](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html)</sup> It has also been reported that the group has developed defense evasion techniques rapidly, such as we creating novel obfuscation methods that in some cases were modified on a daily basis while launching attacks targeting multiple victims.<sup>[11](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)</sup> FireEye dubbed their development of a payload obfuscation style using the Windows command interpreter's native string substitution as "FINcoding."<sup>[11](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)</sup>

FIN7 has also used point-of-sale malware, such as Pillowmint, to scrape track 1 and track 2 payment card data from memory.<sup>[8](https://www.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s05-att&cking-fin7.pdf)</sup> 

---

## FIN7 Software
Name | Associated Names | Software Type | Availability | Emulation Notes
--- | --- | --- | --- |---|
BABYMETAL | | Downloader, Stager | | FIN7 has used BABYMETAL to stage a Meterpreter payload over HTTP(s).<sup>[11](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)</sup> |
BOOSTWRITE ([S0415](https://attack.mitre.org/software/S0415/)) | | Loader | | FIN7 has used BOOSTWRITE as a loader launched via the abuse of DLL search order of applications.<sup>[11](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)</sup> |
Carbanak ([S0030](https://attack.mitre.org/software/S0030/)) | Anunak | Backdoor | | FIN7 has used Carbanak as a post-exploitation tool to cement their foothold and maintain access to victim environments.<sup>[11](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)</sup>|
GRIFFON ([S0417](https://attack.mitre.org/software/S0417/)) | | Backdoor | | FIN7 has used GRIFFON to execute modules in-memory and send results to a C2.<sup>[4](https://securelist.com/fin7-5-the-infamous-cybercrime-rig-fin7-continues-its-activities/90703/)</sup> |
HALFBAKED ([S0151](https://attack.mitre.org/software/S0151/)) | | Backdoor | | FIN7 has used HALFBAKED to establish and maintain a foothold in victim networks.<sup>[25](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html)</sup> |
Mimikatz ([S0002](https://attack.mitre.org/software/S0002/)) | | Windows Credential Dumper | Openly Available | FIN7 has used Mimikatz to facilitate privilege escalation. <sup>[9](https://www.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s05-att&cking-fin7.pdf)</sup> |
PAExec | | Remote Execution | Openly Available | FIN7 has used PAExec to support execution of remote commands.<sup>[9](https://www.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s05-att&cking-fin7.pdf)</sup></sup> |
Pillowmint ([S0517](https://attack.mitre.org/software/S0517/)) | | Point of Sale (POS) Malware  | | FIN7 has used Pillowmint to scrape credit card data from memory.<sup>[9](https://www.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s05-att&cking-fin7.pdf)</sup> |
SQLRat ([S0390](https://attack.mitre.org/software/S0390/)) | | Remote Access Tool (RAT) | | FIN7 has used SQLRat to drop files and execute SQL scripts on victim hosts.<sup>[5](https://www.flashpoint-intel.com/blog/fin7-revisited-inside-astra-panel-and-sqlrat-malware/) |

---

## FIN7 ATT&CK Navigator

#### The following behaviors are in scope for an emulation of actions attributed to FIN7 as referenced by [MITRE ATT&CK](https://attack.mitre.org/groups/G0046/).

![/Attack_Layers/FIN7_G0046.png](/fin7/Attack_Layers/FIN7_G0046.png)

## [Scenario 1](/fin7/Emulation_Plan/Scenario_1/README.md)

#### The following behaviors are in scope for an emulation of actions attributed to FIN7, as implemented in Scenario 1, in the [referenced reporting](#references).

![/Attack_Layers/FIN7_Scenario1.png](/fin7/Attack_Layers/FIN7_Scenario1.png)

## [Scenario 2](/fin7/Emulation_Plan/Scenario_2/README.md)

#### The following behaviors are in scope for an emulation of actions attributed to FIN7, as implemented in Scenario 2, in the [referenced reporting](#references).

![/Attack_Layers/FIN7_Scenario2.png](/fin7/Attack_Layers/FIN7_Scenario2.png)

## [BOOSTWRITE](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0415%2FS0415-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by FIN7 using BOOSTWRITE, exclusively based on current intelligence within ATT&CK for the given software.

![/Attack_Layers/BOOSTWRITE_S0415.png](/fin7/Attack_Layers/BOOSTWRITE_S0415.png)

## [Carbanak](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0030%2FS0030-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by FIN7 using Carbanak, exclusively based on current intelligence within ATT&CK for the given software.

![/Attack_Layers/Carbanak_S0030.png](/fin7/Attack_Layers/Carbanak_S0030.png)

## [GRIFFON](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0417%2FS0417-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by FIN7 using GRIFFON, exclusively based on current intelligence within ATT&CK for the given software.

![/Attack_Layers/GRIFFON_S0417.png](/fin7/Attack_Layers/GRIFFON_S0417.png)

## [HALFBAKED](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0151%2FS0151-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by FIN7 using HALFBAKED, exclusively based on current intelligence within ATT&CK for the given software.

![/Attack_Layers/HALFBAKED_S0151.png](/fin7/Attack_Layers/HALFBAKED_S0151.png)

## [Pillowmint](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0517%2FS0517-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by FIN7 using Pillowmint, exclusively based on current intelligence within ATT&CK for the given software.

![/Attack_Layers/Pillowmint_S0517.png](/fin7/Attack_Layers/Pillowmint_S0517.png)

## [SQLRat](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0390%2FS0390-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by FIN7 using SQLRat, exclusively based on current intelligence within ATT&CK for the given software.

![/Attack_Layers/SQLRat_S0390.png](/fin7/Attack_Layers/SQLRat_S0390.png)

---


## References

The Intelligence Summary summarizes 26 publicly available sources, as well as the results of an [open call for contributions](https://medium.com/mitre-attack/announcing-2020s-attack-evaluation-6755650b68c2). The following organizations participated in the community cyber threat intelligence contribution process:

* Microsoft

ID | Source | Publisher | Date |
|:---:|:---|:---|:---|
1 |[Cyberthreats to Financial Institutions 2020: Overview and Predictions](https://securelist.com/financial-predictions-2020/95388/)|[Kaspersky](https://securelist.com/)| December 2019|
2 |[Mahalo Fin7: Responding to the Criminal Operator's New Tools and Techniques](https://www.fireeye.com/blog/threat-research/2019/10/mahalo-fin7-responding-to-new-tools-and-techniques.html)|[FireEye](https://fireeye.com/)| October 2019|
3 |[Deep Insight into "Fin7" Malware Chain: From Office Macro Malware to Lightweight js Loader](https://labs.sentinelone.com/fin7-malware-chain-from-office-macro-malware-to-lightweight-js-loader/) | [SentinelOne](https://www.sentinelone.com) | October 2019
4 | [FIN7.5: The Infamous CyberCrime RIG "FIN7" Continues its Activities](https://securelist.com/fin7-5-the-infamous-cybercrime-rig-fin7-continues-its-activities/90703/) | [Kaspersky](https://securelist.com)| May 2019
5 | [Fin7 Revisited Inside Astra Panel and SQLRat Malware](https://www.flashpoint-intel.com/blog/fin7-revisited-inside-astra-panel-and-sqlrat-malware/) | [Kaspersky](https://securelist.com)| May 2019
6 | [Profile of an Adversary - FIN7](https://www.deepwatch.com/blog/profile-of-an-adversary-fin7/) | [DeepWatch](https://www.deepwatch.com) | May 2019
7 | [CARBANAK Week Part Four: The CARBANAK Desktop Video Player](https://www.fireeye.com/blog/threat-research/2019/04/carbanak-week-part-four-desktop-video-player.html) | [FireEye](https://www.fireeye.com) | April 2019
8 | [Fin7 Not Finished Morphisec Spots New Campaign](https://blog.morphisec.com/fin7-not-finished-morphisec-spots-new-campaign) | [FireEye](https://www.fireeye.com)| November 2018
9 | [ATT&CKing FIN7: The Value of Using Frameworks for Threat Intelligence](https://www.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s05-att&cking-fin7.pdf) | [FireEye](https://www.fireeye.com)| October 2018
10 | [Carbanak! A Look Inside the Carbanak Source Code](https://www.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s04-hello-carbanak.pdf) | [FireEye](https://www.fireeye.com)| October 2018
11 | [On The Hunt for Fin7: Pursuing an Enigmatic and Evasive Global Crime Operation](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html) | [FireEye](https://www.fireeye.com)| August 2018
12 | [How FIN7 Attacked & Stole Data](https://www.justice.gov/opa/press-release/file/1084361/download) | [Doj](https://justice.gov)| August 2018
13 | [The Carbanak/Fin7 Syndicate: A Historical Overview of an Evolving Threat](https://www.rsa.com/en-us/blog/2017-11/the-carbanak-fin7-syndicate) | [RSA](https://www.rsa.com)| November 2017
14 | [Footprints of Fin7: Pushing New Techniques to Evade Detection](https://blog.gigamon.com/2017/10/08/footprints-of-fin7-pushing-new-techniques-to-evade-detection/) | [Gigamon](https://www.gigamon.com)| October 2017
15 | [Fin7 Weaponization of DDE is just their Latest Slick Move, Say Researchers](https://www.cyberscoop.com/fin7-dde-morphisec-fileless-malware/) | [CyberScoop](https://www.cyberscoop.com)| October 2017
16 | [Fin7 Dissected: Hackers Accelerate Pace of Innovation](https://blog.morphisec.com/fin7-attack-modifications-revealed) | [Morphisec Lab](https://www.morphisec.com)| October 2017
17 | [FIN7 Group Uses JavaScript and Stealer DLL Variant in New Attacks](https://blog.talosintelligence.com/2017/09/fin7-stealer.html#more) | [Talos](https://blog.talosintelligence.com)| September 2017
18 | [Fin7/Carbanak Threat Actor Unleashes Bateleur jScript Backdoor](https://www.proofpoint.com/us/threat-insight/post/fin7carbanak-threat-actor-unleashes-bateleur-jscript-backdoor) | [Proofpoint](https://www.proofpoint.com)| July 2017
19 | [Footprints of Fin7: Tracking Actor Patterns (part 2)](https://blog.gigamon.com/2017/07/26/footprints-of-fin7-tracking-actor-patterns-part-2/) | [Gigamon](https://www.gigamon.com)| July 2017
20 | [Footprints of Fin7: Tracking Actor Patterns (part 1)](https://blog.gigamon.com/2017/07/25/footprints-of-fin7-tracking-actor-patterns-part-1/) | [Gigamon](https://www.gigamon.com)| July 2017
21 | [Behind The CARBANAK Backdoor](https://www.fireeye.com/blog/threat-research/2017/06/behind-the-carbanak-backdoor.html) | [FireEye](https://www.fireeye.com)| June 2017
22 | [Obfuscation in the Wild: Targeted Attackers Lead the Way in Evasion Techniques](https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html) | [FireEye](https://www.fireeye.com)| June 2017
23 | [FIN7 Takes Another Bite at The Resturant Industry](https://blog.morphisec.com/fin7-attacks-restaurant-industry) | [morphisec](https://www.morphisec.com)| June 2017
24 | [To SDB, or Not To SDB: Fin7 Leveraging Shim Databases for Persistence](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html) | [FireEye](https://www.fireeye.com)| May 2017
25 | [Fin7 Evolution and the Phishing LNK](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html) | [FireEye](https://www.fireeye.com)| April 2017
26 | [Fin7 Spearphishing Campaign Targets Personnel Involved in SEC Filings](https://www.fireeye.com/blog/threat-research/2017/03/fin7_spear_phishing.html) | [FireEye](https://www.fireeye.com)| April 2017

---

## Additional Plan Resources

- [Intelligence Summary](/fin7/Intelligence_Summary.md)
- [Operations Flow](/fin7/Operations_Flow.md)
- [Emulation Plan](/fin7/Emulation_Plan)
  - [Scenario 1 - Infrastructure](/fin7/Emulation_Plan/Scenario_1/Infrastructure.md)
  - [Scenario 1 - Detections](/fin7/Emulation_Plan/Scenario_1)
  - [Scenario 2 - Infrastructure](/fin7/Emulation_Plan/Scenario_2/Infrastructure.md)
  - [Scenario 2 - Protections](/fin7/Emulation_Plan/Scenario_2)
  - [YAML](/fin7/Emulation_Plan/yaml)
- [File Hashes](/fin7/hashes)
- [YARA Rules](/fin7/yara-rules)
- [Issues](/issues)
- [Change Log](/fin7/CHANGE_LOG.md)