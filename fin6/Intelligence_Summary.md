
# FIN6 Intelligence Summary

## ATT&CK Group ID: [G0037](https://attack.mitre.org/groups/G0037/)

## Associated Groups: [ITG08](https://exchange.xforce.ibmcloud.com/threat-group/f8409554b71a79792ff099081bc5ac24), [SKELETON SPIDER](https://go.crowdstrike.com/rs/281OBQ266/images/Report2018GlobalThreatReport.pdf), [Magecart Group 6](https://blog.trendmicro.com/trendlabs-security-intelligence/fin6-compromised-e-commerce-platform-via-magecart-to-inject-credit-card-skimmers-into-thousands-of-online-shops/), [MAZE Group 3](https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html)

**Objectives and Evolution:**  FIN6 is thought to be a financially motivated cyber-crime group. As such, they appear to take a pragmatic approach toward targeting and exploitation.  Their strategic objective over time and across a diverse target set remains the same, monetizing compromised environments.  Early on, FIN6 used social engineering to gain unauthorized access to targets that process high-volume point-of-sale (PoS) transactions.  The group had some high-profile success and presumably monetized the compromised credit card information on the dark web.  The widespread implementation of point-to-point encryption (P2PE) and Europay, Mastercard, and Visa (EMV) may have been a catalyst for operational adjustment.<sup>[8](https://securityintelligence.com/posts/itg08-aka-fin6-partners-with-trickbot-gang-uses-anchor-framework/)</sup>

Since 2018, FIN6 has been associated with Magecart Group 6.<sup>[10](https://blog.trendmicro.com/trendlabs-security-intelligence/fin6-compromised-e-commerce-platform-via-magecart-to-inject-credit-card-skimmers-into-thousands-of-online-shops/)</sup>  Magecart is cyber-crime activity directed against e-commerce sites.  The attackers inject a skimmer script into the website's checkout page to pilfer payment information provided by unsuspecting customers.<sup>[10](https://blog.trendmicro.com/trendlabs-security-intelligence/fin6-compromised-e-commerce-platform-via-magecart-to-inject-credit-card-skimmers-into-thousands-of-online-shops/)</sup>  If FIN6 is responsible for this activity, this would demonstrate the group's willingness to modify TTPs to continue to achieve operational success.

In 2019, vendors reported what appeared to be FIN6 TTPs directed against organizations that do not process PoS data.<sup>[4](https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html)</sup> The methods by which the aggressors achieved their tactical objectives were consistent with those historically associated with FIN6 however, the group's operational objectives had evolved once more.  After gaining access to the environment, conducting reconnaissance, escalating privileges, and moving laterally, the group deployed ransomware.<sup>[4](https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html)</sup>  Most recently, FIN6 has been associated with MAZE Group 3.<sup>[12](https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html)</sup>  This continued use of ransomware could confirm a strategic deviation from theft to extortion in order to expand sources of revenue and stay profitable.  

**Target Industries:**  The group has aggressively targeted and compromised high-volume POS systems in the hospitality and retail sectors since at least 2015.<sup>[5](https://exchange.xforce.ibmcloud.com/threat-group/f8409554b71a79792ff099081bc5ac24)</sup>  FIN6 has targeted e-commerce sites and multinational organizations.  Most of the group’s targets have been located in the United States and Europe, but include companies in Australia, Canada, Spain, India, Kazakhstan, Serbia, and China.<sup>[5](https://exchange.xforce.ibmcloud.com/threat-group/f8409554b71a79792ff099081bc5ac24)</sup>  Most recently, the group is reported to be deploying ransomware.  Industry and geography are of little consequence for operations that leverage extortion to monetize compromised environments.

**Operations:**  FIN6 has been known to attain initial access to target organizations by using legitimate but compromised credentials [(T1078)](https://attack.mitre.org/techniques/T1078/) coupled with legitimate remote access applications [(T1133)](https://attack.mitre.org/techniques/T1133/), and spearphishing [(T1566.001)](https://attack.mitre.org/techniques/T1566/001/), [(T1566.002)](https://attack.mitre.org/techniques/T1566/002/), [(T1566.003)](https://attack.mitre.org/techniques/T1566/003/). Most recently, FIN6 may have been purchasing access to environments previously compromised with TrickBot.<sup>[8](https://securityintelligence.com/posts/itg08-aka-fin6-partners-with-trickbot-gang-uses-anchor-framework/)</sup> Once inside the target organization, FIN6 uses a variety of open and closed-source red team tools, custom scripts [(T1059)](https://attack.mitre.org/techniques/T1059/), and commodity malware in support of tactical objectives.

FIN6’s tactical objectives are to identify systems for staging, reconnoiter active directory environments [(T1046)](https://attack.mitre.org/techniques/T1046/), [(T1069)](https://attack.mitre.org/techniques/T1069/), escalate privileges [(T1068)](https://attack.mitre.org/techniques/T1068/) (often via credential access [(T1078)](https://attack.mitre.org/techniques/T1078/)), and identify systems that align with operational objectives.<sup>[5](https://exchange.xforce.ibmcloud.com/threat-group/f8409554b71a79792ff099081bc5ac24)</sup>    More_eggs [(S0284)](https://attack.mitre.org/software/S0284/), a lightweight JScript implant has been used during the initial stages of compromise to conduct host enumeration [(T1018)](https://attack.mitre.org/techniques/T1018/), establish command and control (C2), and to download and execute additional tools [(T1105)](https://attack.mitre.org/techniques/T1105/).<sup>[9](https://securityintelligence.com/posts/more_eggs-anyone-threat-actor-itg08-strikes-again/)</sup>  FIN6 frequently uses Metasploit or Cobalt Strike [(S0154)](https://attack.mitre.org/software/S0154/) for their primary post-exploitation C2 framework, though sometimes employing a degree of customization to increase difficulty in detection.<sup>[4](https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html)</sup> To that end, FIN6 has used code-signing certificates to evade defenses [(T553.002)](https://attack.mitre.org/techniques/T1553/002/).  

Run keys [(T1547.001)](https://attack.mitre.org/techniques/T1547/001/) and scheduled tasks [(T1053.005)](https://attack.mitre.org/techniques/T1053/005/) have been used for adversary persistence.<sup>[7](https://blog.morphisec.com/new-global-attack-on-point-of-sale-systems)</sup> FIN6 tends to use tools that are indicative of routine administrative tasks.  For instance, FIN6 has moved laterally using valid accounts [(T1078)](https://attack.mitre.org/techniques/T1078/) coupled with Remote Desktop Protocol (RDP) [(T1021.001)](https://attack.mitre.org/techniques/T1021/001/), various implementations of PsExec [(S0029)](https://attack.mitre.org/software/S0029/), PowerShell [(T1059.001)](https://attack.mitre.org/techniques/T1059/001/), [(T1059)](https://attack.mitre.org/techniques/T1059/), and Windows Management Instrumentation (WMI) [(T1047)](https://attack.mitre.org/techniques/T1047/).  The group will dump credentials [(T1003)](https://attack.mitre.org/techniques/T1003/) as they move through an environment but have also exfiltrated copies of the Active Directory (AD) database file NTDS.dit utilizing the Metasploit NTDSGRAB module [(T1003.003)](https://attack.mitre.org/techniques/T1003/003/).<sup>[5](https://exchange.xforce.ibmcloud.com/threat-group/f8409554b71a79792ff099081bc5ac24)</sup>  FIN6 has exfiltrated this reconnaissance data to servers it controls using SSH [(T1048.002)](https://attack.mitre.org/techniques/T1048/002/).<sup>[5](https://exchange.xforce.ibmcloud.com/threat-group/f8409554b71a79792ff099081bc5ac24)</sup>  These actions are intended to enable FIN6’s operational objective of monetizing compromised environments.

Depending on the target, FIN6 may identify Point of Sale (POS) systems and use their access to deploy POS malware such as TRINITY. This malware will search process memory, looking for payment card data to harvest [(T1005)](https://attack.mitre.org/techniques/T1005/). FIN6 will then obfuscate collected data [(T1027)](https://attack.mitre.org/techniques/T1027/) and move it to other compromised systems to be compressed [(T1560)](https://attack.mitre.org/techniques/T1560/) and staged for exfiltration [(T1074.002)](https://attack.mitre.org/techniques/T1074/002/).<sup>[5](https://exchange.xforce.ibmcloud.com/threat-group/f8409554b71a79792ff099081bc5ac24)</sup>  FIN6 has also been known to exploit public-facing applications [(T1190)](https://attack.mitre.org/techniques/T1190/) and insert malicious code into the checkout pages of compromised sites to steal payment card information.<sup>[10](https://blog.trendmicro.com/trendlabs-security-intelligence/fin6-compromised-e-commerce-platform-via-magecart-to-inject-credit-card-skimmers-into-thousands-of-online-shops/)</sup>

In more recent campaigns, FIN6 has used its access to deploy ransomware. FIN6 may stage ransomware and automated deployment scripts [(T1072)](https://attack.mitre.org/techniques/T1072/) on victim servers [(T1080)](https://attack.mitre.org/techniques/T1080/); these scripts may call utilities like PsExec [(S0029)](https://attack.mitre.org/software/S0029/) to deploy ransomware such as LockerGoga [(S0372)](https://attack.mitre.org/software/S0372) to as many machines as possible at the same time. FIN6 may try to acquire Domain Administrator credentials to achieve maximum success with PsExec [(S0029)](https://attack.mitre.org/software/S0029/) deployment or so they can use Group Policy Modification [(T1484)](https://attack.mitre.org/techniques/T1484/) to distribute the ransomware via AD group policies.<sup>[4](https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html)</sup>

--- 

## FIN6 Software

Name | Associated Names | Software Type | Availability | Emulation Notes
--- | --- | --- | --- |---|
Cobalt Strike [(S0154)](https://attack.mitre.org/software/S0154) | | Threat Emulation Software | Commercial | FIN6 uses CobaltStrike to realize tactical objectives during the initial phases of an intrusion.
Metasploit | | Penetration Testing Software | Openly Available | FIN6 has used Metasploit's Meterpreter and other tools within the framework to achieve tactical objectives.
LockerGoga [(S0372)](https://attack.mitre.org/software/S0372) | | Ransomware | Malware-as-a-Service (MaaS) | FIN6 deploys POS/Ransomware on systems of interest in support of operational objectives.
Mimikatz [(S0002)](https://attack.mitre.org/software/S0002)| | Windows Credential Dumper | Openly Available | FIN6 is reported to use the credential dumping capability of Mimikatz.
More_eggs [(S0284)](https://attack.mitre.org/software/S0284) | | Remote Access Tool (RAT) | MaaS | Used to expand access and persist on a compromised network.
PsExec [(S0029)](https://attack.mitre.org/software/S0029)| | Remote Execution | Openly Available | FIN6 appears to be using Cobaltstrike’s PsExec_psh module for lateral movement.
Windows Credential Editor [(S0005)](https://attack.mitre.org/software/S0005)| | Windows Credential Dumper | Openly Available | One of three methods FIN6 uses to compromise credentials.
FrameworkPOS | TRINITY | Point of Sale (POS) Malware | | POS malware commonly used by FIN6 to achieve operational objectives.
TerraLoader | SpiceyOmlette | Loader | MaaS | FIN6 uses TerraLoader to download and execute more_eggs and Metasploit stages.
PowerTrick | | Backdoor | MaaS | FIN6 is believed to have used PowerTrick to download TerraLoader, which subequently installs more_eggs or Metasploit.
MAZE | | Ransomware | MaaS | The group is thought to have deployed MAZE ransomware in compromised environments.

---

## FIN6 ATT&CK Navigator

#### The following behaviors are in scope for an emulation of actions attributed to FIN6 in the [referenced reporting](#references).

![/Attack_Layers/FIN6_G0037.png](/fin6/Attack_Layers/FIN6_G0037.png)

## [Cobalt Strike (S0154)](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0154%2FS0154-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by FIN6 using Cobalt Strike, exclusively based on current intelligence within ATT&CK.

![/Attack_Layers/Cobalt_Strike_S0154.png](/fin6/Attack_Layers/Cobalt_Strike_S0154.png)

## [LockerGoga (S0372)](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0372%2FS0372-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by FIN6 using LockerGoga, exclusively based on current intelligence within ATT&CK.

![/Attack_Layers/LockerGoga_S0372.png](/fin6/Attack_Layers/LockerGoga_S0372.png)

## [Mimikatz (S0002)](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0002%2FS0002-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by FIN6 using Mimikatz, exclusively based on current intelligence within ATT&CK.

![/Attack_Layers/Mimikatz_S0002.png](/fin6/Attack_Layers/Mimikatz_S0002.png)

## [More_eggs (S0284)](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0284%2FS0284-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by FIN6 using More_eggs, exclusively based on current intelligence within ATT&CK.

![/Attack_Layers/More_eggs_S0284.png](/fin6/Attack_Layers/More_eggs_S0284.png)

## [PsExec (S0029)](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0029%2FS0029-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by FIN6 using PsExec, exclusively based on current intelligence within ATT&CK.

![/Attack_Layers/PsExec_S0029.png](/fin6/Attack_Layers/PsExec_S0029.png)

## [Windows Credential Editor (S0005)](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0005%2FS0005-enterprise-layer.json)

#### The following behaviors are in scope for an emulation of actions performed by FIN6 using Windows Credential Editor, exclusively based on current intelligence within ATT&CK.

![/Attack_Layers/Windows_Credential_Editor_S0005.png](/fin6/Attack_Layers/Windows_Credential_Editor_S0005.png)

---

## References

ID | Source | Publisher | Date |
:---:|:---|:---|:---|
1 |[MITRE ATT&CK: FIN6](https://attack.mitre.org/groups/G0037/)|[The MITRE Corporation](https://www.mitre.org/) | May 2017 |
2 |[2018 Global Threat Report](https://go.crowdstrike.com/rs/281-OBQ-266/images/Report2018GlobalThreatReport.pdf)|[Crowdstrike](https://www.crowdstrike.com/) |September 2017|
3 |[Follow The Money: Dissecting the Operations of the Cyber Crime Group FIN6](https://www2.fireeye.com/rs/848-DID-242/images/rpt-fin6.pdf)|[FireEye](https://www.fireeye.com/)| April 2016 |
4 |[Pick-Six: Intercepting a FIN6 Intrusion](https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html)|[FireEye](https://www.fireeye.com/) | April 2019 |
5 |[ITG08 Analysis Report](https://exchange.xforce.ibmcloud.com/threat-group/f8409554b71a79792ff099081bc5ac24)|[IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com) | November 2019 |
6 |[FIN6 group goes from compromising PoS systems to deploying ransomware](https://cyware.com/news/fin6-group-goes-from-compromising-pos-systems-to-deploying-ransomware-3e9d0691)|[Cyware](https://cyware.com/)| April 2019 |
7 |[New Global Cyber Attack on Point of Sale Systems](https://blog.morphisec.com/new-global-attack-on-point-of-sale-systems)|[Morphisec](https://www.morphisec.com/) | February 2019 |
8 |[ITG08 (aka FIN6) Partners With TrickBot Gang, Uses Anchor Framework](https://securityintelligence.com/posts/itg08-aka-fin6-partners-with-trickbot-gang-uses-anchor-framework/)|[Security Intelligence](https://securityintelligence.com/)| April 2020|
9 |[More_eggs, Anyone? Threat Actor ITG08 Strikes Again](https://securityintelligence.com/posts/more_eggs-anyone-threat-actor-itg08-strikes-again)|[Security Intelligence](https://securityintelligence.com/) | August 2019 |
10 |[FIN6 Compromised E-commerce Platform via Magecart to Inject Credit Card Skimmers Into Thousands of Online Shops](https://blog.trendmicro.com/trendlabs-security-intelligence/fin6-compromised-e-commerce-platform-via-magecart-to-inject-credit-card-skimmers-into-thousands-of-online-shops/)|[Trendmicro](https://www.trendmicro.com/en_us/business.html)| October 2019 |
11 |[Fake Jobs: Campaigns Delivering More_eggs Backdoor via Fake Job Offers](https://proofpoint.com/us/threat-insight/post/fake-jobs-campaigns-delivering-moreeggs-backdoor-fake-job-offers)|[Proofpoint](https://proofpoint.com/us) | February 2019 |
12 | [Navigating the MAZE: Tactics, Techniques, and Procedures Associated With MAZE Ransomware Incidents](https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html)|[FireEye](https://www.fireeye.com/)| May 2020
13 | [FIN6 Cybercrime Group Expands Threat to eCommerce Merchants](https://usa.visa.com/dam/VCOM/global/support-legal/documents/fin6-cybercrime-group-expands-threat-To-ecommerce-merchants.pdf)|[VISA](https://usa.visa.com)| February 2019
14 | [Inside the Magecart Breach of British Airways: How 22 Lines of Code Claimed 380,000 Victims](https://riskiq.com/blog/labs/magecart-british-airways-breach/)| [RiskIQ](https://riskiq.com)| September 2018
15 | [Another Victim of the Magecart Assault Emerges: Newegg](https://riskiq.com/blog/labs/magecart-newegg/)| [RiskIQ](https://riskiq.com)| September 2018

---

## Next Steps

- [FIN6 Operations Flow](/fin6/Operations_Flow.md)
- [FIN6 Phase 1](/fin6/Emulation_Plan/Phase1.md)
