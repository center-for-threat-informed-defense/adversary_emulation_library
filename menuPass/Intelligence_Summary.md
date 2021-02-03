# menuPass Intelligence Summary

## ATT&CK Group ID: [G0045](https://attack.mitre.org/groups/G0045/)

## Associated Groups: [Stone Panda](https://crowdstrike.com/blog/two-birds-one-stone-panda/), [APT10](https://fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html), [Red Apollo](https://justice.gov/opa/press-release/file/1121706/download), [CVNX](https://fbi.gov/wanted/cyber/zhu-hua), [HOGFISH](https://www.accenture.com/t20180423T055005Z_s_/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf), [BRONZE RIVERSIDE](https://secureworks.com/research/threat-profiles/bronze-riverside)

**Objectives:** menuPass is thought to be motivated by collection objectives that align with Chinese national interests.  Their operational objective over time and across a diverse target set appears to be intellectual property theft.  A 2018 indictment issued by the United States Department of Justice suggests at least a portion of the activity attributed to menuPass was carried out by two employees of Huaying Haitai Science and Technology Development Company.  These individuals are believed to have been working at the behest of the Chinese Ministry of State Security’s (MSS) Tianjin State Security Bureau.<sup>[6](https://justice.gov/opa/press-release/file/1121706/download)</sup> <sup>[14](https://crowdstrike.com/blog/two-birds-one-stone-panda/)</sup> <sup>[17](https://intrusiontruth.wordpress.com/2018/08/15/apt10-was-managed-by-the-tianjin-bureau-of-the-chinese-ministry-of-state-security/)</sup> menuPass is reported to have been active since at least 2009 but may have been operating as early as 2006.<sup>[6](https://justice.gov/opa/press-release/file/1121706/download)</sup>

**Target Industries:** The indicted menuPass actors were charged with one count each of conspiracy to commit computer intrusions.  The document discloses two campaigns attributed to these actors.  The first campaign is reported to have begun in 2006, and is thought to have been motivated by technology theft.  These efforts were directed against NASA's Jet Propulsion Laboratory (JPL) and organizations in aviation, space, communications, manufacturing, maritime, oil and gas.<sup>[6](https://justice.gov/opa/press-release/file/1121706/download)</sup>

The second campaign, is thought to have begun in 2014 and initially targeted Managed Service Providers (MSPs).  The group targeted MSPs for the purpose of pivoting into MSP customer networks.  This campaign resulted in the compromise of organizations in banking and finance, telecommunications, medical equipment, manufacturing, consulting, healthcare, biotechnology, automotive, oil, gas exploration, and mining.<sup>[6](https://justice.gov/opa/press-release/file/1121706/download)</sup>

In addition to the two campaigns listed in the 2018 indictment, menuPass actors are reported to have targeted public and private sector entities in at least 12 other countries.  Aside from targeting organizations based in the United States, the group is perhaps best known for its extensive and sustained efforts against Japanese institutions.  menuPass actors are reported to have targeted public and private interests alike, to include public policy organizations, educational institutions, media, and technology firms.<sup>[16](https://trendmicro.com/en_us/research/18/c/chessmaster-adds-updated-tools-to-its-arsenal.html)</sup>

Researchers have suggested menuPass targeting may broadly align with China’s strategic objectives as stated in the Five-Year Plan (FYP) / Made in China 2025 Plan.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> menuPass is thought to have pursued these objectives over disparate but concurrent campaigns.  From 2016 – 2018, menuPass actors are thought to have been engaged in operations directed against various MSPs, Japanese institutions, manufacturing companies in India and Europe, a mining company in South America, a U.S. based law firm, an international apparel company, and several other targets in Europe, the Middle East, and Africa.<sup>[1](https://unit42.paloaltonetworks.com/unit42-menupass-returns-new-malware-new-attacks-japanese-academics-organizations/)</sup> <sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> <sup>[5](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)</sup> <sup>[6](https://www.justice.gov/opa/press-release/file/1121706/download)</sup> <sup>[8](https://www.accenture.com/t20180423T055005Z_s_/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf)</sup> <sup>[9](https://fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html)</sup> <sup>[10](https://recordedfuture.com/apt10-cyberespionage-campaign/)</sup> <sup>[11](https://blog.trendmicro.com/trendlabs-security-intelligence/chessmaster-cyber-espionage-campaign/)</sup> <sup>[12](https://us-cert.cisa.gov/ncas/alerts/TA17-117A)</sup> <sup>[13](https://blogs.blackberry.com/en/2019/06/threat-spotlight-menupass-quasarrat-backdoor)</sup>

**Operations:** menuPass actors are reported to have pursued initial access by spearphishing to achieve user execution ([T1204.002](https://attack.mitre.org/techniques/T1204/002/)).<sup>[1](https://unit42.paloaltonetworks.com/unit42-menupass-returns-new-malware-new-attacks-japanese-academics-organizations/)</sup> <sup>[6](https://www.justice.gov/opa/press-release/file/1121706/download)</sup> <sup>[8](https://www.accenture.com/t20180423T055005Z_s_/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf)</sup> <sup>[9](https://fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html)</sup> <sup>[11](https://blog.trendmicro.com/trendlabs-security-intelligence/chessmaster-cyber-espionage-campaign/)</sup> <sup>[15](http://blog.trendmicro.com/trendlabs-security-intelligence/chessmasters-new-strategy-evolving-tools-tactics/)</sup> <sup>[16](https://trendmicro.com/en_us/research/18/c/chessmaster-adds-updated-tools-to-its-arsenal.html)</sup> <sup>[20](https://lac.co.jp/lacwatch/people/20170223_001224.html)</sup> <sup>[21](https://lac.co.jp/lacwatch/people/20180521_001638.html)</sup>  menuPass spearphishing attempts generally assume a pretext that would be of interest to the intended target and are reported to have featured password protected Microsoft Word documents embedded with VBA macros ([T1566.001](https://attack.mitre.org/techniques/T1566/001/)), an executable attachment that exploits a vulnerability ([T1566.001](https://attack.mitre.org/techniques/T1566/001/)), or a link that points to a payload server ([T1566.002](https://attack.mitre.org/techniques/T1566/002/)).<sup>[16](https://trendmicro.com/en_us/research/18/c/chessmaster-adds-updated-tools-to-its-arsenal.html)</sup>  Once inside the target organization, menuPass actors have used a variety of open-source, modified open-source, and custom tools to perform discovery, escalate privileges, access credentials, move laterally, and exfiltrate data.

"Operation Cloud Hopper," was a long-term persistent effort to compromise MSPs with the intent of abusing trust relationships in order to pivot into customer networks.([T1199](https://attack.mitre.org/techniques/T1199/)).<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> <sup>[5](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)</sup> <sup>[6](https://www.justice.gov/opa/press-release/file/1121706/download)</sup> <sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup> <sup>[10](https://recordedfuture.com/apt10-cyberespionage-campaign/)</sup> <sup>[12](https://us-cert.cisa.gov/ncas/alerts/TA17-117A)</sup>  menuPass actors are thought to have achieved initial access to MSP networks by spearphishing.  From the MSP networks, menuPass actors are reported to have used legitimate but compromised local accounts ([T1078.003](https://attack.mitre.org/techniques/T1078/003/)) coupled with legitimate remote access applications ([T1133](https://attack.mitre.org/techniques/T1133/)) to access customer environments.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> <sup>[5](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)</sup> <sup>[6](https://www.justice.gov/opa/press-release/file/1121706/download)</sup> <sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup> <sup>[10](https://recordedfuture.com/apt10-cyberespionage-campaign/)</sup> <sup>[12](https://us-cert.cisa.gov/ncas/alerts/TA17-117A)</sup>  From this initial point of presence, menuPass actors are reported to have used administrative tools native to the Windows environment to download an operational toolkit from an attacker controlled server.  This toolkit enabled the pursuit of tactical objectives with the operational intent of exfiltrating intellectual property.  This activity will serve as the basis for Scenario 1.

menuPass is also reported to have engaged in phishing campaigns, the most prolific of which were directed against Japanese institutions.  Successful compromise resulted in the deployment of menuPass malware to the victim network and the establishment of command and control.  menuPass malware has been categorized by the manner in which it was employed by menuPass actors and not necessarily by the malware's inherent functionality.  PWC categorized menuPass malware as tactical or sustained.<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>  Tactical malware is usually deployed during delivery, or upon initial access, and is intended to perform lightweight tasks, such as discovery and execution.<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>  Sustained malware is often modular and has an enhanced set of features.<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>  Sustained malware is deployed to specific systems to facilitate a long-term point of presence.<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>  menuPass is reported to have leveraged the access facilitated by its malware to pursue operational objectives.  This activity will serve as the basis for Scenario 2.

## Tactical Malware

Name | Associated Names | Availability | Emulation Notes|
|:---:|:---|:---|:---|
[ChChes](https://unit42.paloaltonetworks.com/unit42-menupass-returns-new-malware-new-attacks-japanese-academics-organizations/) ([S0144](https://attack.mitre.org/software/S0144/))| [HAYMAKER](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html), [Scorpian](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)|Custom| Has been injected using PowerSploit<sup>[29](https://blogs.jpcert.or.jp/en/2017/03/malware-leveraging-powersploit.html)</sup>|
[EvilGrab](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf) ([S0152](https://attack.mitre.org/software/S0152/))| Vidgrab, Grabber| Custom|Used to "grab" audio, video, and screenshots.  Also capable of lightweight reconnaissance tasks<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>|
[Koadic](https://www.trendmicro.com/en_us/research/18/c/chessmaster-adds-updated-tools-to-its-arsenal.html) ([S0250](https://attack.mitre.org/software/S0250/))| |Publicly available | Delivered via phishing and used to download and execute ANEL<sup>[16](https://www.trendmicro.com/en_us/research/18/c/chessmaster-adds-updated-tools-to-its-arsenal.html)</sup>|
[RedLeaves](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf) ([S0153](https://attack.mitre.org/software/S0153/))| [BUGJUICE](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html), [Trochilus](https://go.recordedfuture.com/hubfs/reports/cta-2019-0206.pdf)| Custom| Operates like publicly available Trochilus<sup>[11](https://blog.trendmicro.com/trendlabs-security-intelligence/chessmaster-cyber-espionage-campaign/)</sup>| Has been deployed to DC to copy NTDS.DIT<sup>[10](https://go.recordedfuture.com/hubfs/reports/cta-2019-0206.pdf)</sup>
[SNUGRIDE](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html) ([S0159](https://attack.mitre.org/software/S0159/))| |Custom|Capable of lightweight tasks and persistence.  Communicates over HTTP requests<sup>[5](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)</sup>|
[UPPERCUT](https://go.recordedfuture.com/hubfs/reports/cta-2019-0206.pdf) ([S0275](https://attack.mitre.org/software/S0275/))|[ANEL](https://go.recordedfuture.com/hubfs/reports/cta-2019-0206.pdf) |Custom| Often deployed via phishing<sup>[9](https://fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html)</sup>|

---
## Sustained Malware
Name | Associated Names| Availability | Emulation Notes|
|:---:|:---|:---|:---|
[Poison Ivy](https://fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-poison-ivy.pdf) ([S0012](https://attack.mitre.org/software/S0012/))|Darkmoon|Custom|menuPass is reported to have deployed Poison Ivy as early as 2009 and as recently as 2014<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>|
[PlugX](https://blog.trendmicro.com/trendlabs-security-intelligence/chessmaster-cyber-espionage-campaign/) ([S0013](https://attack.mitre.org/software/S0013/))| [SOGU](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html) |Custom|Typically deployed as a self-exttracting archive<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>|
[QuasarRAT](https://blogs.blackberry.com/en/2019/06/threat-spotlight-menupass-quasarrat-backdoor) ([S0262](https://attack.mitre.org/software/S0262/))|CinaRAT, Yggdrasil|Publicly available|A publicly available RAT typically deployed with a custom .NET loader<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>|
---

menuPass actors have demonstrated a responsiveness to public reporting and an adaptability born of operational necessity.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup>  The group has also displayed an aptitude for defense evasion using techniques like DLL load order hijacking ([T1574.001](https://attack.mitre.org/techniques/T1574/001/)) and DLL side-loading ([T1574.002](https://attack.mitre.org/techniques/T1574/002/)) to achieve execution and bypass application whitelisting.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> <sup>[5](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)</sup> <sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup> <sup>[10](https://recordedfuture.com/apt10-cyberespionage-campaign/)</sup> <sup>[11](https://blog.trendmicro.com/trendlabs-security-intelligence/chessmaster-cyber-espionage-campaign/)</sup> <sup>[16](https://trendmicro.com/en_us/research/18/c/chessmaster-adds-updated-tools-to-its-arsenal.html)</sup> <sup>[18](https://blogs.jpcert.or.jp/en/2017/04/redleaves---malware-based-on-open-source-rat.html)</sup> <sup>[19](https://carbonblack.com/blog/carbon-black-threat-research-dissects-red-leaves-malware-leverages-dll-sideloading/)</sup>  When possible, menuPass actors have situated their malware in memory, used code-signing certificates ([T1553.002](https://attack.mitre.org/techniques/T1553/002/)), masqueraded files dropped to disk ([T1036.005](https://attack.mitre.org/techniques/T1036/005/)) and used encryption to evade host ([T1027.002](https://attack.mitre.org/techniques/T1027/002/)) and network-based defenses.

menuPass actors have persisted sustained malware by modifying the registry ([T1547.001](https://attack.mitre.org/techniques/T1547/001/)), scheduling tasks ([T1053.005](https://attack.mitre.org/techniques/T1053/005/)) and creating Windows services ([T1543.003](https://attack.mitre.org/techniques/T1543/003/)).<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> <sup>[5](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)</sup> <sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup> <sup>[8](https://www.accenture.com/t20180423T055005Z_s_/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf)</sup> The group is reported to have used legitimate but compromised credentials from MSP environments to impersonate elevated users in customer networks ([T1078.003](https://attack.mitre.org/techniques/T1078/003/)) and harvest additional credentials ([T1003.001](https://attack.mitre.org/techniques/T1003/001/), [T1003.002](https://attack.mitre.org/techniques/T1003/002/), [T1003.003](https://attack.mitre.org/techniques/T1003/003/)) using open-source tools like Mimikatz and Secretsdump.  This credential access enables persistent presence within the environment as menuPass actors are reported to have used the compromised credentials ([T1078.002](https://attack.mitre.org/techniques/T1078/002/), [T1078.003](https://attack.mitre.org/techniques/T1078/003/)) coupled with legitimate remote access tools like TeamViewer, to access target environments at will.<sup>[12](https://us-cert.cisa.gov/ncas/alerts/TA17-117A)</sup>  Additionally, menuPass has deployed versions of the China Chopper web shell to internet accessible webservers to facilitate persistent access ([T1505.003](https://attack.mitre.org/techniques/T1505/003/)).

Once in the target environment, menuPass actors perform discovery to identify opportunities, while attempting to blend in, so as to minimize operational risk.  The group has used tools indicative of routine administrative functions to move laterally.  Systems of interest were accessed over RDP ([T1021.001](https://attack.mitre.org/techniques/T1021/001/)), by mounting network shares ([T1570](https://attack.mitre.org/techniques/T1570/), [T1021.002](https://attack.mitre.org/techniques/T1021/002/)), or by using PsExec ([S0029](https://attack.mitre.org/software/S0029/))([T1021.002](https://attack.mitre.org/techniques/T1021/002/), [T1569.002](https://attack.mitre.org/techniques/T1569/002/)).  menuPass is reputed to have exfiltrated large volumes of data from its victims.  After achieving enabling objectives, the group moved laterally to systems of interest in search of sensitive information.  This data was staged ([T1074.001](https://attack.mitre.org/techniques/T1074/001/)) in multi-part archives ([T1560.001](https://attack.mitre.org/techniques/T1560/001/)) in the Recycle Bin for exfiltration.  These archives were exfiltrated from the target environment using tools like Putty Secure Copy Client (PSCP) and Robocopy.

---

## menuPass Software

Name | menuPass Name | Emulation Notes|
|:---:|:---|:---|
BITSAdmin ([S0190](https://attack.mitre.org/software/S0190/))| |Transfer tools from C2 to C:\ProgramData\temp or C:\ProgramData\media<sup>[10](https://go.recordedfuture.com/hubfs/reports/cta-2019-0206.pdf)</sup>|
certutil ([S0160](https://attack.mitre.org/software/S0160/))| |Used to download and decode b64 encoded files<sup>[9](https://fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html)</sup>|
China Chopper ([S0020](https://attack.mitre.org/software/S0020/)) |iisstart.aspx|A China Chopper variant may have been deployed to a web server to maintain persistence<sup>[10](https://recordedfuture.com/apt10-cyberespionage-campaign/)</sup>|
Csvde| |Used to export data from active directory<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>|
cURL| c.exe, CU.exe|Used to exfiltrate data from a network<sup>[10](https://recordedfuture.com/apt10-cyberespionage-campaign/)</sup>|
esentutl ([S0404](https://attack.mitre.org/software/S0404/))| |Used to copy and delete files<sup>[9](https://fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html)</sup>|
Impacket ([S0357](https://attack.mitre.org/software/S0357/))| |Atexec, psexec, and secretsdump are compiled using PyInstaller and employed during enabling objectives<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>
Koadic ([S0250](https://attack.mitre.org/software/S0250/))| |Delivered via spearphishing, has been used to download and execute ANEL<sup>[16](https://www.trendmicro.com/en_us/research/18/c/chessmaster-adds-updated-tools-to-its-arsenal.html)</sup>|
Mimikatz ([S0002](https://attack.mitre.org/software/S0002/))| Pd.exe, MSVCR100.dll|Repacked and/or compiled to DLL version executed via load order hijacking or sideloading<sup>[10](https://recordedfuture.com/apt10-cyberespionage-campaign/)</sup>
Nbtscan | Nbt.exe | |Used to enumerate NetBIOS sessions<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>|
NetSess | |Observed enumerating NetBIOS sessions during reconnaissance<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>|
PowerSploit ([S0194](https://attack.mitre.org/software/S0194/))| |Discovery, lateral movement, and injected ChChes into PowerShell process<sup>[29](https://blogs.jpcert.or.jp/en/2017/03/malware-leveraging-powersploit.html)</sup>
PsExec ([S0029](https://attack.mitre.org/software/S0029/))| Psexe.exe |Used to execute tools on a remote host<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>|
pwdump ([S0006](https://attack.mitre.org/software/S0006/))| Consl64.exe|DLL containing repacked PwDump6<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>
Putty (PSCP)|Rundll32.exe |Used to exfiltrate data from a network<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>|
Tcping| Rund1132.exe|One of two files included in detect.vbs used to probe ports 445 and 3389<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>|
Wmiexec| t.vbs|Dropped to C:\Recovery, C:\Intel, or C:\PerLogs<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>|
WinRAR| Svchost.exe, r.exe|Compressed files for exfil, named using repeating charaters e.g. ss.rar, pp.rar, dds.rar, gggg.rar<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>|

---

## menuPass ATT&CK Navigator

#### The following behaviors are in scope for an emulation of actions attributed to menuPass in the [referenced reporting](#references).

[![/menuPass/Attack_Layers/menuPass_G0045.png](/menuPass/Attack_Layers/menuPass_G0045.png)](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2FG0045%2FG0045-enterprise-layer.json)


## [ChChes (S0144)](https://attack.mitre.org/software/S0144/)

#### The following behaviors are in scope for an emulation of actions performed by menuPass using ChChes, exclusively based on current intelligence within ATT&CK for the given software.

[![/menuPass/Attack_Layers/ChChes_S0144.png](/menuPass/Attack_Layers/ChChes_S0144.png)](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0144%2FS0144-enterprise-layer.json)

## [Cobalt Strike (S0154)](https://attack.mitre.org/software/S0154/)

#### The following behaviors are in scope for an emulation of actions performed by menuPass using Cobalt Strike, exclusively based on current intelligence within ATT&CK for the given software.

[![/menuPass/Attack_Layers/Cobalt_Strike_S0154.png](/menuPass/Attack_Layers/Cobalt_Strike_S0154.png)](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0154%2FS0154-enterprise-layer.json)

## [EvilGrab (S0152)](https://attack.mitre.org/software/S0152/)

#### The following behaviors are in scope for an emulation of actions performed by menuPass using EvilGrab, exclusively based on current intelligence within ATT&CK for the given software.

[![/menuPass/Attack_Layers/EvilGrab_S0152.png](/menuPass/Attack_Layers/EvilGrab_S0152.png)](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0152%2FS0152-enterprise-layer.json)

## [Koadic (S0250)](https://attack.mitre.org/software/S0250/)

#### The following behaviors are in scope for an emulation of actions performed by menuPass using Koadic, exclusively based on current intelligence within ATT&CK for the given software.

[![/menuPass/Attack_Layers/Koadic_S0250.png](/menuPass/Attack_Layers/Koadic_S0250.png)](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0250%2FS0250-enterprise-layer.json)

## [PlugX (S0013)](https://attack.mitre.org/software/S0013/)

#### The following behaviors are in scope for an emulation of actions performed by menuPass using PlugX, exclusively based on current intelligence within ATT&CK for the given software.

[![/menuPass/Attack_Layers/PlugX_S0013.png](/menuPass/Attack_Layers/PlugX_S0013.png)](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0013%2FS0013-enterprise-layer.json)

## [PoisonIvy (S0012)](https://attack.mitre.org/software/S0012/)

#### The following behaviors are in scope for an emulation of actions performed by menuPass using PoisonIvy, exclusively based on current intelligence within ATT&CK for the given software.

[![/menuPass/Attack_Layers/PoisonIvy_S0012.png](/menuPass/Attack_Layers/PoisonIvy_S0012.png)](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0012%2FS0012-enterprise-layer.json)

## [QuasarRAT (S0262)](https://attack.mitre.org/software/S0262/)

#### The following behaviors are in scope for an emulation of actions performed by menuPass using QuasarRAT, exclusively based on current intelligence within ATT&CK for the given software.

[![/menuPass/Attack_Layers/QuasarRAT_S0262.png](/menuPass/Attack_Layers/QuasarRAT_S0262.png)](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0262%2FS0262-enterprise-layer.json)

## [RedLeaves (S0153)](https://attack.mitre.org/software/S0153/)

#### The following behaviors are in scope for an emulation of actions performed by menuPass using RedLeaves, exclusively based on current intelligence within ATT&CK for the given software.

[![/menuPass/Attack_Layers/RedLeaves_S0153.png](/menuPass/Attack_Layers/RedLeaves_S0153.png)](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0153%2FS0153-enterprise-layer.json)

---

## References

ID | Source | Publisher | Date |
|:---:|:---|:---|:---|
1 |[menuPass Returns with New Malware and New Attacks Against Japanese Academics and Organizations](https://unit42.paloaltonetworks.com/unit42-menupass-returns-new-malware-new-attacks-japanese-academics-organizations/)|[Palo Alto Networks](https://paloaltonetworks.com)| March 2017 |
2 |[CrowdCasts Monthly: You Have an Adversary Problem](https://slideshare.net/CrowdStrike/crowd-casts-monthly-you-have-an-adversary-problem)|[CrowdStrike](https://crowdstrike.com)| March 2017|
3 |[Poison Ivy: Assessing Damage and Extracting Intelligence](https://fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-poison-ivy.pdf)|[FireEye](https://fireeye.com)|November 2014|
4 |[Operation Cloud Hopper](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)|[PricewaterhouseCoopers](https://www.pwc.com)| April 2017|
5 |[APT10(MenuPass Group): New Tools, Global Campaign Latest Manifestation of a Longstanding Threat](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)|[FireEye](https://fireeye.com)| June 2017|
6 |[United States of America v. Zhu Hua and Zhang Shilong](https://www.justice.gov/opa/press-release/file/1121706/download)|[Department of Justice](https://www.justice.gov)| April 2019
7 |[Operation Cloud Hopper: Technical Annex](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)|[PricewaterhouseCoopers](https://www.pwc.com)| April 2017
8 |[HOGFISH RedLeaves Campaign](https://www.accenture.com/t20180423T055005Z_s_/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf)|[Accenture](https://www.accenture.com)| July 2018
9 |[APT10 Targeting Japanese Corporations Using Updated TTPs](https://fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html)|[FireEye](https://fireeye.com)| September 2018
10 |[APT10 Targeted Norwegian MSP and US Companies in Sustained Campaign - Report and Annex](https://go.recordedfuture.com/hubfs/reports/cta-2019-0206.pdf)| [Recorded Future](https://recordedfuture.com)| February 2019
11 |[Chessmaster Cyber Espionage Campaign](https://blog.trendmicro.com/trendlabs-security-intelligence/chessmaster-cyber-espionage-campaign/)|[Trend Micro](https://www.trendmicro.com/en_us/business.html)| July 2017
12 |[Intrusions Affecting Multiple Victims Accross Multiple Sectors](https://us-cert.cisa.gov/ncas/alerts/TA17-117A)|[CISA](https://us-cert.cisa.gov)| April 2017
13 |[MenuPass/QuasarRAT Backdoor](https://blogs.blackberry.com/en/2019/06/threat-spotlight-menupass-quasarrat-backdoor)|[Blackberry](https://www.blackberry.com)| April 2017
14 |[Two Birds, One STONE PANDA](https://crowdstrike.com/blog/two-birds-one-stone-panda/)|[CrowdStrike](https://crowdstrike.com)| April 2018
15 |[ChessMaster's New Strategy: Evolving Tools and Tactics](http://blog.trendmicro.com/trendlabs-security-intelligence/chessmasters-new-strategy-evolving-tools-tactics/)|[Trend Micro](https://trendmicro.com/en_us/business.html)| November 2017
16 |[ChessMaster Adds Updated Tools to Its Arsenal](https://trendmicro.com/en_us/research/18/c/chessmaster-adds-updated-tools-to-its-arsenal.html)|[Trend Micro](https://trendmicro.com/en_us/business.html)| March 2018
17 |[APT10 was managed by the Tianjin bureau of the Chinese Ministry of State Security](https://intrusiontruth.wordpress.com/2018/08/15/apt10-was-managed-by-the-tianjin-bureau-of-the-chinese-ministry-of-state-security/)| [Intrusion Truth](https://intrusiontruth.wordpress.com)| March 2018
18 |[RedLeaves-Malware Based on Open Source RAT](https://blogs.jpcert.or.jp/en/2017/04/redleaves---malware-based-on-open-source-rat.html)|[JPCERT](https://jpcert.or.jp/english/)| April 2017
19 |[Carbon Black Threat Research Dissects Red Leaves Malware, Which Leverages DLL Side Loading](https://www.carbonblack.com/blog/carbon-black-threat-research-dissects-red-leaves-malware-leverages-dll-side-loading/)|[Carbon Black](https://www.carbonblack.com)| May 2017
20 |[Relationship between attacker group menuPass malware "Poison Ivy, PlugX, ChChes"](https://lac.co.jp/lacwatch/people/20170223_001224.html)|[LAC](https://lac.co.jp/english)| February 2017
21 |[New attack by APT attack group menuPass (APT10) confirmed](https://lac.co.jp/lacwatch/people/20180521_001638.html)|[LAC](https://lac.co.jp/english)| May 2018
22 |[Code Blue 2017: Pursue the Attackers](https://jpcert.or.jp/present/2018/20171109codeblue2017_en.pdf)|[JPCERT](https://jpcert.or.jp/english/)|November 2017
23 |[Swiss Cyber Storm:Cross-Border Hunting of Sophisticated Threat Actors in Enterprise Networks - Challenges and Success Factors](https://2016.swisscyberstorm.com/res/presentations/SCS7-Mark-Barwinski.pdf)|[Swiss Cyber Storm](https://swisscyberstorm.com)| October 2016
24 |[How Attackers are Using LNK Files to Download Malware](https://trendmicro/en_us/research/17/e/rising-trend-attackers-using-lnk-files-download-malware.html)| [Trend Micro](https://trendmicro.com/en_us/business.html)| May 2017
25 | [Uncovering New Activity By APT10](https://fortinet.com/blog/threat-research/uncovering-new-activity-by-apt-)| [Fortinet](https://fortinet.com)| October 2019
26 | [Operation Soft Cell: A Worldwide Campaign Against Telecommunications Providers](https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers) | [cybereason](https://www.cybereason.com)| June 2019
27 | [TA410:The Group Behind Lookback Attacks Against U.S. Utilities Sector Returns With New Malware](https://www.proofpoint.com/us/blog/threat-insight/ta410-group-behind-lookback-attacks-against-us-utilities-sector-returns-new)| [proofpoint](https://proofpoint.com)| June 2020
28 | [Attack Activities by Quasar Family](https://blogs.jpcert.or.jp/en/2020/12/quasar-family.html)| [JPCERT](https://jpcert.or.jp/english/) | December 2020
29 | [Malware Leveraging PowerSploit](https://blogs.jpcert.or.jp/en/2017/03/malware-leveraging-powersploit.html)| [JPCERT](https://jpcert.or.jp/english/)|March 2017
30 | [ChChes - Malware that Communicates with C&C Servers Using Cookie Headers](https://blogs.jpcert.or.jp/en/2017/02/chches-malware--93d6.html)|[JPCERT](https://jpcert.or.jp/english/)|February 2017
31 | [How Attackers are Using LNK Files to Download Malware](https://trendmicro.com/en_us/research/17/e/rising-trend-attackers-using-lnk-files-download-malware.html)|[Trend Micro](https://trendmicro.com/en_us/business.html)| May 2017
32 | [Japan-Linked Organizations Targeted in Long-Running and Sophisticated Attack Campaign](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/cicada-apt10-japan-espionage)|[Symantec](https://broadcom.com/)| November 2020

---

## Additional Plan Resources

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