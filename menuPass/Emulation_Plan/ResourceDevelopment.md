# Reconnaissance and Resource Development Overview

* Emulating reconnaissance and resource development such as information gathering, capability development, and weaponization.
* This step is not necessary to remain operationally representative but should be considered if you intend to attain initial access via phishing.

## Contents

  * [Step 1 - Information Gathering](#step-1---information-gathering)
  * [Step 2 - Building Capabilities](#step-2---building-capabilities)
  * [Step 3 - Weaponization](#step-3---weaponization)
  * [Step 4 - Establish and Maintain Infrastructure](#step-2---establish-and-maintain-infrastructure)

---

# Reconnaissance

## Step 1 - Information Gathering
It is difficult to determine precisely how menuPass prepares for an operation.  We can however, assume that menuPass actors, after carefully selecting a target, perform some degree of technical, social, and organizational information gathering.<sup>[4](https://pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup>  This may also be the stage where menuPass actors acquire publicly available documents from the organization they intend to target, for later weaponization.<sup>[4](https://pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup>  They use the information from these efforts to identify individuals to be targeted and develop pretexts to be used in social engineering (phishing) attacks.<sup>[4](https://pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup>  If you intend to phish, this is the time to identify targets, develop pretext, and collect documents for weaponization.

# Resource Development

## Step 2 - Develop Capabilities
menuPass is reported to have used both custom and publicly available tools.  This is the appropriate time to identify the C2 framework you will be using, select exploits (if you intend to use them), generate payloads, compile and rename tools.  menuPass is reported to have made use of several tools from the Impacket Suite.<sup>[7]((https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf))</sup>  Tools like atexec.py, secretsdump.py, and psexec.py should be compiled into executables using a python compiler.  You may also elect to use the compiled binaries [here](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.22.dev-binaries).

## Step 3 - Weaponization
menuPass is reported to have weaponized documents discovered during information gathering that were perceived to have been of interest to the intended target.  These documents would be weaponized with either an exploit or a macro that would inject tactical malware such as ChChes, EvilGrab, or Koadic.  The purpose of using a tactical implant during delivery is to mimimize the risk to, and later correlation with, the strategically emplaced sustained implants used for persistence at a later stage in the operation.  menuPass is widely reported to have weaponized these email messages in one of four ways:

1. Macro
2. .lnk file
3. Exploit
4. Masquerading

menuPass actors are widely reported to have weaponized password protected MS Word/Excel documents with embedded VBA macros.<sup>[9](https://fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html)</sup>  After authenticating, the intended recipient will be prompted to "enable content/macros."  If enabled, the macro typically dropped files to a temp folder, decoded, executed, and deleted them.  This execution resulted in DLL sideloading and the subsequent establishment of C2 on the infected host.<sup>[8](https://www.accenture.com/t20180423T055005Z_s_/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf)</sup> <sup>[9](https://fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html)</sup>

menuPass is also reported to have attached zip files that contained .lnk files.  When executed, the .lnk file would invoke the command prompt and use PowerShell to download and execute another PowerShell script.<sup>[4](https://pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> <sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup> This script was responsible for situating a tactical implant in memory.<sup>[4](https://pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> <sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup> <sup>[11](https://blog.trendmicro.com/trendlabs-security-intelligence/chessmaster-cyber-espionage-campaign/)</sup> <sup>[20](https://lac.co.jp/lacwatch/people/20170223_001224.html)</sup> <sup>[24](https://trendmicro/en_us/research/17/e/rising-trend-attackers-using-lnk-files-download-malware.html)</sup>

menuPass may have weaponized documents with exploits that targeted vulnerabilities in Microsoft products.<sup>[15](http://blog.trendmicro.com/trendlabs-security-intelligence/chessmasters-new-strategy-evolving-tools-tactics/)</sup> <sup>[16](https://trendmicro.com/en_us/research/18/c/chessmaster-adds-updated-tools-to-its-arsenal.html)</sup>  These exploits were responsible for achieving arbitrary code execution and subsequently downloading and situating a tactical implant like Koadic into memory.<sup>[15](http://blog.trendmicro.com/trendlabs-security-intelligence/chessmasters-new-strategy-evolving-tools-tactics/)</sup> <sup>[16](https://trendmicro.com/en_us/research/18/c/chessmaster-adds-updated-tools-to-its-arsenal.html)</sup>

The final method of observed weaponization is masquerading.  menuPass is reported to have attached digitally signed versions of ChChess and other tactical implants to email messages and modified the icon of the attachment to reflect that of a Microsoft Word document.<sup>[1](https://unit42.paloaltonetworks.com/unit42-menupass-returns-new-malware-new-attacks-japanese-academics-organizations/)</sup>

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
