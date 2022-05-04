
# Scenario 1 Infrastructure

We hope to capture the general structure of what is reported to have been seen being used by [Wizard Spider](https://attack.mitre.org/groups/G0102/). Scenarios 1 and 2 share the same infrastructure; however, Scenario 1 was built to exercise detective-only security controls, and thus protective security controls are to be disabled to complete the evaluation. Scenario 2 was built to exercise protective security controls, which may be enabled while completing the evaluation.

The requirements described herein should be considered a bare minimum to execute the scenario.  If you have the time and resources to remain true-to-form, you may elect to stand up multiple of each of these servers, non-contiguous IP space, etc.  If you are not concerned with emulating [Wizard Spider](https://attack.mitre.org/groups/G0102/) to this degree, this level of effort is not necessary.  You could for instance, phish, serve payload, and exfil from/to the same server.

## Resources

Please note that binary executable files hosted in [Resources](/wizard_spider/Resources/) have been added to password protected zip files.  The password for these files is "malware."
We provide a [script](/wizard_spider/Resources/Utilities/Crypt_executables.py) to automatically decrypt these files:
```
cd wizard_spider
python3 Resources/utilities/crypt_executables.py -i ./ -p malware --decrypt
```

*Note, there is no change of infrastructure between Scenario 1 and Scenario 2.*

## Emulation Team Infrastructure

1. **Linux Attack Platform**: tested and executed on Kali Linux 2019.1
    - [PAExec](https://github.com/poweradminllc/PAExec)
    - [pyyaml](https://github.com/yaml/pyyaml)
    - [Rubeus](https://github.com/GhostPack/Rubeus)
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz/wiki)
    - [FreeRDP](https://github.com/FreeRDP/FreeRDP)

---

## Emulation Team Infrastructure Configuration

This methodology assumes the following static IP address configurations:

| Red Team System | IP Address |
| ------ | ------ |
| Linux Attack Platform | 192.168.0.4 |

#### A note about red team payloads

- This evaluation utilizes a combination of modified open-source and custom utilities that are representative of Ryuk ransomeware.

- These utilities include credential dumpers, variants of process injection techniques, and file encryption.

- Some pre-compiled payloads are available in the [resources](/wizard_spider/Resources) directory; however, they are configured to connect back to static IP address 192.168.0.4.

### Linux Attack Platform Setup

1. Download the wizard_spider repository to the home directory
---

## Target Infrastructure

3 targets, all domain joined:

1. *Domain Controller*: tested and executed on Windows Server 2k19 - Build 17763.

2. *User machine 1*: tested and executed on Windows 10 - Build 19042.

3. *User machine 2*: tested and executed on Windows 10 - Build 19042.

--- 

## Target Infrastructure Configuration

| Target System | Hostname | IP Address |
| ------ | ------ | ------|
| Domain Controller | wizard | 10.0.0.4 |
| User machine 1 | dorothy | 10.0.0.7 |
| User machine 2 | Toto | 10.0.0.8 |

### Domain Controller Setup
RDP into domain controller

`xfreerdp +clipboard /u:oz\\vfleming /p:"q27VYN8xflPcYumbLMit" /v:10.0.0.4 /drive:X,wizard_spider/Resources/setup`

Open Windows Defender, toggle all nobs to the off position. Also go to App and Browser control and turn off Smart Screen.

Open PowerShell being sure to select "Run as Administrator":
```
cd \\TSCLIENT\X
Set-Executionpolicy bypass -force
.\install_adfind.ps1
.\install_firefox.ps1
.\create_domain_users.ps1
.\give_rdp_permissions.ps1
.\setup_spn.ps1
.\enable-winrm.ps1
.\disable-defender.ps1
.\file_generator\generate-files.exe -d "C:\Users\Public\" -c 100 --seed "EVALS" --noprompt
.\file_generator\generate-files.exe -d "C:\Users\" -c 50 --seed "EVALS" --noprompt
```
Next we need to download Microsoft Visual C++ Redistributable.
Open FireFox; close all spurious prompts / decline everything.

Go to this page:

https://support.microsoft.com/en-us/topic/the-latest-supported-visual-c-downloads-2647da03-1eea-4433-9aff-95f26a218cc0

Download and install the 32-bit and 64-bit versions.

Reboot the workstation
`Restart-Computer -Force`

### Dorothy / 10.0.0.7 Setup

1.  RDP into Dorothy
```
xfreerdp +clipboard /u:oz\\vfleming /p:"q27VYN8xflPcYumbLMit" /v:10.0.0.7 /drive:X,wizard_spider/Resources/setup
```
2.  Open Windows Defender, toggle all nobs to the off position.
    
3.  Configure Outlook and office?
    
4.  Open PowerShell being sure to select "Run as Administrator":
```
cd \\TSCLIENT\X
Set-Executionpolicy bypass -force
.\give_rdp_permissions.ps1
.\enable-winrm.ps1
.\disable-defender.ps1
.\file_generator\generate-files.exe -d "C:\Users\Public\" -c 100 --seed "EVALS" --noprompt
.\file_generator\generate-files.exe -d "C:\Users\" -c 50 --seed "EVALS" --noprompt
.\file_generator\generate-files.exe -d "C:\Users\" -c 50 --seed "EVALS" --noprompt
```
For local testing:
```
.\install_msoffice.ps1
```
Open Word and Outlook; surpress all spurious prompts.

Close Word and outlook.
```
.\setup_outlook.ps1
```

5.  Next we need to download Microsoft Visual C++ Redistributable.

Open Edge; close all spurious prompts / decline everything.

Go to this page:

[https://support.microsoft.com/en-us/topic/the-latest-supported-visual-c-downloads-2647da03-1eea-4433-9aff-95f26a218cc0](https://support.microsoft.com/en-us/topic/the-latest-supported-visual-c-downloads-2647da03-1eea-4433-9aff-95f26a218cc0)

Download and install the 32-bit and 64-bit versions.

6.  Reboot the workstation

```
Restart-Computer -Force
```

7.  Log back into Dorothy as user judy

```
xfreerdp +clipboard /u:oz\\judy /p:"Passw0rd!" /v:10.0.0.7
```

Open an Administrator CMD.exe

Run this command to take ownership of a privileged directory:

```
takeown /f "C:\Windows\*" /r /d y
icacls "C:\Windows\*" /grant judy:(OI)(CI)F /T
```

8.  Sign out of the RDP session.

### Configure Toto / 10.0.0.8

1.  RDP into Toto
```
xfreerdp +clipboard /u:oz\\vfleming /p:"q27VYN8xflPcYumbLMit" /v:10.0.0.8 /drive:X,wizard_spider/Resources/setup
```
2.  Open Windows Defender, toggle all nobs to the off position.
    
3.  Open PowerShell being sure to select "Run as Administrator":
```
cd \\TSCLIENT\X
Set-Executionpolicy bypass -force
.\give_rdp_permissions.ps1
.\enable-winrm.ps1
.\disable-defender.ps1
.\file_generator\generate-files.exe -d "C:\Users\Public\" -c 100 --seed "EVALS" --noprompt
.\file_generator\generate-files.exe -d "C:\Users\" -c 50 --seed "EVALS" --noprompt
.\file_generator\generate-files.exe -d "C:\Users\" -c 50 --seed "EVALS" --noprompt
```
4.  Reboot the workstation
```
Restart-Computer -Force
```
## Additional Plan Resources

- [Intelligence Summary](/wizard_spider/Intelligence_Summary.md)
- [Operations Flow](/wizard_spider/Operations_Flow.md)
- [Emulation Plan](/wizard_spider/Emulation_Plan)
  - [Scenario 1 - Infrastructure](/wizard_spider/Emulation_Plan/Scenario_1/Infrastructure.md)
  - [Scenario 1 - Detections](/wizard_spider/Emulation_Plan/Scenario_1)
  - [Scenario 2 - Infrastructure](/wizard_spider/Emulation_Plan/Scenario_2/Infrastructure.md)
  - [Scenario 2 - Protections](/wizard_spider/Emulation_Plan/Scenario_2)
- [Issues](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/issues)
- [Change Log](/wizard_spider/CHANGE_LOG.md)

## Network Diagram
A network diagram is [available here](/wizard_spider/Resources/images/InfrastructureDiagram.png) that displays the domains and infrastructure that was used to support the setup and execution of the [Emulation plan](/wizard_spider/Emulation_plan/Scenario_1).
![Infrastructure Image](/Resources/images/InfrastructureDiagram.png)