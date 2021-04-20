# Scenario 1 Infrastructure

We hope to capture the general structure of what is reported to have been seen being used by FIN7. Scenarios 1 and 2 share the same infrastructure; however, Scenario 1 was built to exercise detective-only security controls, and thus protective security controls are to be disabled to complete the evaluation. Scenario 2 was built to exercise protective security controls, which may be enabled while completing the evaluation.

The requirements described herein should be considered a bare minimum to execute the scenario.  If you have the time and resources to remain true-to-form, you may elect to stand up multiple of each of these servers, non-contiguous IP space, etc.  If you are not concerned with emulating FIN7 to this degree, this level of effort is not necessary.  You could for instance, phish, serve payload, and exfil from/to the same server.

## Resources

Please note that binary executable files hosted in [Resources](/fin7/Resources/) have been added to password protected zip files.  The password for these files is "malware."

We provide a [script](/fin7/Resources/utilities/crypt_executables.py) to automatically decrypt these files:

```
$ cd fin7

$ python3 Resources/utilities/crypt_executables.py -i ./ -p malware --decrypt
```

*Note, there is no change of infrastructure between Scenario 1 and Scenario 2.*

## Emulation Team Infrastructure

1. **Attacker Desktop**: tested and executed on Ubuntu 20.04 LTS
    - Remote Desktop Client
        - [xfreerdp](https://www.freerdp.com/)

2. **Linux Attack Platform**: tested and executed on Kali Linux 2019.1
    - C2 Framework
        - [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
    - [PAExec](https://github.com/poweradminllc/PAExec)
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz/wiki)
    - [tmux](https://github.com/tmux/tmux/wiki)

3. **Windows Attack Platform**: Windows 10 SQL Server 2019 Build 17763
    - [ATT&CK RAT](/fin7/Resources/Scenario_1/Step11/FIN7_SQLRat_C2_Server)

4. **Optional - Windows 10**: Windows 10 Client build 18363
	* Note, this Windows 10 machine was used ONLY in the event debugging needed to occur during an evaluation.

---

## Emulation Team Infrastructure Configuration

This methodology assumes the following static IP address configurations:

| Red Team System | IP Address |
| ------ | ------ |
| Linux Attack Platform | 192.168.0.4 |
| Windows Attack Platform | 192.168.0.6 |

#### A note about red team payloads

- This evaluation utilizes a combination of modified open-source and custom utilities that are representative of FIN7 malware.

- These utilities include credential dumpers, and variants of process injection techniques.

- Some pre-compiled payloads are available in the [resources](/fin7/Resources) directory; however, they are configured to connect back to static IP address 192.168.0.4.

- Binaries that are not pre-compiled have compilation instructions included, e.g. for [`AccountingIQ.exe`](/fin7/Resources/Step10/README.md) 

- If you would like to build the payloads yourself, please make the necessary adjustments to the payload source to match your environment.

### Linux Attack Platform Setup

1. Download the FIN7 Adversary Emulation Library to the home directory

### Windows Attack Platform Setup

1. Disable firewall in CMD
    ```
    netsh advfirewall set allprofiles state off
    ```

2. Setup the MSSQL Database using [`dbsetup.bat`](/fin7/Resources/setup/dbsetup.bat)

---

## Target Infrastructure

4 targets, all domain joined:

1. *Domain Controller*: tested and executed on Windows Server 2k19 - Build 17763.

2. *Accounting Manager Workstation*: tested and executed on Windows 10 - Build 18363.

3. *Hotel Manager*: tested and executed on Windows 10 - Build 18363.

4. *IT Admin*: tested and executed on Windows 10 - Build 18363.

--- 

## Target Infrastructure Configuration

| Target System | Hostname |
| ------ | ------ |
| Domain Controller | hoteldc |
| Hotel Manager Workstation | hotelmanager |
| IT Admin Workstation | itadmin |
| Accounting Workstation | accounting |

### Domain Controller Setup

1. If only testing detection capabilities, disable Windows Defender

    The `set-defender.ps1` PowerShell script in the [setup](/fin7/Resources/setup) folder can be used to perform this.

### Hotel Manager Workstation Setup

1. If only testing detection capabilities, disable Windows Defender

    The `set-defender.ps1` PowerShell script in the [setup](/fin7/Resources/setup) folder can be used to perform this.
   
2. Disable OLE Security to enable execution of initial access payload
    
    The `set-OLEsecurity.ps1` PowerShell script in the [setup](/fin7/Resources/setup) folder can be used to perform this.
   
3. Add a static ARP entry for `itadmin`:
    
    1. In a CMP prompt, grab the name of the interface that connects `hotelmanager` to the domain
        ```
        cmd > netsh int ipv4 show interfaces
        ```
    
    2. Use this interface name to set a static ARP entry
        ```
        cmd > netsh interface ipv4 set neighbors Interface="[Interface Name]" address=<itadmin_ip> neighbor=12-34-56-78-9a-bc
        ```

### IT Admin Workstation Setup

1. If only testing detection capabilities, disable Windows Defender

    The `set-defender.ps1` PowerShell script in the [setup](/fin7/Resources/setup) folder can be used to perform this.

2. Set ACLs to allow full control for everyone on the `C:\Windows\SysWOW64` directory
    
    The `set-acl-syswow64.ps1` PowerShell script in the [setup](/fin7/Resources/setup) folder can be used to perform this.

### Accounting Workstation Setup

1. If only testing detection capabilities, disable Windows Defender

    The `set-defender.ps1` PowerShell script in the [setup](/fin7/Resources/setup) folder can be used to perform this.

2. Compile `AccountingIQ.exe` using the instructions found [here](/fin7/Resources/Step10/README.md)

3. Place `AccountingIQ.exe` in `C:\Users\Public`

4. Add `AccountingIQ.exe` to the Registry Run key
    ```
    REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Dummy Accounting Program" /t REG_SZ /F /D "C:\Users\Public\AccountingIQ.exe"
    ```

--- 

## Additional Plan Resources

- [Intelligence Summary](/fin7/Intelligence_Summary.md)
- [Operations Flow](/fin7/Operations_Flow.md)
- [Emulation Plan](/fin7/Emulation_Plan)
  - [Scenario 1 - Infrastructure](/fin7/Emulation_Plan/Scenario_1/Infrastructure.md)
  - [Scenario 1 - Detections](/fin7/Emulation_Plan/Scenario_1)
  - [Scenario 2 - Infrastructure](/fin7/Emulation_Plan/Scenario_2/Infrastructure.md)
  - [Scenario 2 - Protections](/fin7/Emulation_Plan/Scenario_2)
- [Issues](/issues)
- [Change Log](/fin7/CHANGE_LOG.md)
