
  

# Scenario 1 Infrastructure
We hope to capture the general structure of what is reported to have been seen being used by the [Sandworm Team](https://attack.mitre.org/groups/G0034/). Scenarios 1 and 2 share the same infrastructure; however, Scenario 1 was built to exercise detective-only security controls, and thus protective security controls are to be disabled to complete the evaluation. Scenario 2 was built to exercise protective security controls, which may be enabled while completing the evaluation.

The requirements described herein should be considered a bare minimum to execute the scenario. If you have the time and resources to remain true-to-form, you may elect to stand up multiple of each of these servers, non-contiguous IP space, etc. If you are not concerned with emulating the [Sandworm Team](https://attack.mitre.org/groups/G0034/) to this degree, this level of effort is not necessary. You could for instance, phish, serve payload, and exfil from/to the same server.

## Resources
Please note that binary executable files hosted in [Resources](/Resources/) have been added to password protected zip files. The password for these files is "malware."

We provide a [script](/Resources/utilities/crypt_executables.py) to automatically decrypt these files:

```
cd sandworm/
python3 Resources/utilities/crypt_executables.py -i ./ -p malware --decrypt
```
*Note, there is no change of infrastructure between Scenario 1 and Scenario 2.*

## Emulation Team Infrastructure

1.  **Linux Attack Platform**: tested and executed on Kali Linux 2019.1

-  [LaZagne](https://github.com/AlessandroZ/LaZagne)
-  [pyinstaller](https://github.com/pyinstaller/pyinstaller)
-  [Mimikatz](https://github.com/gentilkiwi/mimikatz/wiki)
-  [FreeRDP](https://github.com/FreeRDP/FreeRDP)

## Emulation Team Infrastructure Configuration

This methodology assumes the following static IP address configurations:

| Red Team System | IP Address |
| ------ | ------ |
| Linux Attack Platform | 192.168.0.4 |

#### A note about red team payloads

- This evaluation utilizes a combination of modified open-source and custom utilities that are representative of NotPetya ransomeware.
- These utilities include credential dumpers, variants of process injection techniques, and file encryption.
- Some pre-compiled payloads are available in the [resources](/Resources) directory; however, they are configured to connect back to static IP address 192.168.0.4.

### Linux Attack Platform Setup

1. Download the sandworm repository to the home directory

## Target Infrastructure

4 targets, all domain joined:
1. *Linux Server* : tested and executed on CentOS 7.9

2.  *Domain Controller* : tested and executed on Windows Server 2k19 - Build 17763

3.  *User machine 1* : tested and executed on Windows 10 - Build 19042

4.  *User machine 2* : tested and executed on Windows 10 - Build 19042

## Target Infrastructure Configuration

| Target System | Hostname | IP Address |
| ------ | ------ | ------|
|Linux Server | caladan | 10.0.1.5
| Domain Controller | arrakis | 10.0.1.4 |
| User machine 1 | gammu | 10.0.1.7 |
| User machine 2 | quadra | 10.0.1.8 |

### Linux Server Setup
1. Upload `caladan.sh` to `10.0.1.5` via SCP
```
scp sandworm/Resources/setup/setup_caladan.sh fherbert@10.0.1.5:/tmp/setup_caladan.sh
```
password: `Whg42WbhhCE17FEzrqeJ`

⚠️  Run this command if you get SSH key errors
```
rm -rf ~./ssh/known_hosts
```

2. upload SUID binary to caladan
```
scp sandworm/Resources/suid-binary/suid-binary fherbert@10.0.1.5:/tmp/suid-binary
```

3. Run `caladan.sh` 
### Domain Controller Setup

1.  RDP into arrakis:
```
xfreerdp +clipboard /u:dune\\patreides /p:"ebqMB7DmM81QVUqpf7XI" /v:10.0.1.4 /drive:X,sandworm/Resources/setup/
```
2.  Open Windows Defender, toggle all nobs to the off position.
    
3.  Open PowerShell being sure to select "Run as Administrator":
```
cd \\TSCLIENT\X
Set-Executionpolicy bypass -force
.\enable-winrm.ps1
.\disable-defender.ps1
```

4.  Reboot
```		
Restart-Computer -Force
```

### Gammu / 10.0.1.7 Setup
1. RDP into Gammu:
```
xfreerdp +clipboard /u:WORKGROUP\\fherbert /p:"Whg42WbhhCE17FEzrqeJ" /v:10.0.1.7 /drive:X,sandworm/Resources/setup/
```
2. Open Windows Defender, toggle all knobs to the off position.
3. Open PowerShell being sure to select `Run as Administrator`.
```
cd \\TSCLIENT\X
Set-Executionpolicy bypass -force
.\install_software.ps1
.\enable_winrm.ps1
.\disable-defender.ps1
.\generate-files.exe -d :C:\Users\" -c 50 --seed- "EVALS" --noprompt
```

4. Open chromium and navigate to: 
`https://www.stealmylogin.com/demo.html`

5. Enter the following credentials; save / cache the credentials when prompted.
```
fherbert@mail.com
Passw0rd123!!!
```

6. Double-check the credentials were cached by going to Chromium settings > passwords. You should have one entry for stealmylogin.com

7. Reboot Gammu:
```
Restart-Computer -Force
```

### Configure Quadra / 10.0.1.8
1.  RDP into quadra:
```
xfreerdp +clipboard /u:dune\\patreides /p:"ebqMB7DmM81QVUqpf7XI" /v:10.0.1.8 /drive:X,sandworm/Resources/setup/
```
2.  Open Windows Defender, toggle all knobs to the off position.
    
3.  Open PowerShell being sure to select `Run as Administrator`:
```
cd \\TSCLIENT\X
Set-Executionpolicy bypass -force
.\install_software.ps1
.\enable-winrm.ps1
.\disable-defender.ps1
.\generate-files.exe -d "C:\Users\" -c 50 --seed "EVALS" --noprompt
```

4.  Reboot
```
Restart-Computer -Force
```
## Additional Plan Resources

  

-  [Intelligence Summary](/Intelligence_Summary/Intelligence_Summary.md)
-  [Operations Flow](/Operations_Flow/Operations_Flow.md)
-  [Emulation Plan](/Emulation_Plan)
-  [Scenario 1 - Infrastructure](/Emulation_Plan/Scenario_1/Infrastructure.md)
-  [Scenario 1 - Detections](/Emulation_Plan/Scenario_1)
-  [Scenario 2 - Infrastructure](/Emulation_Plan/Scenario_2/Infrastructure.md)
-  [Scenario 2 - Protections](/Emulation_Plan/Scenario_2)
-  [Issues](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/issues)
-  [Change Log](/CHANGE_LOG.md)

  

## Network Diagram

A network diagram is [available here](/Resources/images/InfrastructureDiagram.png) that displays the domains and infrastructure that was used to support the setup and execution of the [Emulation plan](/Emulation_plan/Scenario_1).

![Infrastructure Image](/Resources/images/InfrastructureDiagram.png)
