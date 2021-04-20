# ATT&CK Evaluations Telemetry Generator

The ATT&CK Evaluations Telemetry Generator (`telemetry-generator.ps1`) is a repeatable, adversary focused data creation mechanism to exercise a variety of data sources that can be used to help identify adversary behavior with an enterprise. The Telemetry Generator is not meant to dictate sensor coverage, which must also consider realism of collection, such as false positives and data volume. The Telemetry Generator should be used to validate configurations, and can be used to help vendors understand other data sources they should consider. Simply because data is generated in this script does not mean it will be applicable in a given round of ATT&CK Evaluations, or guarantee functionality during an engagement.

Data Generator functions are responsible for carrying out an atomic action within the Telemetry Generator. Read the Data Generators section to see a list and description of all supported generators.

## Requirements

* Any Windows OS
* Git for Windows
* Unrestricted PowerShell Execution Policy or CLI equivalent
* Internet Access 

## Installation

Start by cloning this repository:
```Bash
git clone !<INSERT LINK TO REPO HERE>!
```

## Quickstart
### In a USER level PowerShell console, execute the following...

If the PowerShell Execution Policy is restricted, run `telemetry-generator.ps1` with `-ExecutionPolicy Bypass`
```Bash
PowerShell.exe -ExecutionPolicy Bypass -File .\telemetry-generator.ps1
``` 

The `-ExecuteAll` switch will run all data generators:
```Bash
PowerShell.exe -ExecutionPolicy Bypass -File .\telemetry-generator.ps1 -ExecuteAll
```

For isolated generation, specify generators as switches:
```Bash
PowerShell.exe -ExecutionPolicy Bypass -File .\telemetry-generator.ps1 -WriteFile -ReadFile -DeleteFile
```

Order matters for generators when specifying multiple switches. For instance, you can not use `-ReadFile` before `-WriteFile`.


## Data Generators
`.\telemetry-generator.ps1 -Help` will print out this same information

- **WriteFile** - Switch to write file to `$($Env:SystemRoot)\Temp\WriteFile-Test.ps1` with content `Write-Host "[*] WriteFile Test"`

- **ReadFile** - Switch to read file at `$($Env:SystemRoot)\Temp\WriteFile-Test.ps1`

- **DeleteFile** - Switch to delete file at `$($Env:SystemRoot)\Temp\WriteFile-Test.ps1`

- **WriteKey** - Switch to write regkey to `HKCU:\Software\Microsoft\.Test` with content `Test`

- **ReadKey** - Switch to read regkey at `HKCU:\Software\Microsoft\.Test`

- **DeleteKey** - Switch to delete regkey at `HKCU:\Software\Microsoft\.Test`

- **NetworkConnection** - Switch to generate network traffic by making an HTTPS GET request to `https://httpbin.org:443/get`

- **CreateProcess** - Switch to create new cmd.exe process via Start-Process

- **ExecutePowerShell** - Switch to execute PowerShell script from a .ps1 file via powershell.exe -File

- **ExecuteWMI** - Switch to execute WMI query in the `root\cmiv2` namespace for `Win32_BIOS` information

- **ExecuteAPI** - Switch to execute CreateProcess from the Windows API by importing kernel32.dll through PowerShell
   - Source File: `$($Env:SystemRoot)\System32\notepad.exe`

- **ExecuteService** - Switch to restart the Audiosrv service
   - **NOTE:** This requires admin. Achieved through -Verb RunAs in new PowerShell process

- **LogonValid** - Switch to generate valid logon event via `net use q: \\127.0.0.1\IPC$` with provided valid credentials
   - Ensure `Audit Account Logon Events` and `Audit Logon Events` are enabled for event log visibility

- **LogonInvalid** - Switch to generate invalid logon event via `net use q: \\127.0.0.1\IPC$` with invalid credentials
   - Ensure `Audit Account Logon Event` and `Audit Logon Events` are enabled for event log visibility

- **ExecuteAdminIntegrity** - Switch to have calc.exe run with Admin integrity level via -Verb RunAs
   -  **NOTE:** USER context required for visibility into new integrity level.

### Adding New Generators
To add generators:
   - Create a new function in `telemetry-generator.ps1`
   - Create parameter with the same name
   - Add funciton to ExecuteAll
   - Add .PARAMETER descriptor to Get-Help definition

## Video tutorial

TBD

## Licensing

© 2020 MITRE Engenuity. Approved for Public Release.
