# Emotet's Lateral Movement

Lateral movement module that enables users to execute commands, main use will be to give access to net.exe and paexec.exe. PAExec.exe is used to emulate Emotet's lateral movement via access of [Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/).

# Build Implant
Open the command prompt (cmd.exe), navigate to directory containing the Lateral Movement Visual Studio solution file (LatMovementDLL.sln), and run the devenv.exe command:

    cd wizard_spider\Resources\Emotet\LatMovementDLL\
	"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\Common7\IDE\devenv.exe" LatMovementDLL.sln /build Release

The dll will be found in the Release folder.

### Test Instructions
Open the command prompt (cmd.exe), navigate to directory containing the Lateral Movement Visual Studio solution file (LatMovementDLL.sln), and run the devenv.exe command:

    cd wizard_spider\Resources\Emotet\LatMovementDLL\
	"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\Common7\IDE\devenv.exe" LatMovementDLL.sln

Previous command will open project in Visual Studio, run all tests by opening the Test Explorer and clicking in on "Run All Test In View".

    Test > Test Explorer > "Run All Test In View" button

## Usage Examples
Exports command line function that receives string as parameter that will be executed.
```
ExecuteLatMovementCmd
```

## Cleanup Instructions
```
del LatMovementDLL.dll
```

### CTI Evidence
https://attack.mitre.org/software/S0367
https://support.malwarebytes.com/hc/en-us/articles/360038524714
