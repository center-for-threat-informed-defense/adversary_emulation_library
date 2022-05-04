# Emotet

The Emotet client is broken up into the following components:
| Component | Description |
| --- | --- |
| EmotetClientDLL | The main implant in DLL format |
| OutlookScraper | Outlook scraper module |
| LatMovementDLL | Lateral movement module |

## Build Instructions

### Build Implant
Open the developer command prompt, navigate to directory containing the Emotet Client DLL Visual Studio solution file (EmotetClientDLL.sln), and run the devenv.exe command:

    cd %userprofile%\wizard_spider\Resources\Emotet\EmotetClientDLL
	devenv.exe EmotetClientDLL.sln /build Release

Wait about 3 minutes for the build to finish.

The executable will be found in the Release folder:

```
wizard_spider\Resources\Emotet\EmotetClientDLL\EmotetClientDLL\x64
```

Note: if building Emotet for the first time, first build EmotetClientDLL.sln in Visual Studio so it can fetch dependencies (googletest).

### Build OutlookScraper
Open the command prompt (cmd.exe), navigate to directory containing the Outlook Scaper Visual Studio solution file (OutlookScraper.sln), and run the devenv.exe command:

    cd wizard_spider\Resources
	"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\Common7\IDE\devenv.exe" OutlookScraper.sln /build Release

The executable will be found in the Release folder.

## Test Instructions
Open the command prompt (cmd.exe), navigate to directory containing the Emotet Client DLL Visual Studio solution file (EmotetClientDLL.sln), and run the devenv.exe command:

    cd wizard_spider\Resources
	"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\Common7\IDE\devenv.exe" EmotetClientDLL.sln

Previous command will open project in Visual Studio, run all tests by opening the Test Explorer and clicking in on "Run All Test In View".

    Test > Test Explorer > "Run All Test In View" button

## Usage Examples

### Run DLL client via rundll32.exe
Open the command prompt (cmd.exe)
    
    rundll32.exe C:\%USERPROFILE%\{path to DLL}\EmotetClientDLL.dll,Control_RunDLL

## Cleanup Instructions 
Open a command prompt or PowerShell and navigate to the directory from where the DLL was ran.

	del EmotetClientDLL.dll (or renamed)
    del Outlook.dll (if installed)
    del LatMovementDLL.dll (if installed)
    del PAExec.exe (if installed)

## Misc
Conditions required:
- Requires range configuration to remove Outlook prompt when DLL is accessing Outlook via PowerShell.
```
(PowerShell)  New-Item –Path "HKLM:\SOFTWARE\Microsoft\Office\16.0\Outlook" –Name Security
(PowerShell)  New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\16.0\Outlook\Security" -Name "ObjectModelGuard" -Value 2 -PropertyType "DWord"
```

### CTI Evidence
https://attack.mitre.org/software/S0367
https://www.cisecurity.org/white-papers/ms-isac-security-primer-emotet/
https://blogs.vmware.com/security/2019/04/cb-tau-threat-intelligence-notification-emotet-utilizing-wmi-to-launch-powershell-encoded-code.html
https://securityintelligence.com/new-banking-trojan-icedid-discovered-by-ibm-x-force-research/
https://unit42.paloaltonetworks.com/attack-chain-overview-emotet-in-december-2020-and-january-2021/
https://www.fortinet.com/blog/threat-research/deep-dive-into-emotet-malware 
https://support.malwarebytes.com/hc/en-us/articles/360038524714s

### References
https://docs.microsoft.com/en-us/visualstudio/ide/reference/build-devenv-exe?view=vs-2019  
