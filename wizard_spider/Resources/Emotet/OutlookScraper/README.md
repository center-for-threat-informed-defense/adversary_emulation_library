# Emotet's Outlook Scraper

Microsoft Outlook Scraper that retrieves information from the victim's inbox.

# Build Implant
Open the command prompt (cmd.exe), navigate to directory containing the Outlook Scaper Visual Studio solution file (OutlookScraper.sln), and run the devenv.exe command:

    cd wizard_spider\Resources
	"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\Common7\IDE\devenv.exe" OutlookScraper.sln /build Release

The dll will be found in the Release folder.

### Test Instructions
Open the command prompt (cmd.exe), navigate to directory containing the Emotet Client DLL Visual Studio solution file (OutlookScraper.sln), and run the devenv.exe command:

    cd wizard_spider\Resources
	"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\Common7\IDE\devenv.exe" OutlookScraper.sln

Previous command will open project in Visual Studio, run all tests by opening the Test Explorer and clicking in on "Run All Test In View".

    Test > Test Explorer > "Run All Test In View" button

## Usage Examples
Exports two functions. One function retrieves emails from the victim's inbox that may contain passwords. The other function retrieves a list of email addresses found in the inbox.
```
getCredentials
getEmailAddresses
```
Both functions have the functionality to stop and restart the Outlook application. This will force the application to load with the same privilege as the calling implant. 

## Cleanup Instructions
```
del OutlookScraper.dll
```

### Misc
Requires range configuration to remove Outlook prompt when DLL is accessing Outlook via PowerShell.
```
(PowerShell)  New-Item –Path "HKLM:\SOFTWARE\Microsoft\Office\16.0\Outlook" –Name Security
(PowerShell)  New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\16.0\Outlook\Security" -Name "ObjectModelGuard" -Value 2 -PropertyType "DWord"
```
	
For the changes to take effect, you must restart the Outlook Client

### CTI Evidence
https://attack.mitre.org/software/S0367
https://www.cisecurity.org/white-papers/ms-isac-security-primer-emotet/
https://securityintelligence.com/new-banking-trojan-icedid-discovered-by-ibm-x-force-research/