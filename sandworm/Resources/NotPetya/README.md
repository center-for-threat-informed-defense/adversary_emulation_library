# NotPetya

This is a C# implementation of NotPetya's capabilities. For many of the TTPs, the same Windows API calls were made via p/invoke to match the CTI as closely as possible.

Note: In order to mitigate abuse, the encryption for impact functionality has been deliberately removed. Users wishing to emulate this behavior may reference threat intelligence sources to implement their own trusted encryption solution.

### Build Instructions

Open the command prompt (cmd.exe), navigate to directory containing the SharpNP Visual Studio solution file (SharpNP.sln), and run the devenv.exe command:

	cd sandworm\Resources\SharpNP
	"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\Common7\IDE\devenv.exe" SharpNP.sln /build Release


The DLL will be found in the bin\Release\x64 folder (there will also be DLLs available in other folders).

Note: The final product is expected to be a DLL. If you see an executable (.exe), the project settings need to be adjusted by:

1. Open the project in Visual Studio
2. Open SharpNP properties (Click on Project menu and Select "SharpNP Properties")
3. On the Application tab, select "Class Library" in the "Output Type" section
4. Rebuild the solution

### Test Instructions
Open PowerShell

	np_test.ps1

### Usage Examples

	# execute via rundll; #1 == the first entrypoint in the DLL
	# Note: SharpNP.dll is renamed to perfc.dat
	C:\Windows\System32\rundll32.exe perfc.dat,"#1"

### Cleanup Instructions 
Open a command prompt or PowerShell

	del perfc.dat
	del C:\README.txt
	Unregister-ScheduledTask -TaskName Restart

### Misc

Deviations from CTI:

- The MBR and MFT are currently not encrypted
- EternalBlue and EternalRomance exploits not used
- PsExec is not used to propagate; only WMI is used
- A scheduled task to reboot the host is not created
- Some functions use the C# libraries to execute TTPs, so their underlying API calls and the artifacts left behind may differ including:
  - Encryption functions
  - Process execution


### CTI Evidence
https://attack.mitre.org/software/S0368/
https://www.cynet.com/blog/technical-analysis-notpetya/
https://www.securityartwork.es/2017/07/07/the-mimi-mimikatz-side-of-notpetya/
https://www.crowdstrike.com/blog/petrwrap-ransomware-technical-analysis-triple-threat-file-encryption-mft-encryption-credential-theft/

### References
https://blog.xpnsec.com/rundll32-your-dotnet/
https://docs.microsoft.com/en-us/visualstudio/ide/reference/build-devenv-exe?view=vs-2019  
