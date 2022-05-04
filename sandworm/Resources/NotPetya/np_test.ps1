# Test if the DLL was created
if (Test-Path SharpNP\SharpNP\bin\Release\SharpNP.dll) 
{
	# Execute NP
	& 'C:\Windows\System32\rundll32.exe' SharpNP\SharpNP\bin\Release\SharpNP.dll,"#1"
	
	# Pause for 3 seconds
	Start-Sleep -Seconds 3
	
	# Test if Ransom note was created
	if (Test-Path C:\README.txt) 
	{ 
		Write-Output "NotPetya Test Passed"
	} 
	else 
	{
		Write-Output "NotPetya Test Failed"
	}
	
	# Clean up C:\README.txt
	Remove-Item C:\README.txt -Force

}
else
{
	Write-Output "Build Failed"
}