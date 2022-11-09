rule VALUEVAULT_strings
{
meta:
     author = "MITRE Engenuity"
     date = "9/15/2022"
     description = "This is a YARA rule to detect VALUEVAULT which will dump windows credentials."
     source = "ATT&CK Evaluations Managed Services Round 1"
     tool = "VALUEVAULT"
     filename = "b.exe"
     md5 = "a59b8539af98a6a6df7af4a771d05ea5"

strings: 
    $Func1 = "VaultOpenVault"
    $Func2 = "VaultEnumerateItems"
    $Func3 = "VaultGetItem"

    $strWinUUID = "42c4f44b-8a9b-a041-b380-dd4a704ddb28"
    $str1 = "\\AppData\\Roaming\\"
    $str2 = "fsociety.dat"
    
condition: 
    uint16(0) == 0x5a4d and all of ($Func*) and any of ($str*)
}

rule RDAT_strings 
{
meta:
	 author = "MITRE Engenuity"
	 date = "9/15/2022"
	 description = "Used to detect strings associated with RDAT"
	 description = "This is a YARA rule to detect RDAT which is used as a backdoor for exfiltration."
     source = "ATT&CK Evaluations Managed Services Round 1"
     tool = "RDAT"
     filename = "rdat.exe"
     md5 = "6b01fae7ed1e3fa854813667b334730b"
strings: 
	$APIa = "winhttp" nocase
	$APIb = "ShellExecute"
	$APIc = "LsaLogonUser"
	$APId = "Crypt"
	$APIe = "WSASocket"
	$APIf = "AddFileAttachment"
	$APIg = "SendAndSaveCopy"

	$stringA = "guest.bmp"
	$stringB = "bytesWritten"
	$stringH = "icmp"
	$stringI = "VerifySignature"
	$stringJ = "EmailAddress"

	//connects to EWS email server to send emails 
	$com = "Microsoft.Exchange.WebServices.dll"
	$com2 = "RDAT.dll"
	
condition:
	uint16(0) == 0x5a4d and any of ($string*) and all of ($API*) and all of ($com*) 
}

rule SIDETWIST_dropper_strings 
{
meta:
	 author = "MITRE Engenuity"
	 date = "9/15/2022"
	 description = "Used to detect strings associated with the dropper for SIDETWIST. This will only consist of the word doc and vbs script"
	 source = "ATT&CK Evaluations Managed Services Round 1"
	 filename = "Marketing_Materials.zip, GGMS Overview.doc"
     md5 = "35b7a282617c4577480175f203c3d580"
strings: 
	$a = "DNS" nocase
	$b = "Document_Close()"
	$c = "B64"
	$f = "Application.MouseAvailable"
	$g = "UserForm1.TextBox1.Text"
	$h = "writeFile"
	$s2 = "            targetSubfolder = \"System\" & \"Failure\" & \"Reporter\"" fullword ascii
condition:
	all of ($*)
}

rule SIDETWIST_strings 
{
meta:
	 author = "MITRE Engenuity"
	 date = "9/15/2022"
	 description = "Used to detect strings associated with SIDETWIST gathering information (backdoor) "
	 filename = "SystemFailureReporter.exe"
	 md5 = "651d63de08f4352d4ad5fcfdf1d4f0c1"
strings: 
	//SideTwist generates IDs to use for communications.
	$Func1 = "GetComputerName"
	$Func2 = "GetUserName"
	
	//functionality of sidetwist
	$s1 = "2>&1" //looking for command execution 
	$s2 = "base64"
	$s3 = "\\SystemFailureReporter\\update.xml" fullword ascii
	$s4 = "*/</script>" fullword ascii
	$s5 = "<script>/*" fullword ascii
	$s6 = "/getFile/" fullword ascii
	$s7 = "192.168.0.4" fullword ascii
	$s8 = "443"
	
	//sending response or delivering malware 
	$com = "WinHTTP Example/1.0" fullword wide
	$com2 = "GET" nocase
	$com3 = "WinHttpSendRequest"
	$com4 = "WinHttpReceiveResponse"
	$com5 = "WinHttpReadData"
	$com6 = "winhttp.dll" nocase
	
condition:
	uint16(0) == 0x5a4d and all of ($Func*) and all of ($com*) and any of ($s*)

}

rule TWOFACE_strings
{
meta: 
	author = "MITRE Engenuity"
	date = "9/15/2022"
	description = "This is a YARA rule to detect TWOFACE which is a webshell."
    source = "ATT&CK Evaluations Managed Services Round 1"
    tool = "TWOFACE"
    filename = "contact.aspx"
    md5 = "7ee0f50ada6b404961c38368c4c21448"
strings:
	$s1 = "base64" nocase
	$s2 = "http" nocase
	$s3 = "*/</script>" fullword ascii
	$s4 = "<script>/*" fullword ascii
	$func1 = "cmd.exe" nocase
	$func2 = "/EWS/contact.aspx"
	$func3 = "powershell.exe"
	$func4 = "-ExecutionPolicy bypass -NonInteractive"
	$s9 = "                    System.Web.HttpPostedFile UploadedFile = FileCollection.Get(FieldNameForFile);" fullword ascii
condition:
	all of ($func*) and 3 of ($s*)
}
