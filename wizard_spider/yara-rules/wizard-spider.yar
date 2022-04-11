rule EmotetClientDLL_strings

{
	meta:
		author = "MITRE Engenuity"
		date = "2/16/2022"
		description = "Used to detect strings associated with EmotetClientDLL.dll"
	
    strings:
		$string1 = "Emotet" nocase
		$string2 = "outlook" nocase
		$string3 = "latmove" nocase
		$string4 = "paexec" nocase
		$string5 = "sessionID" nocase
		$string6 = "getCredentials" nocase
		$string7 = "getEmailAddresses" nocase
		$string8 = "Unable to read email addresses" nocase
		$string9 = "getTask" nocase
		$string10 = "blbdigital" nocase
		$string11 = "successfully installed persistence" nocase

    condition:
        all of them
}

rule OutlookScraper_strings

{
	meta:
		author = "MITRE Engenuity"
		date = "2/16/2022"
		description = "Used to detect strings associated with OutlookScraper.dll"
	
    strings:
        $string1 = "OutlookScraper" nocase
        $string2 = "powershell -Command" nocase
        $string3 = "outlook = Get-Process outlook -ErrorAction SilentlyContinue" nocase
        $string4 = "outlook.GetNameSpace" nocase
        $string5 = "olFolderInBox" nocase
        $string6 = "Select-Object -ExpandProperty Body | Select-String" nocase
        $string7 = "password" nocase
        $string8 = "New-Object -comobject outlook.application" nocase
        $string9 = "Select-Object -Unique -ExpandProperty SenderEmailAddress" nocase

    condition:
        all of them
}

rule ryuk_strings

{
	meta:
		author = "MITRE Engenuity"
		date = "2/16/2022"
		description = "Used to detect strings associated with ryuk.exe"
	
    strings:
		$string1 = "Your network has been penetrated" nocase
		$string2 = "All files on each host in the network has been encrypted with a strong algorithm" nocase
		$string3 = "Backups were either encrypted or deleted or backup discs were formatted" nocase
		$string4 = "We exclusively have decryption software for your situation" nocase
		$string5 = "No decryption software is available in the public" nocase
		$string6 = "DO NOT RESET OR SHUTDOWN - files may be damaged" nocase
		$string7 = "DO NOT DELETE the readme files" nocase
		$string8 = "To get info (decrypt your files) contact us at" nocase
		$string9 = "BTC wallet" nocase
		$string10 = "Ryuk" nocase

    condition:
        all of them
}

rule uxtheme_strings

{
	meta:
		author = "MITRE Engenuity"
		date = "2/16/2022"
		description = "Used to detect strings associated with uxtheme.exe"
	
    strings:
		$string1 = "temp.txt" nocase
		$string2 = "WinHttp" nocase
		$string3 = "get-file" nocase
		$string4 = "upload-file" nocase
		$string5 = "TrickBot-Implant" nocase
		$string6 = "Unable to cd" nocase
		$string7 = "Error deleting temporary file" nocase
		$string8 = "invalid string position" nocase
		$string9 = "Header contents" nocase
		$string10 = "Succsefully executed" nocase

    condition:
        all of them
}