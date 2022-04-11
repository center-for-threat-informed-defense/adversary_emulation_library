rule lazagne_strings

{
	meta:
		author = "MITRE Engenuity"
		date = "2/16/2022"
		description = "Used to detect strings associated with lazagne.exe"
	
    strings:
        $string1 = "lazagne" nocase
		$string2 = "browsers" nocase
		$string3 = "chromium" nocase
        $string4 = "mozilla" nocase
		$string5 = "win32.hashdump" nocase
		$string6 = "creddump7" nocase
        $string7 = "credfile" nocase
		
    condition:
        all of them
}

rule ExaramelLinux_strings

{
	meta:
		author = "MITRE Engenuity"
		date = "2/16/2022"
		description = "Used to detect strings associated with Exaramel-Linux"
	
    strings:
        $string1 = "attackevals" nocase
		$string2 = "mitre-engenuity" nocase
		$string3 = "exaramel" nocase
        $string4 = "sandworm" nocase
		
    condition:
        all of them
}

rule ExaramelWindows

{
	meta:
		author = "MITRE Engenuity"
		date = "2/16/2022"
		description = "Used to detect strings associated with ExaramelWindows"
	
    strings:
        $string1 = "command-line-arguments" nocase
		$string2 = "exaramel-windows" nocase
		$string3 = "CreateBeacon" nocase
		$string4 = "GetSystemInfo" nocase
		$string5 = "ExecShellCommand" nocase
		$string6 = "taskhandler" nocase
		$string7 = "GetFileFromServer" nocase
		$string8 = "cmdHandle" nocase
		$string9 = "GetOSInfo" nocase
		$string10 = "Getpid" nocase
		$string11 = "CryptRC4" nocase
		$string12 = "GetOutboundIP" nocase
		$string13 = "ParseExecCmd" nocase
		$string14 = "RegisterImplant" nocase
		$string15 = "sandworm" nocase

    condition:
        all of them
}

rule mslog_strings

{
	meta:
		author = "MITRE Engenuity"
		date = "2/16/2022"
		description = "Used to detect strings associated with mslog.exe"
	
    strings:
        $string1 = "_FindPESection" nocase
		$string2 = "Could not open file" nocase
		$string3 = "Failed to get handle" nocase
		$string4 = "Capture ready" nocase
		$string5 = "Starting capture" nocase
		$string6 = "_ValidateImageBase" nocase
		$string7 = "[CAP-LOCK]" nocase
		$string8 = "[ENTER]" nocase
		$string9 = "[CLEAR]" nocase

    condition:
        all of them
}

rule perfc_strings

{
	meta:
		author = "MITRE Engenuity"
		date = "2/16/2022"
		description = "Used to detect strings associated with perfc.dat"
	
    strings:
        $string1 = "6A2F1605C8391B7144D70E0CB99F5816C9EE549545097E40FA26077B292A28D2"
		$string2 = "ATT&CK3valuat10n" nocase
		$string3 = "SharpNP" nocase

    condition:
        all of them
}

rule wsmprovav_strings

{
	meta:
		author = "MITRE Engenuity"
		date = "2/16/2022"
		description = "Used to detect strings associated with wsmprovav.exe"
	
    strings:
        $string1 = "Not enough arguments" nocase
		$string2 = "192.168.0.4" nocase
		$string3 = "file.exe" nocase
		$string4 = "Loading urlmon.dll via LoadLibraryExA" nocase
		$string5 = "Failed to load urlmon.dll" nocase
		$string6 = "Resolving address of URLDownloadToFile via GetProcAddress" nocase
		$string7 = "Failed to resolve address of URLDownloadToFile" nocase
		$string8 = "Downloading file" nocase
		$string9 = "Failed during call to URLDownloadToFile" nocase
		$string10 = "Exaramel" nocase

    condition:
        all of them
}