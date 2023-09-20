rule carbon_dropper {
meta:
    author      = "MITRE Engenuity"
    date        = "2023-08-15"
    description = "This is a YARA rule to detect the Carbon Dropper used to install persistence with C2 comms over HTTP."
    tool        = "Carbon Dropper"
    filename1   = "dropper.exe"
    hash1       = "365105a600fb00760f9f3a649121d4a4c4be06620aacc4c901c1039e22b23e72"
    filename2   = "carbon_installer_2.exe"
    hash2       = "5b87b98a8ad945c0d9fdc1b3584940342dd2272811c4911c05ce5de3e9f61355"
    filename3   = "carbon_installer_3.exe"
    hash3       = "32eba99cd94fad049c374839b089efa8249dfc5292fec8c772ee51edd517b39f"

strings:
    $x1 = "C:\\Windows\\System32\\svchost.exe -k WinSysRestoreGroup"
    $x2 = "C:\\Program Files\\Windows NT\\MSSVCCFG.dll"

    $s1 = "MSXHLP.dll"
    $s2 = "mressvc.dll"
    $s3 = "loader.dll"
    $s4 = "Windows NT\\setuplst.xml"
    $s5 = "KERNEL32.dll"
    $s6 = "dsntport.dat"
    $s7 = "LoadLibraryA"
    $s8 = "p2p client"
    $s9 = "TESTING_C2_SERVER_IP"
    $s10 = "InternetOpenWrapper"
    $s11 = "SYSTEM\\CurrentControlSet\\services\\WinResSvc\\Parameters"
    $s12 = "C:\\Program Files\\Windows NT\\2028\\traverse.gif"

condition:
    uint16(0) == 0x5a4d and filesize < 14000KB and
    any of ($x*) and all of ($s*)
}


rule epic_dropper {
meta:
    author      = "MITRE Engenuity"
    date        = "2023-08-15"
    description = "This is a YARA rule to detect the Epic Dropper used to install persistence with C2 comms over HTTP or HTTPS."
    tool        = "EPIC HTTP Dropper"
    filename1   = "SimpleDropper_http.exe"
    hash1       = "fe9ea7be2021b0d02525c676ae0fd7276740bb090d1c2ac52c4904b54be3d2dc"
    filename2   = "SimpleDropper_https.exe"
    hash2       = "a3cd74364050fcf7f968938dde03a612f74cac9a8756a8315278b77d1deb1feb"

strings:
    $s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    $s2 = "Shell"
    $s3 = "\\mxs_installer.exe"
    $s4 = "C:\\Windows\\explorer.exe"
    $s5 = "CreateToolhelp32Snapshot"
    $s6 = "FindResourceW"
    $s7 = "explorer.exe"
    $s8 = "\\~D723574.tmp"
    $s9 = "POST"

    $w1 = "svchost.exe"
    $w2 = "msedge.exe"
    $w3 = "iexplore.exe"
    $w4 = "firefox.exe"

condition:
    uint16(0) == 0x5a4d and filesize < 5000KB and
    all of ($s*) and any of ($w*)
}


rule keylogger {
meta:
    author      = "MITRE Engenuity"
    date        = "2023-08-15"
    description = "This YARA rule is to detect the Keylogger"
    tool        = "Keylogger"
    filename    = "keylogger.exe"
    hash        = "9f950697b9b91dcab6cbed2438a4c24da228f1ecb4cbad3e0a265c67f31a33bb"

strings:
    $s1 = "GetComputerNameA"
    $s2 = "~DFA512.tmp"
    $s3 = "USER32.dll"
    $s4 = "WTSAPI32.dll"
    $s5 = "[CTRL+BREAK PROCESSING]"
    $s6 = "        <requestedExecutionLevel level=\"asInvoker\"/>"

condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and
    all of them
}


rule snake {
meta:
    author      = "MITRE Engenuity"
    date        = "2023-08-15"
    description = "This is a YARA rule to detect the Snake Installer which communicates with the C2 server over HTTP."
    tool        = "Snake"
    filename1   = "snake.exe"
    hash1       = "6812b1799cc7accfdecf90471b8b9cef5f2329cbdc86eda4395f47652f694c33"
    filename2   = "installer_v2.exe"
    hash2       = "e4924cc8a2f4f7a76ab6d5e75b8eb0fc27bf54c45109eb5feb2387dec8c14d9c"
    filename3   = "installer_v3.exe"
    hash3       = "f8116f194d144f0cb8eb3398f95ff7fe0120302de67d17d73aa4e84a9eefb3b7"

strings:
    $x1 = "Install an unsigned driver"
    $x2 = "CI.dll"
    $x3 = "StartServiceW"
    $x4 = "Failed to grant window station and desktop access"
    $x5 = "CreateProcessWithTokenWrapper"
    $x6 = "WaitForSingleObjectWrapper"

    $s1 = "Duplicated elevated process token for target user."
    $s2 = "PeekNamedPipeWrapper"
    $s3 = "ReleaseMutexWrapper"
    $s4 = "Windows\\$NtUninstallQ608317$"
    $s5 = "gusb"
    $s6 = "POST request"
    $s7 = "server log file"
    $s8 = "C2 log file"
    $s9 = "beacon response"
    $s10 = "Shell Command:"
    $s11 = "Force the driver installation as SYSTEM"

condition:
    uint16(0) == 0x5a4d and filesize < 25000KB and
    5 of ($x*) and all of ($s*)
}


rule ln_transport_agent {
meta:
    author      = "MITRE Engenuity"
    date        = "2023-08-15"
    description = "This is a YARA rule to detect the LightNeuron transport agent used to collect emails on an Exchange server"
    tool        = "LightNeuron Transport Agent DLL"
    filename    = "ln_transport_agent.dll"
    hash        = "38c53b411dde5b09e600c47267fe7297342bf687b5eb8a020a270d015fc4e6c3"

strings:
    $x1 = "Microsoft.Exchange.Transport.Agent.ConnectionFiltering.dll"
    $x2 = "C:\\Windows\\serviceprofiles\\networkservice\\appdata\\Roaming\\Microsoft\\Windows\\msxfer.dat" fullword wide

    $s1 = "Microsoft.Exchange.Data.Transport.Smtp"
    $s2 = "Microsoft.Exchange.Transport.Agent.ConnectionFiltering"
    $s3 = "Microsoft.Exchange.Data.Transport.Email"
    $s4 = "exdbdata.dll"

condition:
    uint16(0) == 0x5a4d and filesize < 20KB and
    1 of ($x*) and all of ($s*)
}


rule ln_installer_aux {
meta:
    author      = "MITRE Engenuity"
    date        = "2023-08-15"
    description = "This is a YARA rule to detect the LightNeuron companion DLL which"
    description = "  uses steganography to extract commands from emails coming from"
    description = "  the C2 server and embed command output within JPGs emailed back"
    description = "  to the C2 server."
    tool        = "LightNeuron Companion DLL"
    filename    = "n_installer_aux.dll"
    hash        = "b8af645791bb2f6a8d72ec87396caebb2a38874701fa4c2a1ac96f92f6037161"

strings:
    $s1 = "C:\\Program Files\\Microsoft\\Exchange Server\\V15\\Bin\\winmail.dat"
    $s2 = "C:\\Program Files\\Microsoft\\Exchange Server\\V15\\TransportRoles\\Pickup\\"
    $s3 = "exdbdata.dll"
    $s4 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide
    $s5 = "AppPolicyGetProcessTerminationMethod"
    $s6 = ".eml"

condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and
    all of them
}
