### Payloads Explained
* ```2016_United_States_presidential_election_-_Wikipedia.html```: Staging payload for ADFS.
* ```cod.3aka.scr.exe```: Sandcat payload to complete RTLO execution.
* ``` dmevals.local.pfx```: Staged private key used for Get-PrivateKey discovery.
* ``` File-Collection.ps1```: PowerShell script to collect the following: 
    * *.doc
    * *.xps
    * *.xls
    * *.ppt
    * *.pps
    * *.wps
    * *.wpd
    * *.ods
    * *.odt
    * *.lwp
    * *.jtd
    * *.pdf
    * *.zip
    * *.rar
    * *.docx
    * *.url
    * *.xlsx
    * *.pptx
    * *.ppsx
    * *.pst
    * *.ost
    * *psw*
    * *pass*
    * *login*
    * *admin*
    * *sifr*
    * *sifer*
    * *vpn
    * *.jpg
    * *.txt
    * *.lnk
* ``` Get-Screenshot.ps1```: [PowerShell Empire Script](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection/Get-Screenshot.ps1) script to take screenshots.
* ``` Invoke-BypassUACTokenManipulation.ps1```: [PowerShell Empire script](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/Invoke-BypassUACTokenManipulation.ps1) to bypass UAC.
* ``` Invoke-Mimikatz.ps1```: [PowerShell Empire PowerShell script](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Mimikatz.ps1) to execute Mimikatz.
* ``` Invoke-PSInject.ps1```: [PowerShell Empire PowerShell script](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management/Invoke-PSInject.ps1) to execute base64 encoded PowerShell code.
* ``` invoke-winrmsession.ps1```: [PoshC2 script](https://github.com/nettitude/PoshC2/blob/master/resources/modules/Invoke-WinRMSession.ps1) to create winrm sessions.
* ``` make_lnk.ps1```: Payload generation script to create masqumasquerading .lnk file
* ``` m.exe```: [Mimikatz](https://github.com/gentilkiwi/mimikatz) executable.
* ``` MITRE-ATTACK-EVALS.HTML```: Staged .html only used for Discovery.
* ``` Modified-SysInternalsSuite.zip```: Utilities used in persistence mechanisms that are stored within a SysInternals directory. 

**Note, none of the utilities here are actually Windows SysInternals tools.
The SysInternals is downloaded from Microsoft during Day-1 A execution.**

* ``` monkey.png```: Stenography png with encoded payload.
* ``` powerview.ps1```: Powerview functions to execute reflective loading.
* ``` ps.ps1```: Process enumeration.
* ``` rar.exe```: Archive utility.
* ``` sandcat.go-windows```: Sandcat binary.
* ``` sandcat.go-windows-upx```: UPX packed Sandcat binary.
* ``` schemas.ps1```: Payload generation script using alternate data streams.
* ``` setup.py```: Setup utility to update all payloads with appropriate IP:PORT.
* ``` StealToken.ps1```: Steal a process' token.
* ``` stepFifteen_wmi.ps1```: WMI persistence.
* ``` stepFourteen_bypassUAC.ps1```: UAC bypass via sdclt.exe.
* ``` stepFourteen_credDump.ps1```: WMI Based credential dump.
* ``` stepSeventeen_email.ps1```: Outlook e-mail enumeration.
* ``` stepSeventeen_zip.ps1```: Zip up a directory.
* ``` stepSixteen_SID.ps1```: Get SID of user.
* ``` stepThirteen.ps1```: Discovery functions.
* ``` stepTwelve.ps1```: Detect AntiVirus.
* ``` timestomp.ps1```: Timestomp a file.
* ``` update.ps1```: Update sandcat payload.
* ``` upload.ps1```: CALDERA upload utility.
* ``` wipe.ps1```: Reflectivly load sdelete64.exe.
