# OilRig Scenario Cleanup Procedures

Clean up scripts provided will check and delete all artifacts. The script will also force reboot
the host at the end of the script's execution.

## THEBLOCK (10.0.1.5)

1. RDP into THEBLOCK as follows:
```
# from the Resources/cleanup directory

xfreerdp +clipboard /u:boombox\\gosta /p:"d0ntGoCH4$ingW8trfalls" /v:10.1.0.5 /drive:X,Resources/cleanup
```

2. Open PowerShell and select "Run as Administrator":
```
cd \\TSCLIENT\X
Set-ExecutionPolicy bypass -force
.\cleanup-theblock.ps1
```

### Artifact List

#### SideTwist Dropper/SideTwist 
- SystemFailureReporter schtask
- C:\Users\gosta\Downloads\Marketing_Materials.zip
- C:\Users\gosta\Downloads\GGMS Overview.doc
- C:\Users\gosta\AppData\Local\SystemFailureReporter\
  - (File renamed) C:\Users\gosta\AppData\Local\SystemFailureReporter\b.doc
  - C:\Users\gosta\AppData\Local\SystemFailureReporter\SystemFailureReporter.exe
  - (Removed in scenario) C:\Users\gosta\AppData\Local\SystemFailureReporter\update.xml

#### VALUEVAULT
- (Removed in scenario) C:\users\gosta\AppData\Roaming\b.exe
- (Removed in scenario) C:\users\gosta\AppData\Roaming\fsociety.dat

#### Other
- (Removed in scenario) C:\Users\Public\Downloads\plink.exe
- (Removed in scenario) C:\Users\Public\contact.aspx

## WATERFALLS (10.0.1.6)

1. RDP into WATERFALLS as follows:
```
# from the Resources/cleanup directory

xfreerdp +clipboard /u:boombox\\gosta /p:"d0ntGoCH4$ingW8trfalls" /v:10.1.0.6 /drive:X,Resources/cleanup
```

2. Open PowerShell and select "Run as Administrator":
```
cd \\TSCLIENT\X
Set-ExecutionPolicy bypass -force
.\cleanup-waterfalls.ps1
```

### Artifact List

#### TwoFace
- C:\Program Files\Microsoft\Exchange Server\V15\ClientAccess\exchweb\ews\contact.aspx

#### Other
- (Removed in scenario) C:\Windows\System32\m64.exe
- (Removed in scenario) C:\Windows\Temp\01.txt
- (Removed in scenario) C:\Windows\System32\ps.exe 
- (Removed in scenario) C:\Windows\temp\Nt.dat
- (Removed in scenario) C:\Windows\System32\mom64.exe

## ENDOFROAD (10.0.1.7)

1. RDP into WATERFALLS as follows:
```
# from the Resources/cleanup directory

xfreerdp +clipboard /u:boombox\\tous /p:"E2Ung_ZS%x-E-T5G" /v:10.1.0.7 /drive:X,Resources/cleanup
```

2. Open PowerShell and select "Run as Administrator":
```
cd \\TSCLIENT\X
Set-ExecutionPolicy bypass -force
.\cleanup-endofroad.ps1
```

### Artifact List

#### RDAT
- (File renamed) C:\ProgramData\Nt.dat
- (Removed in scenario) C:\ProgramData\VMware\
  - (Removed in scenario) C:\ProgramData\VMware\VMware.exe
- C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Backup\guest.bmp
- C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Backup\guest.bmp.tmp