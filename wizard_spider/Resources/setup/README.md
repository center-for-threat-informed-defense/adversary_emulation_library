# Wizard Spider Setup Procedure

## Clone the repo

git clone the wizard spider repo into your home directory:

```
git clone git@github.com:attackevals/wizard_spider.git
```

Note that this requires having read access to our repo and multi-factor authentication setup.

## Configure Domain Controller

1. RDP into domain controller

```
xfreerdp +clipboard /u:oz\\vfleming /p:"q27VYN8xflPcYumbLMit" /v:10.0.0.4 /drive:X,wizard_spider/Resources/setup
```

2. Open Windows Defender, toggle all nobs to the off position. Also go to App and Browser control and turn off Smart Screen.

3. Open PowerShell being sure to select "Run as Administrator":

```
cd \\TSCLIENT\X
Set-Executionpolicy bypass -force
.\install_adfind.ps1
.\install_firefox.ps1
.\create_domain_users.ps1
.\give_rdp_permissions.ps1
.\setup_spn.ps1
.\enable-winrm.ps1
.\disable-defender.ps1
.\file_generator\generate-files.exe -d "C:\Users\Public\" -c 100 --seed "EVALS" --noprompt
.\file_generator\generate-files.exe -d "C:\Users\" -c 50 --seed "EVALS" --noprompt
```

4. Next we need to download Microsoft Visual C++ Redistributable.

Open FireFox; close all spurious prompts / decline everything.

Go to this page:

https://support.microsoft.com/en-us/topic/the-latest-supported-visual-c-downloads-2647da03-1eea-4433-9aff-95f26a218cc0

Download and install the 32-bit and 64-bit versions.

5. Reboot the workstation

```
Restart-Computer -Force
```

## Configure Dorothy / 10.0.0.7

1. RDP into Dorothy

```
xfreerdp +clipboard /u:oz\\vfleming /p:"q27VYN8xflPcYumbLMit" /v:10.0.0.7 /drive:X,wizard_spider/Resources/setup
```

2. Open Windows Defender, toggle all nobs to the off position.

3. Configure Outlook and office?

4. Open PowerShell being sure to select "Run as Administrator":

```
cd \\TSCLIENT\X
Set-Executionpolicy bypass -force
.\give_rdp_permissions.ps1
.\enable-winrm.ps1
.\disable-defender.ps1
.\file_generator\generate-files.exe -d "C:\Users\Public\" -c 100 --seed "EVALS" --noprompt
.\file_generator\generate-files.exe -d "C:\Users\" -c 50 --seed "EVALS" --noprompt
.\file_generator\generate-files.exe -d "C:\Users\" -c 50 --seed "EVALS" --noprompt
```

For local testing:

```
.\install_msoffice.ps1
```

Open Word and Outlook; surpress all spurious prompts.

Close Word and outlook.

```
.\setup_outlook.ps1
```

5. Next we need to download Microsoft Visual C++ Redistributable.

Open Edge; close all spurious prompts / decline everything.

Go to this page:

https://support.microsoft.com/en-us/topic/the-latest-supported-visual-c-downloads-2647da03-1eea-4433-9aff-95f26a218cc0

Download and install the 32-bit and 64-bit versions.


6. Reboot the workstation

```
Restart-Computer -Force
```


7. Log back into Dorothy as user judy

```
xfreerdp +clipboard /u:oz\\judy /p:"Passw0rd!" /v:10.0.0.7
```

Open an Administrator CMD.exe

Run this command to take ownership of a privileged directory:

```
takeown /f "C:\Windows\*" /r /d y
icacls "C:\Windows\*" /grant judy:(OI)(CI)F /T
```

8. Sign out of the RDP session.

## Configure Toto / 10.0.0.8

1. RDP into Toto

```
xfreerdp +clipboard /u:oz\\vfleming /p:"q27VYN8xflPcYumbLMit" /v:10.0.0.8 /drive:X,wizard_spider/Resources/setup
```

2. Open Windows Defender, toggle all nobs to the off position.

3. Open PowerShell being sure to select "Run as Administrator":

```
cd \\TSCLIENT\X
Set-Executionpolicy bypass -force
.\give_rdp_permissions.ps1
.\enable-winrm.ps1
.\disable-defender.ps1
.\file_generator\generate-files.exe -d "C:\Users\Public\" -c 100 --seed "EVALS" --noprompt
.\file_generator\generate-files.exe -d "C:\Users\" -c 50 --seed "EVALS" --noprompt
.\file_generator\generate-files.exe -d "C:\Users\" -c 50 --seed "EVALS" --noprompt
```

4. Reboot the workstation

```
Restart-Computer -Force
```
