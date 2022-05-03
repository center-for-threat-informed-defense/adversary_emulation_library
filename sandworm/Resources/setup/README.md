# Sandworm Range Setup Instructions

## Configure dungeon - 192.168.0.4

0. Clone sandworm repo to home directory

```bash
cd ~/
git clone git@github.com:attackevals/sandworm.git
git clone git@github.com:attackevals/wizard_spider.git
```

Enter your credentials when prompted.

Stage the file generator for later user:

```bash
cp ~/wizard_spider/Resources/setup/file_generator/generate-files.exe ~/sandworm/Resources/setup/
cp -R ~/wizard_spider/Resources/setup/file_generator/templates/ ~/sandworm/Resources/setup/
```

Install terminator:

```bash
sudo chmod 755 ./sandworm/Resources/setup/setup_attack_platform.sh
sudo ./sandworm/Resources/setup/setup_attack_platform.sh 
```

If you are prompted to automatically restart services, select yes.

## Configure Caladan - 10.0.1.5

1. Upload caladan.sh to 10.0.1.5 via SCP

```bash
scp sandworm/Resources/setup/setup_caladan.sh fherbert@10.0.1.5:/tmp/setup_caladan.sh
```

Password:

`Whg42WbhhCE17FEzrqeJ`

:warning: Run this command if you get SSH key errors

```bash
rm -rf ~/.ssh/known_hosts
```

2. Upload SUID binary to caladan

```bash
scp sandworm/Resources/suid-binary/suid-binary fherbert@10.0.1.5:/tmp/suid-binary
```

3. Run caladan.sh

```bash
ssh fherbert@10.0.1.5 "chmod 755 /tmp/setup_caladan.sh && sudo /tmp/setup_caladan.sh && shred /tmp/setup_caladan.sh"
```

4. Reboot caladan

```bash
ssh fherbert@10.0.1.5 "sudo reboot"
```

## Configure Gammu - 10.0.1.7

1. RDP into Gammu:

```
xfreerdp +clipboard /u:WORKGROUP\\fherbert /p:"Whg42WbhhCE17FEzrqeJ" /v:10.0.1.7 /drive:X,sandworm/Resources/setup/
```

2. Open Windows Defender, toggle all nobs to the off position.

3. Open PowerShell being sure to select "Run as Administrator":

```
cd \\TSCLIENT\X
Set-Executionpolicy bypass -force
.\install_software.ps1
.\enable-winrm.ps1
.\disable-defender.ps1
.\generate-files.exe -d "C:\Users\" -c 50 --seed "EVALS" --noprompt
```

4. Open Chromium and navigate to: 

`https://www.stealmylogin.com/demo.html`

5. Enter the following credentails; save / cache the credentials when prompted.

```
fherbert@mail.com
Passw0rd123!!!
```

5. Double check the credentials were cached by going to Chromium settings > passwords. You should have one entry for stealmylogin.com.

6. Reboot gammu:

```powershell
Restart-Computer -Force
```

## Configure arrakis - 10.0.1.4

1. RDP into arrakis:

```
xfreerdp +clipboard /u:dune\\patreides /p:"ebqMB7DmM81QVUqpf7XI" /v:10.0.1.4 /drive:X,sandworm/Resources/setup/
```

2. Open Windows Defender, toggle all nobs to the off position.

3. Open PowerShell being sure to select "Run as Administrator":

```powershell
cd \\TSCLIENT\X
Set-Executionpolicy bypass -force
.\enable-winrm.ps1
.\disable-defender.ps1
```

5. Reboot

```powershell
Restart-Computer -Force
```

## Configure quadra - 10.0.1.8

1. RDP into quadra:

```bash
xfreerdp +clipboard /u:dune\\patreides /p:"ebqMB7DmM81QVUqpf7XI" /v:10.0.1.8 /drive:X,sandworm/Resources/setup/
```

2. Open Windows Defender, toggle all nobs to the off position.

3. Open PowerShell being sure to select "Run as Administrator":

```
cd \\TSCLIENT\X
Set-Executionpolicy bypass -force
.\install_software.ps1
.\enable-winrm.ps1
.\disable-defender.ps1
.\generate-files.exe -d "C:\Users\" -c 50 --seed "EVALS" --noprompt
```

4. Reboot

```powershell
Restart-Computer -Force
```
