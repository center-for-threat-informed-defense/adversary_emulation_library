# OilRig Setup Procedure

## Emulation Team Infrastructure

1.  **Linux Attack Platform**: Kali Linux 2019.2
2.  **Mail and Apache Server**: Kali Linux 2019.2 

## Emulation Team Infrastructure Configuration

This methodology assumes the following static IP address configurations:

| Red Team System | IP Address |
| ------ | ------ |
| Linux Attack Platform | 192.168.0.4 |
| Mail and Apache Server | 192.168.0.5 |	

#### A note about red team payloads

- This evaluation utilizes payloads that model malware previously used by OilRig.
- These utilities include credential dumpers, implants, and file exfiltration.
- The [Binaries.zip](../Resources/Binaries/binaries.zip) contains all executables in one zip file for easy download. The password is `malware`.
  - Implants are configured to connect back to static IP address 192.168.0.4. Build instructions for each payload can be found with source code in their respective directories.

### Linux Attack Platform Setup \ 192.168.0.4

1. Download the OilRig Adversary Emulation Library to the `/opt/` directory
1. Use the Linux commands below to populate the binaries in the expected directories for the scenario:
    ```
    # from oilrig/
    unzip -P malware Resources/Binaries/binaries.zip

    # copy VALUEVAULT (b.exe) and TwoFace (contact.aspx) to the payload staging directory for SideTwist
    cp Resources/Binaries/b.exe Resources/payloads/SideTwist
    cp Resources/Binaries/contact.aspx Resources/payloads/SideTwist

    # copy RDAT.exe to the payload staging directory for TwoFace
    cp Resources/Binaries/RDAT.exe Resources/payloads/TwoFace
    ```
1. Download [Mimikatz](https://github.com/gentilkiwi/mimikatz/wiki) to the `Resources/payloads/TwoFace/` directory. Rename Mimikatz executable as `m64.exe`.
1. Download [Plink](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) to the `Resources/payloads/SideTwist/` directory
1. Download [PsExec.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) to the `Resources/payloads/TwoFace/` directory
1. Install [FreeRDP](https://github.com/FreeRDP/FreeRDP)

### Mail and File Server Setup \ 192.168.0.5
1. Install Apache
1. Install Postfix
1. Stage the SideTwist dropper `Marketing_Materials.zip` to /var/www/html
1. Run the [`install-configure-postfix.sh`](../../Resources/setup/install-configure-postfix.sh) bash script as sudo
    ```
    sudo ./install-configure-postfix.sh
    ```
1. Run the [`setup-apache-fileserver.sh`](../../Resources/setup/setup-apache-fileserver.sh) bash script as sudo
    ```
    sudo ./setup-apache-fileserver.sh
    ```
Note: You may need to chmod the scripts to allow them to run.

## Target Infrastructure

4 targets, all domain joined to the `boombox` domain:
1. *SQL Server* : tested and executed on CentOS 7.9
1. *Domain Controller* : tested and executed on Windows Server 2k19 - Build 17763
1. *Exchange Server* : tested and executed on Windows Server 2k19 - Build 17763
1. *Exchange Admin Workstation* : tested and executed on Windows 10 - Build 17763

## Target Infrastructure Configuration

| Target System | Hostname | IP Address |
| ------ | ------ | ------|
| SQL Server | endofroad | 10.1.0.7
| Domain Controller | diskjockey | 10.1.0.4 |
| Exchange Server | waterfalls | 10.1.0.6 |
| Exchange Admin Workstation | theblock | 10.1.0.5 |

### Configure Domain Controller `diskjockey`\ 10.1.0.4
Note: in the scenario, DNS records were manually created to emulate network activity from suspect domains
1. Open Windows Defender, toggle all nobs to the off position.
1. Open PowerShell being sure to select "Run as Administrator" and run the [`modify-defender.ps1`](../../Resources/preflight/modify-defender.ps1) script:
    ```
    .\modify-defender.ps1
    ```
1. Create the user accounts as used in the scenario:

    | username | groups |
    | ---------- | ----------|
    | tous | EWS Admins, SQL Admins, Domain Users |
    | gosta | EWS Admins, Domain Users | 
    | mariam | Domain Users |
    | shiroyeh | Domain Users |
    | shiroyeh_admin | Domain Admins |

1. In the Administrator Powershell Terminal run the [`disable-automatic-updates.ps1`](../../Resources/setup/disable-automatic-updates.ps1) script:
    ```
    .\disable-automatic-updates.ps1
    ```
1. In the Administrator Powershell Terminal run the [`choco-install.ps1`](../../Resources/setup/choco-install.ps1) script:
    ```
    .\choco-install.ps1
    ```
1. In the Administrator Powershell Terminal run the [`install-packages.ps1`](../../Resources/setup/install-packages.ps1) script:
    ```
    .\install-packages.ps1
    ```

### Configure Workstation `theblock`\ 10.1.0.5
1. Ensure [Microsoft Office](https://www.microsoft.com/en-us/download/office.aspx) is installed and that you're able to edit a document. This will ensure the macros run correctly against the host.
1. Open PowerShell being sure to select "Run as Administrator" and run the [`modify-defender.ps1`](../../Resources/preflight/modify-defender.ps1) script:
    ```
    .\modify-defender.ps1
    ```
1. In the Administrator Powershell Terminal run the [`disable-automatic-updates.ps1`](../../Resources/setup/disable-automatic-updates.ps1) script:
    ```
    .\disable-automatic-updates.ps1
    ```
1. In the Administrator Powershell Terminal run the [`choco-install.ps1`](../../Resources/setup/choco-install.ps1) script:
    ```
    .\choco-install.ps1
    ```
1. In the Administrator Powershell Terminal run the [`install-packages.ps1`](../../Resources/setup/install-packages.ps1) script:
    ```
    .\install-packages.ps1
    ```
### Configure EWS Server `waterfalls`\ 10.1.0.6
1. Setup [Exchange Server](https://www.microsoft.com/en-us/download/details.aspx?id=103477) to host OWA and EAC.
1. Create the "EWS Admins" group, adding `tous`, `gosta`
1. Install [MSSQL](https://www.microsoft.com/en-us/sql-server/sql-server-2019) 
1. Create a scheduled task to run the [`sql_connection.bat`](../../Resources/Infrastructure) upon system startup:
    ```
    schtasks /create /tn "SQL Connection" /tr <Path to the batch file> /sc onstart /U BOOMBOX\tous
    ```
1. Reboot the machine and verify connection in PowerShell:
    ```
    netstat -ano | select-string 1433
    ```
1. Open Windows Defender, toggle all nobs to the off position.
1. In the same PowerShell window,  run the [`modify-defender.ps1`](../../Resources/preflight/modify-defender.ps1) script:
    ```
    .\modify-defender.ps1
    ```
1. In the Administrator Powershell Terminal run the [`disable-automatic-updates.ps1`](../../Resources/setup/disable-automatic-updates.ps1) script:
    ```
    .\disable-automatic-updates.ps1
    ```
1. In the Administrator Powershell Terminal run the [`choco-install.ps1`](../../Resources/setup/choco-install.ps1) script:
    ```
    .\choco-install.ps1
    ```
1. In the Administrator Powershell Terminal run the [`install-packages.ps1`](../../Resources/setup/install-packages.ps1) script:
    ```
    .\install-packages.ps1
    ```
### Configure SQL Server `endofroad`\ 10.1.0.7

1. Install [MSSQL](https://www.microsoft.com/en-us/sql-server/sql-server-2019) and configure data to be stored locally on the C: drive.
1. Create an "SQL Admins" domain group with `tous` as a member, additionally giving tous access permissions and ownership of the DB.
1. Sign in as `tous` and create a new database called `sitedata`.
1. Import the `minfac.csv` data file to populate the database.
1. Create a backup of the database to the drive for later exfiltration by the adversary
	* Note: For the purpose of execution, this directory was `C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Backup\`
1. Open Windows Defender, toggle all nobs to the off position.
1. Open PowerShell being sure to select "Run as Administrator" and run the [`modify-defender.ps1`](../../Resources/preflight/modify-defender.ps1) script:
    ```
    .\modify-defender.ps1
    ```
1. In the Administrator Powershell Terminal run the [`disable-automatic-updates.ps1`](../../Resources/setup/disable-automatic-updates.ps1) script:
    ```
    .\disable-automatic-updates.ps1
    ```
1. In the Administrator Powershell Terminal run the [`choco-install.ps1`](../../Resources/setup/choco-install.ps1) script:
    ```
    .\choco-install.ps1
    ```
1. In the Administrator Powershell Terminal run the [`install-packages.ps1`](../../Resources/setup/install-packages.ps1) script:
    ```
    .\install-packages.ps1
    ```
1. Open port 1433 in Windows Defender Firewall
1. Add the "SQL Admins" group to Local Administrators

