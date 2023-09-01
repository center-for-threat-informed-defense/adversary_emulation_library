# Scenario Infrastructure

We hope to capture the general structure of what is reported to have been seen being used by [Blind Eagle](http://attack.mitre.org/groups/G0099/).

The requirements described herein should be considered a bare minimum to execute the scenario. If you have the time and resources to remain true-to-form, you may elect to stand up multiple of each of these servers, non-contiguous IP space, etc. If you are not concerned with emulating [Blind Eagle](https://attack.mitre.org/groups/G0099/) to this degree, this level of effort is not necessary. You could for instance, phish, serve payload, and act on objectives on a single server.

## Network Diagram

Below is the domains and infrastructure used to support the setup and execution of the Blind Eagle [Emulation plan](../../Emulation_Plan/).

![Infra](../Screenshots/infrastructurediagram.png)


## Emulation Team Infrastructure

This emulation leveraged the following attacker infrastructure with configurations.

| Red Team System | IP Address | OS |
| ------ | ------ | ------ |
| Windows Attack Platform | 192.168.0.4 | Windows 10 Pro - Build 19044 |
| Web Server | 192.168.0.5 | Ubuntu 20.04 LTS |

#### A note about payloads

- This evaluation utilizes payloads that model malware previously used by Blind Eagle.
- These utilities include loaders, injectors, and implants.
- The [Binaries.zip](../Binaries/Binaries.zip) contains all executables in one zip file for easy download. The password is `malware`.
  - Implants are configured to connect back to static IP address 192.168.0.4. Build instructions for each payload can be found with source code in their respective directories.

### Windows Attack Platform Setup \ 192.168.0.4

RDP to your Windows Attack Platform

1. Open Windows Defender and toggle all of the knobs to the off position - this is so that Defender will not eat your malware

    ![defender-off](../Screenshots/windows-av-off.png)
1. Open a PowerShell Prompt and download the Blind Eagle Adversary Emulation Library to your chosen directory on your Windows attack machine
    ```PowerShell
    git clone https://github.com/center-for-threat-informed-defense/blackhat-2023-becoming-a-dark-knight-emulation
    ```
1. Open File Explorer and navigate to the repo directory `Resources\Binaries\`. `Right click -> Extract Files` on `Binaries.zip` and provide the password `malware` when prompted

### Web Server Setup \ 192.168.0.5

SSH to the web server from either your machine or a separate PowerShell prompt on your Windows Attack Platform:
```
ssh ubuntu@192.168.0.5
```

1. Download the Blind Eagle Adversary Emulation Library to the `/opt` folder on your Linux Web Machine
    ```bash
    cd /opt/
    ```
    ```bash
    git clone https://github.com/center-for-threat-informed-defense/blackhat-2023-becoming-a-dark-knight-emulation
    ```
1. `cd` to `/opt/blackhat-2023-becoming-a-dark-knight-emulation` and use `unzip -P malware Resources/Binaries/Binaries.zip` to extract payloads
    ```bash
    cd /opt/blackhat-2023-becoming-a-dark-knight-emulation
    ```
    ```bash
    unzip -P malware Resources/Binaries/Binaries.zip
    ```
1. Create a the following directories to host payloads from the attack users home directory:
    ```bash
    mkdir -p ~/web/{rump,dll,notificaciones/contribuyentes/factura-228447578537}
    ```
1. Use the Shell commands below to populate the binaries in the expected directories for the scenario:
    ```bash
    cp Resources/Binaries/asy.txt ~/web
    ```
    ```
    cp Resources/Binaries/new_rump_vb.net.txt ~/web/dll
    ```
    ```
    cp Resources/Binaries/Rump.xls ~/web/rump
    ```
    ```
    cp Resources/Binaries/factura-228447578537.pdf.uue ~/web
    ```
    ```
    cp Resources/Binaries/index.html ~/web/notificaciones/contribuyentes/factura-228447578537
    ```
1. SCP the bancomurcielago website built using Django CMS to the victim Web server :heavy_exclamation_mark: this will be used in a later configuration step
    ```bash
    scp /opt/blackhat-2023-becoming-a-dark-knight-emulation/Resources/Binaries/django-cms-quickstart.zip ubuntu@10.1.0.4:/opt
    ```

## Target Infrastructure

4 targets, all domain joined to the `bancomurcielago` domain:

| Target System | Hostname | IP Address | OS |
| ------ | ------ | ------| ----- |
| webserver | bancomurcielago-linux-srv3 | 10.1.0.4 | Ubuntu 20.04 LTS |
| Domain Controller | canario | 10.1.0.10 | Windows Server 2019 - Build 17763 |
| Exchange Server | mail | 10.1.0.11 | Windows Server 2019 - Build 17763 |
| Exchange Admin Workstation | desk1 | 10.1.0.7 | Windows 10 Pro - Build 19043 |

### Configure Domain Controller `canario`\ 10.1.0.10

Note: in the scenario, DNS records were manually created to emulate network activity from suspect domains
If you wish to create DNS records the following will be useful for a complete emulation:

| IP Address | DNS Name |
| --- | --- |
| 192.168.0.5 | dian-info.com | 
| 10.1.0.4 | web.bancomurcielago.com |

1. Create the user accounts as used in the scenario:

    | username | groups |
    | ---------- | ----------|
    | demo_admin | Domain Users |
    | devadmin | EWS Admins, Domain Admins, Domain Users |

### Configure Workstation `desk1`\ 10.1.0.7

RDP to the workstation from either your computer or the Windows Attack Machine:

1. Open Windows Defender, toggle all nobs to the off position - this is so that the malware can execute properly to completion
   If it is is useful to your organization to test defenses against this adversary you may choose to do this differently, however
   some tradecraft is likely to be blocked by modern EDR solutions (we hope)

   ![defender-off](../Screenshots/windows-av-off.png)

### Configure EWS Server `mail`\ 10.1.0.11

SSH to mail from either your computer or the Windows Attack Machine:
```
ssh ubuntu@10.1.0.11
```

1. Setup [Exchange Server](https://www.microsoft.com/en-us/download/details.aspx?id=103477) to host OWA and EAC.
1. Create the "EWS Admins" group, adding `devadmin`

### Configure Web Server `bancomurcielago-linux-srv3`\ 10.1.0.4

1. Remove any prior Docker and Docker-Compose installations:
    ```bash
    for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do sudo apt-get remove $pkg; done
    ```
1. Install prerequisite packages:
    ```bash
    sudo apt-get update
    sudo apt-get install ca-certificates curl gnupg
    ```
1. Set up Docker APT repo:
    ```bash
    # add gpg key
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg

    # set up repo
    echo \
    "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    # apt update
    sudo apt update
    ```
1. Install Docker and Docker Compose:
    ```bash
    sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin unzip
    ```
1. unzip website built with Django CMS in `/opt/` on `bancomurcielago-linux-srv3`
    ```bash
    unzip /opt/django-cms-quickstart.zip
    ```
1. Run the website with Docker:
    ```bash
    cd /opt/django-cms-quickstart
    sudo docker compose up -d
    ```

The bancomurcielago website should now be hosted on HTTP port 8000

## Resources

The [Binaries.zip](../Binaries/Binaries.zip) contains all executables in one zip file for easy download. The password is `malware`. :heavy_exclamation_mark: binaries in this folder will only work with the infrastructure configuration described in this document as some payloads need to be built with specific URLs hard coded.

## Additional Plan Resources

- [Intelligence Summary](../../Intelligence_Summary/Intelligence_Summary.md)
- [Operations Flow](../../Operations_Flow/Operations_Flow.md)
- [Emulation Plan](../../Emulation_Plan/README.md)
- [Issues](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/issues)

