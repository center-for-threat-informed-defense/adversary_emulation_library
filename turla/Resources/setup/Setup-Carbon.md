# Carbon Victim LAN Setup

- [Carbon Victim LAN Setup](#carbon-victim-lan-setup)
  - [Domain Controller - Bannik](#domain-controller---bannik)
  - [Desktop - Hobgoblin](#desktop---hobgoblin)
  - [Desktop - Domovoy](#desktop---domovoy)
  - [Desktop - Khabibulin](#desktop---khabibulin)
  - [Exchange - Brieftragerin](#exchange---brieftragerin)
  - [Web Server - Kagarov](#web-server---kagarov)
  - [Script order and dependencies](#script-order-and-dependencies)


## Domain Controller - Bannik

| Script                                    | Summary                                                      |
| ----------------------------------------- | :----------------------------------------------------------- |
| chocolatey-install.ps1                    | Installs Chocolatey Package Manager                          |
| choco-install-packages.ps1                | Installs sysinternals, vscode, and microsoft-edge            |
| bannik-create-carbon-domain.ps1           | Creates the Carbon scenario Active Directory domain (“skt.local”) |
| bannik-create-carbon-users.ps1            | Creates domain users and domain groups for Carbon scenario   |
| bannik-set-dns-resolution.ps1             | Set primary and secondary DNS on endpoints to the DC         |
| bannik-set-adalwolfa-group-membership.ps1 | Add Kagarov to Webservers group                              |

## Desktop - Hobgoblin

| Script                                                | Summary                                           |
| ----------------------------------------------------- | :------------------------------------------------ |
| chocolatey-install.ps1                                | Installs Chocolatey Package Manager               |
| choco-install-packages.ps1                            | Installs sysinternals, vscode, and microsoft-edge |
| all-join-carbon-domain.ps1                            | Join the Carbon domain                            |
| all-carbon-enable-remote-desktop-for-domain-users.ps1 | Enable remote desktop access for Domain Users     |
|                                                       |                                                   |

The Hobgoblin host also runs the ViperVPN Windows service used in the scenario. After running the setup, perform the following steps:

1. Copy the `windows-service/dist/ViperVPN.exe` file to Hobgoblin
2. Open Adminstrator Command Prompt on Hobgoblin
3. Execute the following command from the Command Prompt.
   1. `ViperVPN.exe --startup delayed install`
4. Install SetACL Studio on Hobgoblin (see [WindowsService](WindowsService.md) for download link)
5. Modify the ACL on the registry key `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ViperVPNSvc` to grant full control to `"Authenticated Users"`.



## Desktop - Domovoy

| Script                                                | Summary                                           |
| ----------------------------------------------------- | :------------------------------------------------ |
| chocolatey-install.ps1                                | Installs Chocolatey Package Manager               |
| choco-install-packages.ps1                            | Installs sysinternals, vscode, and microsoft-edge |
| all-join-carbon-domain.ps1                            | Join the Carbon domain                            |
| all-carbon-enable-remote-desktop-for-domain-users.ps1 | Enable remote desktop access for Domain Users     |
|                                                       |                                                   |

## Desktop - Khabibulin

| Script                                                | Summary                                            |
| ----------------------------------------------------- | :------------------------------------------------- |
| chocolatey-install.ps1                                | Installs Chocolatey Package Manager                |
| choco-install-packages.ps1                            | Installs sysinternals, vscode, and microsoft-edge  |
| all-join-carbon-domain.ps1                            | Join the Carbon domain                             |
| all-carbon-enable-remote-desktop-for-domain-users.ps1 | Enable remote desktop access for Domain Users      |
| khabibulin-set-local-admin.ps1                        | Set Adalwolfa as Local Administrator on khabibulin |

## Exchange - Brieftragerin

| Script                                                | Summary                                           |
| ----------------------------------------------------- | :------------------------------------------------ |
| chocolatey-install.ps1                                | Installs Chocolatey Package Manager               |
| choco-install-packages.ps1                            | Installs sysinternals, vscode, and microsoft-edge |
| all-join-carbon-domain.ps1                            | Join the Carbon domain                            |
| all-carbon-enable-remote-desktop-for-domain-users.ps1 | Enable remote desktop access for Domain Users     |
| brieftragerin-install-exchange.ps1                    | Install Exchange                                  |
| brieftragerin-create-carbon-exchange-admin.ps1        | Create Exchange administrator                     |

## Web Server - Kagarov

| Script                 | Summary                                              |
| ---------------------- | :--------------------------------------------------- |
| kagarov-setup.sh       | Installs dependencies for Kagarov and configures DNS |
| kagarov-join-domain.sh | Joins Kagarov host to domain                         |

## Script order and dependencies

1. Run chocolatey-install.ps1 on all victim machines.
2. Run choco-install-packages.ps1 on all victim machines.
3. Run bannik-create-carbon-domain.ps1 script on bannik.
4. Run bannik-create-carbon-users.ps1 script on bannik.
5. Run all-join-carbon-domain.ps1 script on all respective Windows endpoints that should be joined to the domain.
6. Run all-carbon-enable-remote-desktop-for-domain-users.ps1 on all Desktop endpoints to enable remote desktop access for Domain Users.
7. Run kagarov-setup.sh and kagarov-join-domain.sh on kagarov, as user with effective root permissions.
8. Run the brieftragerin-install-exchange.ps1 on brieftragrein, make sure that the server was properly joined to the domain in the previous step.
9. Run brieftragerin-create-carbon-exchange-admin.ps1 on brieftragrein
10. Run khabibulin-set-local-admin.ps1 on khabibulin
11. Run bannik-add-computer-descriptions.ps1 on bannik
12. Run bannik-set-adalwolfa-group-membership.ps1 on bannik
13. Run bannik-set-dns-resolution.ps1 on bannik
14. Disable Defender on all Windows machines (requires manual setup)

    1. Open MS Defender Settings -> Virus Protection and manually uncheck everything and save.
