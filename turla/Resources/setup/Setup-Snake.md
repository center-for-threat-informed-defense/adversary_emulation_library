# Snake Victim LAN Setup

- [Snake Victim LAN Setup](#snake-victim-lan-setup)
  - [Domain Controller - Berlios](#domain-controller---berlios)
  - [Desktop - Uosis](#desktop---uosis)
  - [Desktop - Azuolas](#desktop---azuolas)
  - [Exchange - Drebule](#exchange---drebule)
  - [File Server - Berzas](#file-server---berzas)
  - [Script order and dependencies](#script-order-and-dependencies)

## Domain Controller - Berlios

| Script                                | Summary                                                      |
| ------------------------------------- | :----------------------------------------------------------- |
| chocolatey-install.ps1                | Installs Chocolatey Package Manager                          |
| choco-install-packages.ps1            | Installs sysinternals, vscode, and microsoft-edge            |
| berlios-create-snake-domain.ps1       | Creates the Snake scenario Active Directory domain (“nk.local”) |
| berlios-create-snake-users.ps1        | Creates domain users and domain groups for Snake scenario    |
| berlios-set-dns-resolution.ps1        | Set primary and secondary DNS on endpoints to the DC         |
| berlios-create-fileserver-admin.ps1   | Creates necessary File Server Admin group                    |
| berlios-set-computer-descriptions.ps1 | Sets the names and descriptions of endpoints joined to Snake scenario domain |

## Desktop - Uosis

| Script                                               | Summary                                           |
| ---------------------------------------------------- | ------------------------------------------------- |
| chocolatey-install.ps1                               | Installs Chocolatey Package Manager               |
| choco-install-packages.ps1                           | Installs sysinternals, vscode, and microsoft-edge |
| all-join-snake-domain.ps1                            | Join the Snake domain                             |
| all-snake-enable-remote-desktop-for-domain-users.ps1 | Enable remote desktop access for Domain Users     |
|                                                      |                                                   |

## Desktop - Azuolas

| Script                                               | Summary                                                     |
| ---------------------------------------------------- | ----------------------------------------------------------- |
| chocolatey-install.ps1                               | Installs Chocolatey Package Manager                         |
| choco-install-packages.ps1                           | Installs sysinternals, vscode, and microsoft-edge           |
| all-join-snake-domain.ps1                            | Join the Snake domain                                       |
| all-snake-enable-remote-desktop-for-domain-users.ps1 | Enable remote desktop access for Domain Users               |
| azuolas-enable-fileserver-admin.ps1                  | Enable File Server Admin permissions as Local Administrator |

## Exchange - Drebule

| Script                                                     | Summary                                                 |     |
| ---------------------------------------------------------- | ------------------------------------------------------- | --- |
| chocolatey-install.ps1                                     | Installs Chocolatey Package Manager                     |     |
| choco-install-packages.ps1                                 | Installs sysinternals, vscode, and microsoft-edge       |     |
| all-join-snake-domain.ps1                                  | Join the Snake domain                                   |     |
| drebule-install-exchange.ps1                               | Install Exchange                                        |     |
| drebule-create-snake-exchange-admin.ps1                    | Create Exchange administrator                           |     |
| drebule-enable-remote-desktop-for-exchange-admin.ps1 | Enable remote desktop access for Exchange administrator |     |
| drebule-disable-wmic-integrity-check.ps1                   | Disable WMIC integrity check                            |     |

## File Server - Berzas

| Script                                               | Summary                                            |
| ---------------------------------------------------- | -------------------------------------------------- |
| chocolatey-install.ps1                               | Installs Chocolatey Package Manager                |
| choco-install-packages.ps1                           | Installs sysinternals, vscode, and microsoft-edge  |
| all-join-snake-domain.ps1                            | Join the Snake domain                              |
| berzas-enable-remotedesktop-for-snake-fileserver.ps1 | Enable remote desktop access for File Server admin |
| berzas-install-admodule.ps1                          | Install AD Powershell module                       |
| berzas-set-local-admin.ps1                           | Configure File Server Admin as local administrator |
|                                                      |                                                    |

## Script order and dependencies

1. Run chocolatey-install.ps1 on all victim machines.
2. Run choco-install-packages.ps1 on all victim machines.
3. Run berlios-create-snake-domain.ps1 scripts on berlios.
4. Run berlios-create-snake-users.ps1 scripts on berlios.
5. Run berzas-install-admodule.ps1 script on berzas.
6. Run all-join-snake-domain.ps1 scripts on all respective Windows endpoints that should be joined to the domain.
7. Run drebule-install-exchange.ps1 on drebule, make sure that the server was properly joined to the domain in previous step.
8. Run berlios-set-dns-resolution.ps1 on all endpoints.
9. Run berlios-set-computer-descriptions.ps1 on berlios.
10. Run berlios-create-fileserver-admin.ps1 on berlios.
11. Run drebule-create-snake-exchange-admin.ps1 on drebule.
12. Run drebule-enable-remote-desktop-for-exchange-admin.ps1 on drebule.
13. Run azuolas-enable-fileserver-admin.ps1 on azuolas.
14. Run berzas-enable-remotedesktop-for-snake-fileserver.ps1 on berzas.
15. Run berzas-set-local-admin.ps1 on berzas.
16. Disable Defender on all Windows machines (requires manual setup).
    1. Open MS Defender Settings -> Virus Protection and manually uncheck everything and save.
