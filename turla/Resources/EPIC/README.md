# EPIC

EPIC is broken up into the following components:
| Component | Description |
| --- | --- |
| Payload | Third stage worker DLL for the EPIC implant. It is compiled as a DLL, and communicates with a hardcoded C2 server and port value via HTTP POST requests. |
| Reflective Guard | Second stage guard DLL for the EPIC implant. It is compiled as a DLL, and loads the third stage payload or an arbitrary .dll substitute as an embedded resource. |
| Reflective Injector | First stage injector for the EPIC implant. It is compiled as an executable, and loads the second stage guard or an arbitrary .dll payload as an embedded resource. |
| Simple Executable Dropper | "Simple" dropper program that enables the delivery of an executable to a subtle location on the victim machine and alters the registry keys so that the executable will run on the user's logon. |

## Build Instructions

**Manually**

All instructions to build the EPIC components manually are detailed in their respective READMEs. The links to the individual build sections are below.

[Payload Build](./payload/README.md#build-instructions) \
[Guard Build](./Defense-Evasion/reflective-guard/reflective-guard/README.md#build-instructions) \
[Injector Build](./Defense-Evasion/reflective_injector/reflective_injector/README.md#build-instructions) \
[SimpleDropper Build](../SimpleDropper/SimpleDropper/README.md#build-instructions)

**Using the build script**

You can use the `buildall.ps1` script to build any or all of the EPIC components. 

From the `turla\Resources\EPIC` directory in Powershell:
```
.\buildall.ps1 -c2Address "<c2Address>" -c2Port <port #> -https "<true/false>" -build "<components>"
```

The script will use HTTP and a default C2 server (address and port) if none are specified. If no EPIC components are specified in the `build` input, all components will be built by default. To build one or more specific components, input any variation of: `"payload guard injector simpledropper"`. To build all of the components, input `"all"`.

No cleanup is required to rebuild the components using the script. If building the payload or guard DLLs, the script will create a txt file in the EPIC directory containing the converted DLL shellcode. All necessary resource preparation for the components is handled by the build script. If you would like to add an alternative resource, please follow the instructions detailed in the component's respective README linked above.

## Execution Details

[Payload Execution](./payload/README.md#execution) \
[Guard Execution](./Defense-Evasion/reflective-guard/reflective-guard/README.md#execution) \
[Injector Execution](./Defense-Evasion/reflective_injector/reflective_injector/README.md#execution) \
[SimpleDropper Execution](../SimpleDropper/SimpleDropper/README.md#execution)

### Cleanup Instructions

Cleanup instructions for the individual EPIC components are linked below.

[Payload Cleanup](./payload/README.md#cleanup-instructions) \
[Guard Cleanup](./Defense-Evasion/reflective-guard/reflective-guard/README.md#cleanup-instructions) \
[Injector Cleanup](./Defense-Evasion/reflective_injector/reflective_injector/README.md#cleanup-instructions) \
[SimpleDropper Cleanup](./SimpleDropper/SimpleDropper/README.md#cleanup-instructions)

**Using the cleanup script**

EPIC's cleanup script can be accessed [here](../cleanup/EPIC/epic_cleanup.ps1).
This script should be run from the domain controller of the range with
administrative privileges.

For Carbon scenario cleanup:
* From the Kali Linux machine (`176.59.15.33`):
  * ```
    cd /opt/day1/turla
    xfreerdp +clipboard /u:skt\\\evals_domain_admin /p:"DuapQj7k8Va8U1X27rw6" /v:10.20.10.9 /drive:X,Resources/cleanup
    ```
* Open an Admin PowerShell and execute the cleanup script:
  * **Note:** To cleanup the SYSTEM-level EPIC implant, a reboot of HOBGOBLIN
    is required.
  * ```
    cd \\tsclient\X
    .\epic-cleanup.ps1 -target hobgoblin -user gunter -restart
    ```
* Sign out of the RDP session when finished.

For Snake scenario cleanup:
* From the Kali Linux machine (`176.59.15.33`):
  * ```
    cd /opt/day2/turla
    xfreerdp +clipboard /u:nk.local\\evals_domain_admin /p:"DuapQj7k8Va8U1X27rw6" /v:10.100.30.202 /drive:X,Resources/cleanup
    ```
* Open an Admin PowerShell and execute the cleanup script:
  * **NOTE:** A restart of AZUOLAS is not required as long as Egle as been
  logged out.
  * ```
    cd \\tsclient\X
    .\epic-cleanup.ps1 -target azuolas -user egle
    ```
* Sign out of the RDP session when finished.

## Troubleshooting

### SimpleDropper
* Check via Registry Edit as the current user that the Winlogon key was
  properly created:
  * `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
* Check that the injector `mxs_installer.exe` was dropped to the user's
  `%APPDATA%` folder

### Injector
 * At the user-level, the injector is not selective of which explorer.exe
   it injects into. If there are additional users logged into the host, there
   is a chance the injector may inject into an explorer.exe that does not
   belong to the current user.
### Guard
 * At the user-level, the guard is will search for `msedge.exe` processes
   (among other browser-like processes) to inject into. If none exist, guard
   will wait until an `msedge.exe` becomes available.
 * Similar to the injector, no additional users should be logged into the host.
### Payload/Worker DLL
 * Check if `%APPDATA%\Temp\~D723574.tmp` is growing in size every 15 seconds
   * If yes:
     * C2 domain/port may be incorrect
     * C2 server may be configured improperly
     * Network flow may be configured improperly (redirectors, etc.)
   * If not or it's missing:
     * Payload/Worker DLL was most likely not injected into Edge properly

## CTI References

1. https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
2. https://securelist.com/the-epic-turla-operation/65545/
