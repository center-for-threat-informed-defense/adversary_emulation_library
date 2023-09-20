# Turla Setup Procedure

- [Turla Setup Procedure](#turla-setup-procedure)
  - [Emulation Team Infrastructure Configuration](#emulation-team-infrastructure-configuration)
    - [Linux Attack Platform Setup](#linux-attack-platform-setup)
      - [Move Unzipped Binaries into Payloads](#move-unzipped-binaries-into-payloads)
      - [Download Required Binary Files](#download-required-binary-files)

## Emulation Team Infrastructure Configuration

See [Getting Started](GettingStarted.md) for information on setting up the overall range.

### Linux Attack Platform Setup

See [Setup RedTeam](Setup-RedTeam.md) for information on setting up the attack platform.

#### Move Unzipped Binaries into Payloads

A zip of the scenario binaries have been included [here](../Binaries/). The
binaries.zip can be unzipped to the expected directory location using the
following command and password `malware`:

```shell
# from the turla directory

unzip Resources/Binaries/binaries.zip -d Resources/payloads
```

:exclamation: Snake has not been included in this binaries.zip. Please visit the following
resources for building Snake and its components:

1. [Snake Installer Build](../Snake/SnakeInstaller/README.md#build)
1. [Snake Build Script](../Snake/buildall.ps1)

#### Download Required Binary Files

1. Download and extract the [PSTools](https://learn.microsoft.com/en-us/sysinternals/downloads/pstools) directory
    1. Copy `PSExec.exe` to the `Resources/payloads/carbon` directory
    1. Copy `PSExec.exe` to the `Resources/payloads/snake` directory
1. Download [pscp.exe](https://the.earth.li/~sgtatham/putty/latest/w64/pscp.exe) and copy it to the `Resources/payloads/carbon` directory
1. Download [plink.exe](https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe) and copy it to the `Resources/payloads/carbon` directory
1. Download [mimikatz](https://github.com/gentilkiwi/mimikatz/)
1. Update the Mimikatz source code with the [PTH adjustments](../Mimikatz/README.md#adjustments-made-to-mimikatz-pth-function) then recompile
1. Copy `mimikatz.exe` to the `Resources/payloads/carbon` and `Resources/payloads/snake` directory

The `Resources/payloads` directory should be setup to match the following:

```text
├── Resources
│   ├── payloads
│   │   ├── carbon
│   │   │   ├── PsExec.exe
│   │   │   ├── carbon_installer_2.exe
│   │   │   ├── carbon_installer_3.exe
│   │   │   ├── mimikatz.exe
│   │   │   ├── hsperfdata.zip
│   │   │   ├── keylogger.exe
│   │   │   ├── password_spray.bat
│   │   │   ├── plink.exe
│   │   │   ├── pscp.exe
│   │   ├── epic
│   │   │   ├── dropper.exe
│   │   │   ├── snake.exe (needs compiling)
│   │   ├── snake
│   │   │   ├── PsExec.exe
│   │   │   ├── installer_v2.exe (needs compiling)
│   │   │   ├── installer_v3.exe (needs compiling)
│   │   │   ├── ln_transport_agent.dll
│   │   │   ├── mimikatz.exe
│   │   │   ├── msiex.ps1
│   │   │   ├── n_installer_aux.dll
│   │   │   ├── rules.xml
│   │   │   ├── winmail.dat
│   │   ├── wordpress
│   │   │   ├── EPICDropper_http.exe
│   │   │   ├── EPICDropper_https.exe
```

As part of infrastructure setup, `EPICDropper_http.exe` and
`EPICDropper_https.exe` should be staged on a Wordpress server and renamed to
`NTFVersion.exe` and `NFVersion_5e.exe`, respectively.
