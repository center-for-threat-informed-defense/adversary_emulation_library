# Windows Service



## Overview

A custom Windows service was created for the evaluation, `Viper VPN Service`. The Windows service was a dummy service, using `pywin32` and `pyinstaller`. The source code and build instructions for the Windows service are in the `windows-service` directory.

## Build Instructions

The build must be performed on a Windows host.

NOTE: The following steps assume you have installed [Python](https://www.python.org/) on your Windows host, and the Python executables are on your system PATH.

### Build

1. Create a Python virtual environment, we will use the name `venv` for the virtual environment, `python -m venv venv`.
2. Activate virtualenv.
   1. `venv/Scripts/activate`
3. Use `pip` to install dependencies.  
   1. `python -m pip install pywin32 pyinstaller`
4. Run pywin32 post installer script.
   1. `python venv/Scripts/pywin32_postinstall.py -install`
5. Deactivate virtualenv.
   1. `deactivate`
6. Reactivate virtualenv.
   1. `venv/Scripts/activate`
7. Run build.
   1. Change directory to `files/windows-service`.
   2. Execute build, `pyinstaller.exe --onefile --runtime-tmpdir=. --hidden-import win32timezone viperVpn.py`
8. Binary executable will be output in `files/windows-service/dist/` directory.

Use the new executable to continue with [Carbon Setup](Setup-Carbon.md#desktop---hobgoblin)

## SetACL Studio

After the `ViperVPNSvc` service was installed on the hosts, the service registry key access control was modified.

[SetACL Studio](https://helgeklein.com/setacl-studio/) was used to configure service permissions, to configure the `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ViperVPNSvc` was modified to grant full control to `"Authenticated Users"`.
