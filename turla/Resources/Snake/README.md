# Snake Rootkit
Snake is a rootkit used by Turla, and the version in this repository emulates several features of the original rootkit<sup>[1](https://artemonsecurity.com/snake_whitepaper.pdf)</sup>:
- hides itself by hooking into several Windows API functions
- drops the usermodule DLL to disk (`C:\Windows\msnsvcx64.dll` in our emulated variant)
- injects the usermodule DLL into a SYSTEM process (`taskhostw.exe` in our emulated variant) and into browser processes (`msedge.exe` in our emulated variant) upon detecting outbound network traffic

When the rootkit is installed, its Snake home directory is set to `C:\Windows\$NtUninstallQ608317$` (can be changed at installer compile time), which is where the Snake rootkit driver file and usermodule DLL log files reside.
  - Snake has used similar home directories in the past, such as `C:\Windows\$NtUninstallQ812589$`<sup>[1](https://artemonsecurity.com/snake_whitepaper.pdf)</sup>

## Components

### Snake Installer
The [`SnakeInstaller`](./SnakeInstaller/) folder contains the source code, README, and additional resources for the Snake installer, which does the following:
- Sets up the Snake home directory
- Optional privilege escalation exploit CVE-2021-1732
- DSE bypass by exploiting a vulnerable signed driver that is also dropped by the installer
- Dropping the Snake rootkit driver to disk and installing it

Note that the Snake installer is bundled with both drivers inside, and since the Snake rootkit driver contains the embeded usermodule DLL, any changes to the usermodule DLL or to the rootkit driver will require a new installer to be compiled. Different installers will also be needed to target different hosts, since each usermodule DLL is compiled to reach out to a specific C2 domain or IP.

For more information on the Snake Installer, please see the [installer README](./SnakeInstaller/README.md).

### Snake Rootkit Driver
The Snake rootkit driver is run by the Snake installer and performs various rootkit functionality:
- hides itself by hooking into several Windows API functions via a modified [InfinityHook library](./SnakeDriver/libinfinityhook/README.md)
- drops the usermodule DLL to `C:\Windows\msnsvcx64.dll` (stored XOR-encrypted within the driver)
- injects the usermodule DLL into `taskhostw.exe`
- injects the usermodule DLL into browser processes (e.g. `msedge.exe`) upon detecting outbound network traffic

For more information on the Snake rootkit, please see the [rootkit README](./SnakeDriver/README.md).

### Usermodule DLL
The [`UserModule`](./UserModule/) folder contains the source code, README, and additional resources for the Snake usermodule DLL, which does the following:
- When injected into a browser process, handles C2 communications over HTTP
  - Retrieves tasking and payloads to forward to the non-browser usermodule variant, uploads files and task output
- When injected into a non-browser process, executes commands
  - Supports executing commands via cmd, powershell, direct process creation, and also supports token impersonation.
  
Note that the usermodule DLL is given the C2 address and Snake home directory at compile-time, so any adjustments to such variables will require compiling a new usermodule DLL, and thus a new rootkit driver and installer.

For more information on the Snake usermodule DLL, please see the [usermodule DLL README](./UserModule/README.md).

## Usage
To install the Snake rootkit using the Snake installer, you can use the following commands for default options:

(with privilege escalation exploit):
```
C:\Path\to\installer.exe -f
```

(without privilege escalation exploit - requires admin privileges)
```
C:\Path\to\installer.exe
```

For additional installer options, please see the [installer README](./SnakeInstaller/README.md).

If you are running just the driver, you must have a machine with test signing mode ON. To do this, open an Administrative command prompt, enter `Bcdedit.exe -set TESTSIGNING ON` and reboot your machine. You should now see "Test Mode" in the bottom right hand corner of your desktop.

Run the script `.\run_driver.ps1 start` in the same directory as your driver, and it will automatically create and start the driver for you. To stop the driver, run `.\run_driver.ps1 stop`

If you are running the driver via the installer, test signing mode is not necessary.

## Troubleshooting

### Installer Troubleshooting
Please see the [Snake Installer README](./SnakeInstaller/README.md#troubleshooting) for installer-related troubleshooting steps.

### Usermodule Troubleshooting
If the Snake installer is successful but you don't receive a beacon, there are two main possible points of failure:
1. The driver was unable to inject successfully into `taskhostw.exe` or the injected DLL crashed
2. The driver was unable to inject successfully into `msedge.exe`, or the injected DLL crashed

You can generally tell which injected DLLs started up by looking for the log files in the Snake home directory (`C:\Windows\$NtUninstallQ608317$`) and checking their timestamps:
- The C2-related log (`svcmon32.sdb`) is used exclusively by the browser-injected DLL process. If the file exists, then the injected DLL was at least able to get far enough to begin logging. If the file exists but is not being updated, then either the DLL crashed or is stuck waiting for the `taskhostw`-injected DLL to connect to it via named pipes.
- The execution log (`dbsvcng64.bin`) is used exclusively by the `taskhostw`-injected DLL and has at least one line written to it when the injected DLL starts up. If the file exists, then the injected DLL was at least able to get far enough to begin logging.

There are two ways to decrypt and read the log files:
- If you have successful beacons and are troubleshooting other issues, you can task the implant to upload the logs to the C2 server, which will automatically decrypt them and write them to the `control_server/files` directory:
    - `./evalsC2client.py --set-task <guid> '{"type": 6}'`
- If you do not have a beacon, you will have to manually copy the files from the Windows target host to your linux C2 server, where you can call the 
`control_server/handlers/snake/decrypt_logs.py` utility like so:
    - `python3 decrypt_logs.py -p /path/to/log -o /path/to/output/file`

Each log file covers different aspects of the implant:
- `svcmon32.sdb` for C2-related logging (heartbeats, beacons, payload downloads, instruction parsing, data uploads)
- `svcstat64.bin` for pipe server logging (when in pipe server mode)
- `udmon32.bin` for pipe client logging (when in pipe client / execution mode)
- `dbsvcng64.bin` for logging related to command execution (process creation, exit codes, command output)

To investigate general C2 communication issues, look at the C2 logs and pipe-related logging.

To investigate execution-related issues (e.g. failed token impersonation), look at the execution log.

Note that error codes in the logs will either be a [Windows system error code](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-) or a custom error code defined in [`UserModule/include/usermodule_errors.h`](./UserModule/include/usermodule_errors.h)

## Build
For specific build/installation instructions for each component, please refer to their respective README files.

## Debugging
In order to properly test, it is recommended to setup a Virtual Machine on which install and run the driver.
That's because any bugs in this code base can cause the executing system to crash. Additionally, this system
will need to have test signing mode enabled, in order to load our unsigned driver.

To view any output from the driver will also require tooling with the ability to attach to the target system's kernel.
Recommended solutions are to use `WinDbg` from the host machine for advanced debugging needs. Or, for lighter testing
`DebugView` is capable of reporting messages printed from the driver.
- [WinDbg remote debugging setup instructions](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-network-debugging-of-a-virtual-machine-host)
- [DebugView download from SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/debugview)

## Cleanup
A cleanup script has been provided [here](../cleanup/Snake/snake_cleanup.ps1). This script should be
run from an Admin PowerShell terminal.

The script will perform the following actions:
* Cleanup any PsExec artifacts
* Delete signed driver service
* Delete unsigned driver service
* Clean up installer directory
* Delete Snake installer (if `-deleteInstaller`)
* Restart the host (if `-restart`)
* Remove dropped user module DLL
* Recheck and redelete signed driver service

The script should be run with `-restart` if the user module DLL has been injected.

## CTI and References
1. https://artemonsecurity.com/snake_whitepaper.pdf
2. https://www.circl.lu/pub/tr-25/
