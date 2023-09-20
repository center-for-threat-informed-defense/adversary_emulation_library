# Snake Installer
This component combines several others into a convenient all-in-one executable to setup the Snake rootkit.

These embedded components are:
1. The privilege escalation exploit CVE-2021-1732
2. The signed, vulnerable, Gigabyte driver
3. The unsigned Snake driver (rootkit)
4. Within the Snake driver, the Snake usermodule

At a high level, the installer takes the following steps:
- Elevates privileges, if the `force` flag is specified.
- Creates a directory, specified by the `path` flag, to house files related to Snake's execution. The default path requires elevated privileges to create.
- Drops a vulnerable _signed_ driver and a malcious _unsigned_ driver to path specified in the previous bullet.
- Abuses the vulnerable driver to disable Driver Signing Enforcement.
- Installs the unsigned driver
- The unsigned driver is then responsible for two usermodule injections. One responsible for network communication (user privileges), and one responsible for execution (SYSTEM privileges)
- Once the rootkit is running, it will attempt to cleanup by: renabling DSE, and removing the vulnerable Gigabyte driver service and .sys file.

## Usage
```Powershell
Install an unsigned driver

Usage:
  installer.exe [OPTION...]

  -i, --info       Show Code Integrity configuration
  -p, --path arg   Installation directory (default:
                   C:\WINDOWS\$NtUninstallQ608317$)
  -s, --sname arg  Signed driver/service name (default: gigabit)
  -n, --name arg   Unsigned driver/service name (default: gusb)
  -f, --force      Force the driver installation as SYSTEM
  -h, --help       Print Usage
```

The drivers are bundled within the installer executable. They will be written
in the specified installation directory path. For example,
`C:\WINDOWS\$NtUninstallQ608317$\gigabit.sys`.

## Troubleshooting
The installer can occasionally fail under certain conditions. Read ahead for information required to diagnose an issue, or
skip to the subheading matching your issue for remediation steps.
- [Incomplete output via C2](#incomplete-output-via-c2)
- [Output but no callback](#output-but-no-callback)
- [No callback but log files are present](#no-callback-but-log-files-are-present)
- [The system crashes](#the-system-crashes)

The following components can be used to identify how far execution got before failure:

1. Files on disk
  - `C:\Windows\msnsvcx64.dll` is the usermodule. If present on disk, then the rootkit driver ran far enough to drop the file there.
  - `C:\Windows\$NtUninstallQ608317$` is the default snake directory and should contain several files. If the installer was run with the `-f` (force privilege escalation) flag as a non-admin user, then the presence of this directory indicates that privilege escalation was successful.
    - `gusb.sys` is the default rootkit driver file.
    - `gigabit.sys` is the default vulnerable driver file. This file _should not_ be present after the installer finishes.
    - `svcmon32.sdb` is the user-module DLL log file for C2-related logging (heartbeats, beacons, payload downloads, instruction parsing, data uploads)
    - `svcstat64.bin` is the user-module DLL log file for pipe server logging (when the user module is running in pipe server / c2-comms mode)
    - `udmon32.bin` is the user-module DLL log file for pipe client logging (when the user module is running in pipe client / execution mode)
    - `dbsvcng64.bin` is the user-module DLL log file for command execution (process creation, exit codes, command output)
2. Services
  - The `gusb` service should be running
  - The temporary `gigabit` service should no longer be present once the installer finishes
3. Injected DLL
  - The `taskhostw` process running as SYSTEM should have the usermodule dll loaded at all times after a successful installer run
  - There are several target processes (`msedge`) that will have the usermodule injected if they are detected communicating over HTTP/S

### General cleanup steps
For a thorough cleanup, we recommend referencing the [cleanup section](../README.md#cleanup) in the Snake overall README file.

However, if you want to manually run certain cleanup portions, you can reference the below instructions.

From an adminstrative prompt the following commands can be used to setup a second attempt.
```Powershell
sc.exe stop gusb
sc.exe stop gigabit
sc.exe delete gusb
sc.exe delete gigabit
rm -recurse 'C:\WINDOWS\$NtUninstallQ608317$'
```

If the usermodule DLL is resident within `taskhostw` the computer will need to be rebooted so that handle to the DLL will be released.
```Powershell
restart-computer
```

If the usermodule DLL is resident within `msedge` all Edge processes will need to be closed.
```Powershell
get-process msedge | stop-process
```

Delete the usermodule from disk and cleanup will be complete.
```Powershell
rm C:\Windows\msnsvcx64.dll
```

### Incomplete output via C2
If stdout does not log `Installation complete`, identify whether or not the usermodule DLL was written to `C:\Windows\msnsvcx64.dll`.

1. If the file was not written to disk, the installer did not run the rootkit service
  - Simply follow the [cleanup](#general-cleanup-steps) steps from an admin command prompt and try again
2. If the file was written to disk, the rootkit is running
  - Check the home directory for vulnerable `gigabit.sys` driver, if it isn't there it should be safe to proceed.
  - Ohterwise, follow the [cleanup](#general-cleanup-steps) steps from an admin prompt

### Output but no callback
If the installer completes the output should end with:
> Installation complete

When the installer runs successfully, we need to see how far the driver made it through injection of the two usermode DLLs.
Examine the installer home directory for the presence of the usermodule's encrypted log files.

1. If `svcmon32.sdb` or `svcstat64.bin` are missing, then the user-module DLL may not have successfully been injected into the target browser process (in our emulation, Microsoft Edge).
  - Simply generate some traffic from the browser to ensure injection is triggered (e.g. open a new tab and browse to a site)
  - Close all edge processes and try again (this doesn't require administrator rights)
  ```Powershell
  get-process msedge | stop-process
  ```
2. If `udmon32.bin` or `dbsvcng64.bin` are missing, then the execution instance of the usermodule DLL may not have successfully been injected into
`taskhostw`.
  - As an administrator, enumerate the DLLs loaded into the instance of `taskhostw` owned by the SYSTEM user
  ```Powershell
  (Get-Process taskhostw).modules | ? -Property ModuleName -Like *msnsvc* 
  ```
  - If it's not present, follow the [cleanup instructions](#general-cleanup-steps) and try again

### No callback but log files are present
There may be an issue with named pipe communication between usermodule instances. This requires pulling the encrypted logs off the host,
decrypting and analyzing them for issues. For specific instructions, please see the [user-module troubleshooting guide](../UserModule/README.md#troubleshooting).

### The system crashes
Retrieve the dump files for further analysis
1. `C:\Windows\MEMORY.DMP`
2. `C:\Windows\minidump\DUMP_CREATED_AT_TIME_OF_CRASH.dmp`

When possible, loading the associated PDB file while debugging is advised.

## Build
### Requirements
- `vcpkg`
- `CMake 3.23`
- `C++23` (for `std::expected`)

[`vcpkg`](https://vcpkg.io/en/getting-started.html) is used to manage third
party libraries. Once installed, make sure to set the `VCPKG_ROOT` envrionment
variable as it will be used during the build process.

### Vulnerable Driver
The Snake Installer makes use of a [vulnerable Gigabyte driver](https://www.gigabyte.com/uk/Support/Security/1801)
to disable Driver Signing Enforcement. To make use of this repository, said
driver needs to be downloaded, XOR'd with the key `0xd3`, and placed at the
path: `data/gdrv.sys.xor`. Once that dependency has been satisfied the
subsequent build commands can be followed.

### Compilation
#### Visual Studio
---
- Clone the turla repo within the IDE or open the existing local repository
- Project -> CMake Workspace Settings

Edit the CMake workspace settings to contain the following:
```json
{
  "enableCMake": true,
  "sourceDirectory": "Resources/SnakeInstaller"
}
```

The installer can now be built and debugged using Visual Studio's native CMake
integration.

#### Command Line
---
```Powershell
/path/to/vs/vcvarsall.bat amd64
git clone ssh://github:attackevals/turla.git
cd turla/Resources/SnakeInstaller
cmake --presets x64-debug
cmake --build ./build/x64-debug
```

The binary will be output into `build/x64-debug/src/installer.exe`

## Cleanup
To undo changes to the system after running the installer use the included
script `cleanup.ps1`. If the usermodule has been injected into `taskhostw`,
the system may require a reboot prior to cleanup.

## Disabling DSE
Driver Signature Enforcement (DSE) prevents unsigned drivers from interacting 
with the Windows kernel. However using a vulnerable driver, which is signed,
we can disable DSE temporarily before loading our malicious driver.

### Vulnerable Driver
We are currently using the Gigabyte `gdrv.sys` which has a known [kernel read/write vulnerability](https://seclists.org/fulldisclosure/2018/Dec/39).
This can be swapped out for any driver with the ability to write to kernel space.

### CI!g_ciOptions
Driver Signing Enforcement is managed by the `Code Integrity` kernel module of Windows.
It manages the variable, `g_ciOptions`, which contains the current driver verifications mode.
It can either be set to only allow any drivers, only signed drivers or test signed drivers.

|Mode        |Value|
|------------|-----|
|Off         |0x0|
|On          |0x6|
|Test Signing|0xe|

#### Leak
In order to overwrite `CI!g_ciOptions` from user-mode we need to first leak it's kernel address.
This is possible by retrieving the base address of `CI.dll` in kernel space, and then calculating
the offset to `g_ciOptions`.

1. Use the undocumented feature of `NtQuerySystemInformation` to leak the base address of all currently running kernel modules
2. Parse the preffered base address of `C:\Windows\System32\ci.dll` from its PE headers
3. Map `C:\Windows\System32\ci.dll` into a memory section and calculate the offset to the export `CiInitialize`
4. Do a binary scan of the assembly within `CiInitialize` searching for a call to the function `CipInitialize`
5. Binary scan again from `CipInitialize` onwards to find a reference to `g_ciOptions`

This offset may change between Windows versions, but is easy to find using a disassembler and
Microsoft's provided symbol server.

## References
1. https://github.com/hfiref0x/KDU
2. https://v1k1ngfr.github.io/loading-windows-unsigned-driver/
3. https://seclists.org/fulldisclosure/2018/Dec/39
4. https://github.com/KaLendsi/CVE-2021-1732-Exploit
5. https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2021/CVE-2021-1732.html

## CTI
1. https://www.circl.lu/pub/tr-25/#analysis-payload
2. https://www.virusbulletin.com/virusbulletin/2014/05/anatomy-turla-exploits/
3. https://artemonsecurity.com/snake_whitepaper.pdf
