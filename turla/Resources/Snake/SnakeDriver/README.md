# Snake Driver
The Snake driver is the threat actor's rootkit. There are three projects included in this SnakeDriver Solution.

- SnakeDriver - A WDM kernel driver project for the Snake rootkit
- libinfinityhook - InfinityHook library, enables syscall hooks. More information can be found in [./libinfinityhook/README.md](./libinfinityhook/README.md) or on the InfinityHook [GitHub](https://github.com/everdox/InfinityHook)
- SnakeTester - userspace tool used to test certain syscall hooks

## Overview
Once the installer successfully implants the Snake driver, it is responsible
for evading detection and injecting the usermodule. To accomplish these goals
the driver comes equipped with several features:

1. libinifinityhook is used to filter several syscalls
2. An embedded DLL is XOR'd and dropped to disk
3. This DLL is then injected into a SYSTEM level process (`taskhostw`)
4. The Windows Filtering Platform is used to monitor processes that
communicate over HTTP/HTTPS
5. Once a target process is observed communicating, it injects the DLL
6. If the injected process exits, the driver will begin listening
for HTTP/HTTPS from target processes again and then reinject

With those tasks completed, the stage is now set for the usermodule to
manage command and control communications and execute tasks.

## Installation
### Visual Studio Configuration
Building the driver requires several SDKs from Microsoft. Follow the Microsoft setup instructions [here](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) in order to guarantee a functional kernel development environement.

1. `Windows SDK`
1. `Windows Driver Kit`

OR
1. `Enterprise Windows Driver Kit` (Self-contained build env in a mountable ISO)

### Python (optional)

If you would like to use the `..\buildall.ps1` script which includes installer and usermodule builds, XORs, and embedding, you will need to install Python 3.x. Ensure that it is on your PATH and can be called via `python` from the command line.

## Compilation

All compilation so far is done using Configuration:Release Platofrm:x64

If you are not using the VS GUI, there is a script `turla\Resources\Snake\SnakeDriver\build_and_copy_driver.ps1` that will select the proper configuration for you, and takes an optional argument to copy the newly built driver to a new directory.

SnakeDriver is version dependent, and has been tested and configured for two versions of Windows 10: 1809 and 1903. This is necessary to be comaptible with InfinityHook. It can be expanded to support more versions of Windows by extracting the appropriate syscall numbers and adding a new `#ifdef`. Syscall numbers can be found [here](https://j00ru.vexillium.org/syscalls/nt/64/) 

### Visual Studio Configurations

|Configuration|Platform|Notes|
|-|-|-|
|Release|x64|DEBUG_PRINT, WIN10_1903|
|Release_1903|x64|No debug output, pdb renamed, WIN10_1903|
|Release_1809|x64|No debug output, pdb renamed, WIN10_1809|

### Compiling the driver

Compiling via the VS GUI and `msbuild` are supported. InfinityHook compilation warnings are to be expected.

Sample msbuild command (Must be run from VS Developer Command Prompt): 

`msbuild -target:Clean,Build -property:Configuration="Release_1903",Platform="x64`

### buildall.ps1

This compilation script will compile the usermodule, XOR it, convert it into `payload.hpp` in the driver, and then compile the driver. all intermediate and final files will be stored in `.\out\`

## Running

If you are running just the driver, you must have a machine with test signing mode ON. To do this, open an Administrative command prompt, enter `Bcdedit.exe -set TESTSIGNING ON` and reboot your machine. You should now see "Test Mode" in the bottom right hand corner of your desktop.

Run the script `.\run_driver.ps1 start` in the same directory as your driver, and it will automatically create and start the driver for you. To stop the driver, run `.\run_driver.ps1 stop`

If you are running the driver via the installer, test signing mode is not necessary. Please refer to the installer documentation for more information.

## Debugging
If you build the driver with the `DEBUG_PRINT` compiler flag it will output some helpful status messages. You can view this output using `DebugView` or `WinDbg` while installing and running the driver.

## Cleanup
Use the [Snake Installer cleanup script](../../cleanup/Snake/snake_cleanup.ps1) to remove the driver and its artifacts.
This will require a reboot.

## References
- https://github.com/Rhydon1337/windows-kernel-dll-injector
- https://github.com/JaredWright/WFPStarterKit
- https://github.com/everdox/InfinityHook
- https://github.com/DarthTon/Blackbone

## CTI
- https://www.circl.lu/pub/tr-25/#analysis-payload
- https://www.mcafee.com/blogs/other-blogs/mcafee-labs/analyzing-uroburos-patchguard-bypass
