# Loaders

## Overview

The Loaders folder contains the following resources that enable the emulation of APT-C-36 Blind Eagle. Along with instructions, their respective TTPs and CTI references:

| Payload | Description |
| ------- | ----------- |
| VBS Loader | loader written in VBS hidden in Microsoft WinRM file |
| fiber.dll | DLL written in C# that handles downloading  and executing the injector and payload |
| fsociety.dll | DLL written in C# that performs process hollowing<sup>1</sup> to inject AsyncRAT into RegSvcs.exe |
| file-ops.py | Python script to aid in performing obfuscation of URLs and payloads |

## Dependencies

This emulation has a few dependencies that, without proper configuration, will cause the emulation to fail. The following table shows components and their dependent input and output:

| Component | Input Dependency/s | Output Dependency |
| --- | --- | --- |
| VB Loader | obfuscated URL pointing to AsyncRAT Client `(asy.txt)` created with `file-ops.py` `-u` flag | double extension added `.pdf.vbs` then winRAR archived as `.pdf.uue` |
| fiber.dll | hard coded reversed URL pointing to `Rump.xls` `(Fsociety.dll)` in [fiber.cs](./fiber/fiber/fiber.cs) | `file-ops.py` obfuscation using the `-b` flag |
| Fsociety.dll |  N/A | `file-ops.py` obfuscation using the `-f` flag |
| AsyncRAT Client | N/A | `file-ops.py` obfuscation using the `-r` flag |

## References

1)  https://attack.mitre.org/techniques/T1055/012