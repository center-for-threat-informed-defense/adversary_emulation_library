.NET Core CLR (CoreCLR)
===========================

Contains the complete runtime implementation for .NET Core. It includes RyuJIT, the .NET GC, native interop and many other components.

**Modified** and has been prepared specialy for [https://github.com/3F/DllExport](https://github.com/3F/DllExport) by [GitHub/3F](https://github.com/3F) developer.

✓ License
-------

.NET Core (including the coreclr repo) is licensed under the [MIT License (MIT)](https://github.com/3F/coreclr/blob/master/LICENSE.TXT).

```
Copyright (c) .NET Foundation and Contributors
Copyright (c) 2016-2019  Denis Kuzmin < x-3F@outlook.com > GitHub/3F
```

## CoreCLR IL Assembler

ILAsm & ILDasm      | CI
--------------------| ----------------
Win.x86-x64.Release | [![Build status](https://ci.appveyor.com/api/projects/status/asb0nbj8tly2rp7p/branch/master?svg=true)](https://ci.appveyor.com/project/3Fs/coreclr-62ql7/branch/master)

[![release](https://img.shields.io/github/release/3F/coreclr.svg)](https://github.com/3F/coreclr/releases/latest)
[![License](https://img.shields.io/badge/License-MIT-74A5C2.svg)](https://github.com/3F/coreclr/blob/master/LICENSE.TXT)
[![NuGet package](https://img.shields.io/nuget/v/ILAsm.svg)](https://www.nuget.org/packages/ILAsm/)

**Download:** [/releases](https://github.com/3F/coreclr/releases) [ **[latest](https://github.com/3F/coreclr/releases/latest)** ]


IL Assembler (ILAsm) + IL Disassembler (ILDasm)

Custom version on .NET Core CLR (CoreCLR) 3.0: https://github.com/3F/coreclr

Specially for: https://github.com/3F/DllExport

! To provide compatible converter of resources to obj COFF-format when assembling with ILAsm, use /CVRES (/CVR) key.

```
~... /CVR=cvtres.exe
```

Related issue: https://github.com/3F/coreclr/issues/2

### NuGet Packages

Custom use via [GetNuTool](https://github.com/3F/GetNuTool)

[`gnt`](https://3f.github.io/GetNuTool/releases/latest/gnt/)` /p:ngpackages="ILAsm"` [[?](https://github.com/3F/GetNuTool)]

**PDB** files (240 MB+) are available through GitHub Releases:
https://github.com/3F/coreclr/releases

Additional **MSBuild Properties**:

* `$(ILAsm_RootPkg)` - path to root folder of this package after install.
* `$(ILAsm_PathToBin)` - path to `\bin` folder., eg.: *$(ILAsm_PathToBin)Win.x64\ilasm.exe*

