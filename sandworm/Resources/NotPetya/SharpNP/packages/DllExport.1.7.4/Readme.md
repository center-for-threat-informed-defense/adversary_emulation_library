# [.NET DllExport](https://github.com/3F/DllExport)

*.NET DllExport* with .NET Core support (aka 3F/DllExport)

```
Copyright (c) 2009-2015  Robert Giesecke
Copyright (c) 2016-2021  Denis Kuzmin <x-3F@outlook.com> github/3F
```

[![Build status](https://ci.appveyor.com/api/projects/status/hh2oxibqoi6wrdnc/branch/master?svg=true)](https://ci.appveyor.com/project/3Fs/dllexport-ix27o/branch/master)
[![Latest-Release](https://img.shields.io/github/release/3F/DllExport.svg)](https://github.com/3F/DllExport/releases/latest)
[![License](https://img.shields.io/badge/License-MIT-74A5C2.svg)](https://github.com/3F/DllExport/blob/master/LICENSE)
[![coreclr_ILAsm](https://img.shields.io/badge/coreclr.ILAsm-4.700.2-C8597A.svg)](https://www.nuget.org/packages/ILAsm/)
[![Cecil](https://img.shields.io/badge/Cecil-0.11.2-1182C3.svg)](https://github.com/jbevain/cecil)
[![MvsSln](https://img.shields.io/badge/MvsSln-v2.5.2-865FC5.svg)](https://github.com/3F/MvsSln)
[![GetNuTool](https://img.shields.io/badge/GetNuTool-v1.8-93C10B.svg)](https://github.com/3F/GetNuTool)
[![hMSBuild](https://img.shields.io/badge/hMSBuild-v2.3.0-7F7F7F.svg)](https://github.com/3F/hMSBuild)
[![Conari](https://img.shields.io/badge/Conari-v1.4.0-8AA875.svg)](https://github.com/3F/Conari)

[![Build history](https://buildstats.info/appveyor/chart/3Fs/dllexport-ix27o?buildCount=20&includeBuildsFromPullRequest=true&showStats=true)](https://ci.appveyor.com/project/3Fs/dllexport-ix27o/history)

[`DllExport`](https://3f.github.io/DllExport/releases/latest/manager/)` -action Configure` [[?](#how-to-get-dllexport)]

> [ ***[Quick start](https://github.com/3F/DllExport/wiki/Quick-start)*** ] [ [Examples: C++, C#, Java](https://github.com/3F/DllExport/wiki/Examples) ] 
> -> { **[Wiki](https://github.com/3F/DllExport/wiki)** } { [🧪 Demo src](https://github.com/3F/Examples/tree/master/DllExport/BasicExport) }

```csharp
[DllExport]
public static int entrypoint(IntPtr L)
{
    // ... it will be called from Lua script

    lua_pushcclosure(L, onProc, 0);
    lua_setglobal(L, "onKeyDown");

    return 0;
}
```

* For work with **Unmanaged** memory including native or binary data from the heap and binding between .NET and unmanaged native C/C++ etc, use [Conari](https://github.com/3F/Conari)
* For related work with Lua (5.4, 5.3, 5.2, 5.1, ...), use [LuNari](https://github.com/3F/LuNari)

```csharp
[DllExport("Init", CallingConvention.Cdecl)]
// __cdecl is the default calling convention for our library
[DllExport(CallingConvention.StdCall)]
[DllExport("MyFunc")]
[DllExport]
```

We're supporting the following PE modules: Library (**.dll**) and Executable (**.exe**) [[?](https://github.com/3F/DllExport/issues/18)]


[![](./Resources/img/DllExport.png)](https://3f.github.io/DllExport/releases/latest/manager/)
[![](https://raw.githubusercontent.com/3F/Conari/master/Conari/Resources/screencast_Complex_types.jpg)](https://www.youtube.com/watch?v=QXMj9-8XJnY)

## License

The [MIT License (MIT)](https://github.com/3F/DllExport/blob/master/LICENSE)

.NET DllExport contributors: https://github.com/3F/DllExport/graphs/contributors

## &_

### How does it work

Current features has been implemented through [ILDasm](https://github.com/3F/coreclr/tree/master/src/ildasm) & [ILAsm](https://github.com/3F/coreclr/tree/master/src/ilasm) that prepares the all required steps via `.export` directive ([it's specific directive for ILAsm compiler only](https://github.com/3F/DllExport/issues/45#issuecomment-317802099)).

**What inside ? or how does work the .export directive ?**

Read about format PE32/PE32+, start with grammar from asmparse and move to writer:

```cpp
...
//yacc
if(PASM->m_pCurMethod->m_dwExportOrdinal == 0xFFFFFFFF)
{
  PASM->m_pCurMethod->m_dwExportOrdinal = $3;
  PASM->m_pCurMethod->m_szExportAlias = $6;
  if(PASM->m_pCurMethod->m_wVTEntry == 0) PASM->m_pCurMethod->m_wVTEntry = 1;
  if(PASM->m_pCurMethod->m_wVTSlot  == 0) PASM->m_pCurMethod->m_wVTSlot = $3 + 0x8000;
}
...
EATEntry*   pEATE = new EATEntry;
pEATE->dwOrdinal = pMD->m_dwExportOrdinal;
pEATE->szAlias = pMD->m_szExportAlias ? pMD->m_szExportAlias : pMD->m_szName;
pEATE->dwStubRVA = EmitExportStub(pGlobalLabel->m_GlobalOffset+dwDelta);
m_EATList.PUSH(pEATE);
...
// logic of definition of records into EXPORT_DIRECTORY (see details from PE format)
HRESULT Assembler::CreateExportDirectory()  
{
...
    IMAGE_EXPORT_DIRECTORY  exportDirIDD;
    DWORD                   exportDirDataSize;
    BYTE                   *exportDirData;
    EATEntry               *pEATE;
    unsigned                i, L, ordBase = 0xFFFFFFFF, Ldllname;
    ...
    ~ now we're ready to miracles ~
```

Read also my brief explanations here: [AssemblyRef encoding](https://github.com/3F/DllExport/issues/125#issuecomment-561245575) / [about mscoree](https://github.com/3F/DllExport/issues/45#issuecomment-317802099) / [DllMain & the export-table](https://github.com/3F/DllExport/issues/5#issuecomment-240697109) / [DllExport.dll](https://github.com/3F/DllExport/issues/28#issuecomment-281957212) / [ordinals](https://github.com/3F/DllExport/issues/8#issuecomment-245228065) ...

### How to get DllExport

[**`tl;dr`: put this inside solution folder, then click it there.**](https://3f.github.io/DllExport/releases/latest/manager/)

Since v1.6+ have no official support of NuGet clients ([[?](https://github.com/3F/DllExport/wiki/DllExport-Manager-Q-A)]), you need just use [this](https://3f.github.io/DllExport/releases/latest/manager/) inside your solution folder. **Wiki:** [ [Quick start](https://github.com/3F/DllExport/wiki/Quick-start) ]

Get our manager (~20 Kbytes) from any **trusted** place. Official [GHR](https://github.com/3F/DllExport/releases/latest) is recommended. But you can also get it from official packages via NuGet server [![NuGet package](https://img.shields.io/nuget/v/DllExport.svg)](https://www.nuget.org/packages/DllExport/), etc. [ **[Documentation](https://github.com/3F/DllExport/wiki/DllExport-Manager)** ]

### How to Build .NET DllExport

Just use build.bat if you need final binaries (NuGet package as `DllExport.<version>.nupkg`, Manager, zip-archives, and others).

```batch
.\build Debug
```

Part of the build works through [vssbe](https://github.com/3F/vsSolutionBuildEvent) (including CI that uses [CIM](https://www.nuget.org/packages/vsSolutionBuildEvent/) version). But you don't need to do anything at all. For Visual Studio IDE you can also use [vsix version](https://visualstudiogallery.msdn.microsoft.com/0d1dbfd7-ed8a-40af-ae39-281bfeca2334/)

### Modified ILAsm + ILDasm on coreclr

We're using **our modified versions on coreclr** specially for our .NET DllExport project - https://github.com/3F/coreclr

This helps to avoid some problems ([like this](https://github.com/3F/DllExport/issues/125#issuecomment-561245575), or [this](https://github.com/3F/DllExport/issues/17)) and more...

*To build minimal version (it will not include all components as for original coreclr repo):*

Restore git submodule or use repo: https://github.com/3F/coreclr.git

```bash
git submodule update --init --recursive
```

*Make sure that you have installed [CMake](https://cmake.org/download/), then build simply:*

```bash
build-s -all -x86 -x64 Release
```

*You can also use our compiled versions:* [![NuGet package](https://img.shields.io/nuget/v/ILAsm.svg)](https://www.nuget.org/packages/ILAsm/)

### Donation

Please note again, the [UnmanagedExports](https://www.nuget.org/packages/UnmanagedExports) was created by Robert Giesecke. His page is [here](https://sites.google.com/site/robertgiesecke/Home/uploads/unmanagedexports). [[?](https://github.com/3F/DllExport/issues/3#issuecomment-232422362)]

But *.NET DllExport* [**is not related to him**](https://github.com/3F/DllExport/issues/87#issuecomment-438576100).

✔ *.NET DllExport* is developed for you by [GitHub/3F](https://github.com/3F) ([ [GitHub](https://github.com/3F) ]; [ [twitter](https://twitter.com/GitHub3F) ]). 

If something is helpful from *3F/DllExport,* donations are welcomed, and thanks !

[ [ ☕ Donate ](https://3F.github.com/Donation/) ]
