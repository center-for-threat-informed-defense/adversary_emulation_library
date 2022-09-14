## Build Prerequisites

### Build Prerequisites - OS

This application was developed on Windows 10.

### Build Prerequisites - Software

* Microsoft .NET 6.0 (6.0.300 or later)
  * Link to installer: https://dotnet.microsoft.com/en-us/download/dotnet/6.0
  * Ensure that your PATH is set up correctly by running `dotnet --version`
    * If the execution fails, check your PATH for `C:\Program Files\dotnet`
* Nuget packages for .NET
  * The default .NET installation does not download these packages even if
    your host is connected to the internet, so manually downloading these is
    necessary.
  * ![ASP.NET Core Runtime 6.0.5](https://www.nuget.org/packages/Microsoft.AspNetCore.App.Runtime.win-x64/6.0.5)
    * Downloads as `microsoft.aspnetcore.app.runtime.win-x64.6.0.5.nupkg`
  * ![Microsoft .NET Core Runtime 6.0.5](https://www.nuget.org/packages/Microsoft.NETCore.App.Runtime.win-x64/6.0.5)
    * Downloads as `microsoft.netcore.app.runtime.win-x64.6.0.5.nupkg`
  * ![Windows Desktop Runtime 6.0.5](https://www.nuget.org/packages/Microsoft.WindowsDesktop.App.Runtime.win-x64/6.0.5)
    * Downloads as `microsoft.windowsdesktop.app.runtime.win-x64.6.0.5.nupkg`
* Gnu Make for Win32:
  * http://gnuwin32.sourceforge.net/packages/make.htm
  * Ctrl+F "Download" and click "Setup Program."
    * This currently goes to: http://gnuwin32.sourceforge.net/downlinks/make.php
    * The version should be 3.81 or higher (latest as of May 2022).
  * Run the downloaded installer, `make-3.81.exe`.
    * The default installation directory is `C:\Program Files (x86)\GnuWin32`.
  * Add `C:\Program Files (x86)\GnuWin32\bin` to the Windows PATH in your Environment Variables.

### Build Prerequisites - Setting Up the Build Directory

* Ensure that the Interop.IWshRuntimeLibrary.dll file is in the same directory as the source code

## Compile the Executable

First, build the executables with static compilation:

```
make build-all
```

The executables are placed in `build/`.


Create an archive to hold the executable:

```
make archive
```

The archive will be `generate_lnk.zip`.

