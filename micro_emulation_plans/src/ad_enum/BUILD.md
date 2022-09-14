## Build Prerequisites

## Build Prerequisites - OS

This application was developed on Windows 10.

### Build Prerequisites - Software

* Microsoft .NET 6.0 SDK x64 Binaries (6.0.300 or later):
  * `dotnet-sdk-6.0.300-win-x64.zip`
    * Direct link to installer: https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/sdk-6.0.300-windows-x64-binaries
    * Main page: https://dotnet.microsoft.com/en-us/download/dotnet/6.0
* Nuget packages for .NET
  * The default .NET installation does not download these packages even if
    your host is connected to the internet, so manually downloading these is
    necessary.
  * [ASP.NET Core Runtime 6.0.5](https://www.nuget.org/packages/Microsoft.AspNetCore.App.Runtime.win-x64/6.0.5)
    * Downloads as `microsoft.aspnetcore.app.runtime.win-x64.6.0.5.nupkg`
  * [Microsoft .NET Core Runtime 6.0.5](https://www.nuget.org/packages/Microsoft.NETCore.App.Runtime.win-x64/6.0.5)
    * Downloads as `microsoft.netcore.app.runtime.win-x64.6.0.5.nupkg`
  * [Windows Desktop Runtime 6.0.5](https://www.nuget.org/packages/Microsoft.WindowsDesktop.App.Runtime.win-x64/6.0.5)
    * Downloads as `microsoft.windowsdesktop.app.runtime.win-x64.6.0.5.nupkg`
* .NET Packages that must be installed from the console
  * These packages only seem to work if installed with `dotnet add package`. **Internet access is required.**
  * System.DirectoryServices 7.0.0-preview.6.22324.4:
    * `dotnet add package System.DirectoryServices --version 7.0.0-preview.6.22324.4`
    * Related Nuget page: [System.DirectoryServices 7.0.0-preview.6.22324.4](https://www.nuget.org/packages/System.DirectoryServices/7.0.0-preview.6.22324.4)
  * System.DirectoryServices.AccountManagement 7.0.0-preview.6.22324.4:
    * `dotnet add package System.DirectoryServices.AccountManagement --version 7.0.0-preview.6.22324.4`
    * Related Nuget page: [System.DirectoryServices.AccountManagement 7.0.0-preview.6.22324.4](https://www.nuget.org/packages/System.DirectoryServices.AccountManagement/7.0.0-preview.6.22324.4)
* Gnu Make for Win32:
  * http://gnuwin32.sourceforge.net/packages/make.htm
  * Ctrl+F "Download" and click "Setup Program."
    * This currently goes to: http://gnuwin32.sourceforge.net/downlinks/make.php
    * The version should be 3.81 or higher (latest as of May 2022).
  * Run the downloaded installer, `make-3.81.exe`.
    * The default installation directory is `C:\Program Files (x86)\GnuWin32`.
  * Add `C:\Program Files (x86)\GnuWin32\bin` to the Windows Path in your Environment Variables.

### Build Prerequisites - Setting Up a Standalone .NET Installation

These examples assume that this is the only .NET SDK available on the Path.

1. Extract `dotnet-sdk-6.0.300-win-x64.zip` to `C:\dotnet\`.
   * This should be extracted such that `C:\dotnet\dotnet.exe` is the path to `dotnet.exe`.
2. Add `C:\dotnet\` to the Path in the System Environment Variables.
3. Verify the following in a new Powershell shell:
   * `dotnet --version` should resolve to `6.0.300`
   * `dotnet --list-sdks` should include `6.0.300 [C:\dotnet\sdk]`

### Build Prerequisites - Setting Up the Build Directory

* Create a directory named `nuget-local` (or other preferred name).
* Copy the Nuget packages into `nuget-local`. (Refer to "Nuget packages for .NET" in ![Build Prerequisites - Software](BUILD.md#build-prerequisites---software).
* Copy `nuget.config.default` to `nuget.config` (still in this directory).
* Open `nuget.config` in a text editor. Change the `value` in `packageSources` to a relative path that points to the `nuget-local` directory.

  ```
    <packageSources>
        <!-- Comment: Change "value" to your package directory -->
        <add key="LocalNuget" value="..\nuget-local" />
    </packageSources>
  ```

## Compile the Executable

First, build the executables with static compilation:

```
make build-all
```

The executables are placed in `build/`.

If the `%USERPROFILE%/.nuget` cache directory does not exist yet, the `dotnet publish` command executed by the Makefile will create it there.

## The Archive

The `ad_enum.zip` archive contains the built executable:

* `ad_enum/`
  * `ad_enum.exe`
