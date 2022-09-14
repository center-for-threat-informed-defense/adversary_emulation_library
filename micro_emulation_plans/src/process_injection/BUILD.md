## Build Prerequisites

### Build Prerequisites - OS

This application was developed on Windows 10.

### Build Prerequisites - Endpoint Security and Internet Disconnection

Building or running this executable is known to trigger antivirus or other endpoint security software.

It is recommended that you build and run this application only on a host that meets the following requirements:
* Not connected to the Internet.
* No third-party antivirus or endpoint security applications or services are installed.
* Windows 10's real-time protection and automatic sample submission settings are disabled.

**IMPORTANT WARNING**: If you are using a shared folder to get your code into a virtual machine, you
must copy this `process_injection` directory outside of the shared folder and work with that copy instead.

This ensures that your build artifacts are only created on the VM, and not in the shared folder where they
might be scanned on your host machine by its security software.

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

The `process_injection.zip` archive contains the built executable:

* `process_injection/`
  * `process_injection.exe`
