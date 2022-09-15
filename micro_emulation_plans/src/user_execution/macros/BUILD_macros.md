# Build the Macros Executable

## Build Prerequisites - OS

This application was developed on Windows 10.

## Build Prerequisites - Endpoint Security

This application is likely to be flagged by antivirus or other endpoint security, unless those services are disabled.

## Build Prerequisites - Software

* Microsoft .NET 6.0 SDK binaries, 6.0.301 or later:
  * `dotnet-sdk-6.0.301-win-x64.zip` (as of June 21, 2022)
    * Direct link to installer: https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/sdk-6.0.301-windows-x64-binaries
    * Main page: https://dotnet.microsoft.com/en-us/download/dotnet/6.0
* Microsoft Office installed on the host
  * It is assumed that this is a prerequisite for `Microsoft.Office.*` DLLs to be installed.
  * `winword.exe` (Microsoft Word) must be available in Windows' `Path` system environment variable.
* Identify the locations of these DLLs within `C:\Windows\assembly\GAC_MSIL\`
  (actual paths may vary):
  * `System.Management.dll`
    * Example original location: `C:\Windows\assembly\GAC_MSIL\System.Management\2.0.0.0__b03f5f7f11d50a3a\`
  * `System.Windows.Forms.dll`
    * Example original location: `C:\Windows\assembly\GAC_MSIL\System.Windows.Forms\2.0.0.0__b77a5c561934e089\`

### Build Prerequisites - Software - Setting Up a Standalone .NET Installation

These examples assume that this is the only .NET SDK available on the Path.

1. Extract `dotnet-sdk-6.0.301-win-x64.zip` to `C:\dotnet\`.
2. Add `C:\dotnet\` to the Path in the System Environment Variables.
3. Verify the following in a new Powershell shell:
   * `dotnet --version` should resolve to `6.0.301`
   * `dotnet --list-sdks` should include `6.0.301 [C:\dotnet\sdk]`

### Prerequisites - Verify that winword.exe is on the Path

Open an instance of Powershell and run `winword.exe`. It should launch Microsoft Word.

```
> winword.exe
```

If it does not, you probably need to add it to the `Path` system environment variable.

This is important because `macro_doc.cs` invokes `winword.exe` without specifying an
absolute path, so it needs to be possible to find `winword.exe` in the shell context.
Adding it to the Path fixes this.

### Build Prerequisites - Software - Office Macro Settings

This walks users through [Microsoft's steps to enable Office macros](https://support.microsoft.com/en-us/office/macros-in-office-files-12b036fd-d140-4e74-b45e-16fed1a7e5c6?ui=en-us&rs=en-us&ad=us).

1. Open a Microsoft Office application, such as Microsoft Word.
2. Go to File -> Options -> Trust Center (in left sidebar) -> Trust Center Settings -> Macro Settings (in left sidebar).
  * Under "Macro Settings" -> "Macro Settings," select "Enable all macros."
  * Under "Macro Settings" -> "Developer Settings," check the box for "Trust access to the VBA Object Model."
  * Click "OK" to apply both changes and exit the Trust Center settings menu.
3. Click "OK" to exit the Options menu.

These are insecure settings. If you are doing this on a non-disposable VM
(however you define this), these settings should be reverted to your
organization's defaults after you are finished.

### Build Prerequisites - Software - Setting up the DLL Directory

If you have found the required DLLs, copy each DLL from its location in `C:\Windows\assembly\GAC_MSIL\` into the `macros/DLL/` directory,
which contains only a `.gitkeep` by default.

At the end, `macros/DLL/` should contain all of the DLLs listed earlier:
* `System.Management.dll`
* `System.Windows.Forms.dll`

The `macros/.gitignore` is intentionally configured to block all DLL files in `DLL/` from being committed.
For now, it is assumed that it is better for the user to source these from the build host.

## Compile the Executable

Build the executable:

```
cd macros
make build-all-macro
```

The executable is placed in `macros/build/`.

Though the variables `MACRO_EXE_NAME` and `MACRO_PDB_NAME` are used internally
by the Makefile, the name of the built executable is fixed based on the name of the
main CSharp file, currently `macro_doc.cs` -> `macro_doc.exe` and `macro_doc.pdb`.

If you want the executable to have a different name, you must rename it manually.

The location of the DLL directory can be customized by setting the make
variable `DLL_PATH` (default `"./DLL/"`).

```
make DLL_PATH="./MY_DLLS/" build-all-macro
```

**If you override this default, your custom directory must contain ALL of the
required DLLs for the build.**

## Build the Archive

The `build-archive-macro` target deletes an existing archive with the same
name as the new one, and creates the new archive.

This command requires:
* An executable for `zip` on your system.

```
make build-archive-macro
```

You can customize the archive's name by overriding
`MACRO_ARCHIVE` (default `macro_doc.zip`):

```
make MACRO_ARCHIVE="myarchive" build-archive-macro
```

If you changed the name of the executable after the build, you musy
override `MACRO_ARCHIVE_EXE` here. It defaults to the value
of `MACRO_EXE_NAME`. It also assumes that the executable is
in `build/` (relative path).

```
make MACRO_ARCHIVE_EXE="myapp.exe" build-archive-macro
```

If you want to change what is included in the archive, you must
edit the make target in the Makefile.

These files are included as hard-coded names:
* `README_macros.md`
* `docs/create_macro_documents.md`
* `docs/enable_macros.md`

These files will be included in the archive based on relative path and file
extension:
* Word macro documents in `payloads/` with the extension `.docm`.
  * There are none by default. They must be created by the user.
    * Guide: [Create and Edit Macro Documents](docs/create_macro_documents.md)
    * Sample macro code is included in Markdown files in `payload_code`.
* Markdown (`.md`) documents in `payload_code`.
* Images with the extension `.jpg` or `.png` in:
  * `docs/create_macro_docs/`
  * `docs/enable_macros/`
