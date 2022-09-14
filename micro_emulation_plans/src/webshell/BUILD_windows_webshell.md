# Build the Windows Webshell

### Build Prerequisites - OS

This application was developed on Windows 10.

### Build Prerequisites - Other Dependencies

* GNU Make for Win32: http://gnuwin32.sourceforge.net/packages/make.htm
* Go 1.18.x: latest stable versions available from https://go.dev/dl/
* Something that provides a `zip` executable for the `archive` make targets.

If a `zip` executable is not already installed, you may need
to assemble the zip contents manually and create the zip
using Windows Explorer's right-click context menu option for
`Send to -> Compressed (Zipped) Folder`.

#### Installing Gnu Make for Win32

On the gnuwin32 page, Ctrl+F "Download" and click "Setup Program."

* This currently goes to: http://gnuwin32.sourceforge.net/downlinks/make.php
* The version should be 3.81 or higher (latest as of May 2022).
* Run the downloaded installer:

    ```
    make-3.81.exe
    ```

* The default installation directory is `C:\Program Files (x86)\GnuWin32`.

Add `C:\Program Files (x86)\GnuWin32\bin` to the Windows PATH in your Environment Variables.

#### Installing the Golang Compiler on Windows

You must also install at least golang 1.18.x for Windows amd64, as
specified in `wrapper/go.mod` and `windowswebshell/go.mod`.
As of May 2022, the latest golang version is 1.18.2.

Follow [Google's instructions](https://go.dev/doc/install) to do the following:
* Download the MSI file for Windows amd64.
* Run the installer. It will install Go and add Go executables to the PATH.

## Building the Executables

Builds are placed in `build/windows/`.

Each build deletes executables or other files that were
placed by a previous build of the same make target
that have the same names as its outputs.

Use `make build-all-win` to complete all of the tasks.

For an explanation of the `go build` flags in the make target,
see [Golang Build Flags](docs/go_build_flags.md).

### Building the Webshell Wrapper

* Default name: `wrapper.exe`
* Make command: `build-wrapper-win`

```
make build-wrapper-win
```

### Building the Windows Webshell

* Default name: `windowswebshell.exe`
* Make command: `build-webshell-win`

```
make build-webshell-win
```

### Customizing the Executables

You can build the executables with custom names by setting these `make` variables:
* windowswebshell.exe: `WIN_SHELL_NAME`
* wrapper.exe: `WIN_WRAPPER_NAME`

```
make WIN_EXE_NAME=mywebshell.exe build-webshell-win

make WIN_WRAPPER_NAME=mywrapper.exe build-wrapper
```

You can use any or all of these variables with `build-all-win` or `archive-win`.

## Creating a Zip Archive

This step requires you to build the executables first.

If you have, use `make archive-win`:

```
make archive-win
```

This will delete the old `windows_webshell.zip` and produce a new one.

This `webshell.zip` includes:

* `README.md`
* `README_windows_webshell.md`
* `BUILD_windows_webshell.md`
* Files in `docs/`:
  * Used by `README.md`:
    * `docs/linuxRareApps.PNG`
    * `docs/splunkURI.PNG`
    * `docs/webshell.gif`
  * Used by `BUILD_windows_webshell.md`:
    * `docs/go_build_flags.md`
* `build/windows/windowswebshell.exe` (or custom name)
* `build/windows/wrapper.exe` (or custom name)
