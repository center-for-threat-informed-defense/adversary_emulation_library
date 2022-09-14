# Build the Linux Webshell

The Linux PHP webshell consists of the PHP script and the
instructions to set up its environment, so there is nothing to build
for the webshell itself.

This document is about building the wrapper that launches the webshell.

## Build Prerequisites

The prerequisites for the Linux installation has all of the prerequisites used by
[the PHP webshell](README_linux_php_webshell.md#prerequisites).

In addition, you will need these packages:
  * Support for some golang build functionality:
    * gcc
  * Building the wrapper:
    * make
  * Building the archive:
    * zip

```
sudo apt-get install gcc make zip
```

### Installing the Golang Compiler on Linux

You must also install at least golang 1.18.x for Linux amd64, as
specified in `wrapper/go.mod`. As of May 2022, the latest golang
version is 1.18.2.

Follow [Google's instructions](https://go.dev/doc/install) to do the following:
* Download the zip for Linux amd64
* Extract the zip to `/usr/local/`, which will create the `go` directory
* Add `/usr/local/go/bin` to the PATH for your current user.

If your VM cannot access this repo, you will need to
mount this `phpwebshell` directory as a shared folder in your
VM in order to build it there.

To configure shared folders for your Ubuntu VM in VMWare Player, refer to
[Enabling VMWare Shared Folders in an Ubuntu VM](docs/linux/vmware_shared_folders.md).

## Building the Executables

Builds are placed in `build/linux/`.

Each build deletes executables or other files that were
placed by a previous build of the same make target
that have the same names as its outputs.

Use `make build-all-php` to complete all of the tasks.

For an explanation of the `go build` flags in the make target,
see [Golang Build Flags](docs/go_build_flags.md).

## Copying the PHP Webshell to the Build Directory

* Default name: `simpleshell.php`
* Make command: `move-webshell-php`

```
make move-webshell-php
```

The PHP script is copied into the `build/linux` directory.
Nothing is built by this target.

## Building the Webshell Wrapper

* Default name: `wrapper`

## Customizing the Executables

You can define custom name using these `make` variables:

* simpleshell.php (webshell script): `PHP_SHELL_NAME`
* wrapper_php (webshell wrapper): `PHP_WRAPPER_NAME`

```
make PHP_SHELL_NAME=myscript.php build-webshell-php

make PHP_WRAPPER_NAME=mywrapper.exe build-wrapper-php
```

You can use any or all of these variables with `build-all-php` or `archive-php`.

## Creating a Zip Archive

This step requires you to build the executables first.

If you have, use `make archive-php`:

```
make archive-php
```

This will delete the old `linux_php_webshell.zip` and produce a new one.

This `linux_php_webshell.zip` includes:

* `README.md`
* `README_linux_php_webshell.md`
* `BUILD_linux_php_webshell.md`
* Files in `docs/`:
  * Used by `README.md`:
    * `docs/linuxRareApps.PNG`
    * `docs/splunkURI.PNG`
  * Used by `BUILD_linux_php_webshell.md`:
    * `docs/go_build_flags.md`
    * `docs/linux/vmware-shared-folders.md`
* `build/linux/simpleshell.php` (or custom name)
* `build/windows/wrapper.exe` (or custom name)
