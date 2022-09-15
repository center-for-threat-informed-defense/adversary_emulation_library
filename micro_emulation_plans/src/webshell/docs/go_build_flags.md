# Golang Build Flags

As of July 2022, golang builds for the webshell sub-projects
`windowswebshell` and `phpwebshell` all use three specific flags:

* `-trimpath`
* `-ldflags="-s -w"`
* `-o <output filename variable> <name of golang module>`

**Maintainers should update this document when the make targets change.**

For example, this builds the `wrapper` executable for `windowswebshell` (Windows):
```
build-wrapper-win: clean-wrapper-win
	cd windowswebshell\wrapper \
		&& go build \
			-trimpath \
			-ldflags="-s -w" \
			-o ${WIN_WRAPPER_NAME} wrapper \
		&& move ${WIN_WRAPPER_NAME} ..\..\build\windows\${WIN_WRAPPER_NAME}
```

This similar make target builds the `wrapper` for the `phpwebshell` (Linux).
It is very similar apart from the Linux-specific forward slashes.

```
build-wrapper-php: clean-wrapper-php
	cd phpwebshell/wrapper \
		&& go build \
			-trimpath \
			-ldflags="-s -w" \
			-o ${PHP_WRAPPER_NAME} phpwrapper \
		&& mv ${PHP_WRAPPER_NAME} ../../build/linux/${PHP_WRAPPER_NAME}
```

## The -trimpath flag

The `-trimpath` flag removes the paths to the source files for the module from the
build.

* https://stackoverflow.com/questions/63831540/removing-module-path-in-trace-in-go

This is a mitigation in case these paths might reveal sensitive information about
the user, the organization, or its build process. If this is a major concern,
however, it may be more effective to check out and build this project in a way 
such that that absolute path to the source code files does not leak
any such information, possibly using a virtual machine or other disposable
build environment.

For example, assume the following apply to a copy of this repo somewhere:
* These files exist in the repo checkout:
  * `src/windowswebshell/web-shell-main.go`
  * `src/windowswebshell/web-shell.go`
* The user is named John Doe ("JOHNDOE") working at CompanyName on SecretProject
* The project is checked out into `C:\Users\JOHNDOE\CompanyName\SecretProject\micro-emulation-plans`

If you dump the executable's strings after it is built (e.g, with
Sysinternals' `strings64.exe` or the Linux tool `strings`), you would find
these paths embedded as strings:

```
C:\Users\JOHNDOE\CompanyName\SecretProject\micro-emulation-plans\src\webshell\windowswebshell\web-shell-main.go
C:\Users\JOHNDOE\CompanyName\SecretProject\micro-emulation-plans\src\webshell\windowswebshell\web-shell.go
```

This could potentially reveal the following information if you distribute your executable:
* The application was built by someone with the username JOHNDOE (or variations, because
  Windows is case insensitive), who works for "Company Name" on "Secret Project."

## The -ldflags flag and its Arguments

In `-ldflags="-s -w"`, the `-s` and `-w` flags remove debug information,
resulting in smaller executables.
* `-s` removes the symbol table and debug information.
* `-w` removes the DWARF symbol table.

For more information, refer to these links:
* https://words.filippo.io/shrink-your-go-binaries-with-this-one-weird-trick/
* https://pkg.go.dev/cmd/link

## The -o Flag and its Arguments

In the example, the use of the `-o` flag with the variable `WIN_WRAPPER_NAME`
allows the output executable's name to be changed; `wrapper` is hard-coded and
refers to the module name.

This is according to the documentation:
* https://pkg.go.dev/cmd/go
