## Windows webshell make targets.
# These are intended to run on a Windows system and use
# Windows Powershell-compatible commands with the backslash
# as the path separator, except in the zip commands.

WIN_WRAPPER_NAME="wrapper.exe"
WIN_SHELL_NAME="windowswebshell.exe"

clean-webshell-win:
	if exist build\windows\shell\${WIN_SHELL_NAME} del build\windows\shell\${WIN_SHELL_NAME}

build-webshell-win: clean-webshell-win
	cd windowswebshell\windowswebshell \
		&& go build \
			-trimpath \
			-ldflags="-s -w" \
			-o ${WIN_SHELL_NAME} windowswebshell \
		&& move ${WIN_SHELL_NAME} ..\..\build\windows\shell\${WIN_SHELL_NAME}

clean-wrapper-win:
	if exist build\windows\${WIN_WRAPPER_NAME} del build\windows\${WIN_WRAPPER_NAME}

build-wrapper-win: clean-wrapper-win
	cd windowswebshell\wrapper \
		&& go build \
			-trimpath \
			-ldflags="-s -w" \
			-o ${WIN_WRAPPER_NAME} wrapper \
		&& move ${WIN_WRAPPER_NAME} ..\..\build\windows\${WIN_WRAPPER_NAME}

build-all-win: build-wrapper-win build-webshell-win

clean-archive-win:
	if exist windows_webshell.zip del windows_webshell.zip

archive-win: clean-archive-win
	zip windows_webshell.zip \
	    README.md \
		README_windows_webshell.md \
		BUILD_windows_webshell.md \
		docs/linuxRareApps.PNG \
		docs/splunkURI.PNG \
		docs/webshell.gif \
		docs/go_build_flags.md \
		build/windows/shell/${WIN_SHELL_NAME} \
		build/windows/${WIN_WRAPPER_NAME}

## PHP webshell make targets.
# These are intended to run on a Linux system
# and use Linux bash-compatible shell commands
# with the forward slash as the path separator.

PHP_WRAPPER_NAME="wrapper_php"
PHP_SHELL_NAME="simpleshell.php"

clean-webshell-php:
	rm -f build/linux/${PHP_SHELL_NAME}

move-webshell-php: clean-webshell-php
	cd phpwebshell \
		&& cp simpleshell.php ../build/linux/${PHP_SHELL_NAME}

clean-wrapper-php:
	rm -f build/${PHP_WRAPPER_NAME}

build-wrapper-php: clean-wrapper-php
	cd phpwebshell/wrapper \
		&& go build \
			-trimpath \
			-ldflags="-s -w" \
			-o ${PHP_WRAPPER_NAME} phpwrapper \
		&& mv ${PHP_WRAPPER_NAME} ../../build/linux/${PHP_WRAPPER_NAME}

build-all-php: move-webshell-php build-wrapper-php

clean-archive-php:
	rm -f linux_php_webshell.zip

archive-php: clean-archive-php
	zip linux_php_webshell.zip \
	    README.md \
		README_linux_php_webshell.md \
		BUILD_linux_php_webshell.md \
		docs/linuxRareApps.PNG \
		docs/splunkURI.PNG \
		docs/webshell.gif \
		docs/linux/vmware_shared_folders.md \
		docs/go_build_flags.md \
		build/linux/${PHP_SHELL_NAME} \
		build/linux/${PHP_WRAPPER_NAME}
