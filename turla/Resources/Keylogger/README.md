# Keylogger

## Overview
The Keylogger is written in C++ and compiles into a single executable file that can be used to capture keystrokes on the target system.
The Keylogger is meant to be run as SYSTEM from the Carbon DLL implant as part of the Turla emulation plan.

This keylogger will perform the following:
- register a control handler to catch certain events like ctrl+c for termination in order to log them correctly
- set a low-level keyboard hook procedure that will log keystrokes
- keystrokes and other session information are logged to `%temp%\~DFA512.tmp` (when running as SYSTEM, this will typically resolve to `C:\Windows\Temp`)
- start a background thread that keeps track of the current active window. If the current active window changes, the window title and associated process path are logged
- if started with the `-r` option, the keylogger will restart itself in the current active session in order to log keystrokes correctly.
    - This is needed when running from Carbon DLL because Carbon is kicked off as a SYSTEM service, meaning the keylogger process will not initially
    be in the same session as the active logged on user. As a result, it won't be able to track foreground windows and keystrokes properly.
    - At a technical level, the keylogger will do the following:
        - Query sessions until an active one is found, and grab the session ID
        - Access its own process token and duplicate it to create a new primary token
        - Adjust the duplicated token session ID to match the active session ID
        - Create a new keylogger process using the new token, and then terminate the current process

The keystrokes are logged in the following format: `Key Pressed: KEY_NAME` for key presses, and `Key Released: KEY_NAME` for key releases. 
Note that while all key presses are tracked, key releases are only tracked for the following keys to reduce logging verbosity:
- Shift
- Alt
- Windows key
- Ctrl

Also note that key combinations (e.g. shift+A, ctrl+c) are not converted into the end result (e.g. special characters or capital letters). It is up
to the user to determine what the end result is based on which keys were pressed or released.

## Usage
To run the keylogger within an active session, you can execute it as a normal file within a command prompt, and it will kick off the keyboard hook resulting keystrokes. Session info and logging will be found in `%temp%\~DFA512.tmp`. To terminate the keylogger, you can exit out of the command prompt window or terminate the process via ctrl+c.

To run the keylogger as part of a service or outside of the active session, use the `-r` switch to have it automatically restart in an active session:
```
keylogger.exe -r
```
To terminate, you will need to terminate any `keylogger` processes either via Task Manager or command prompt / PowerShell.

## Example Keylogger Output:
```
[C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe: Windows PowerShell]
Key Pressed: G
Key Pressed: E
Key Pressed: T
Key Pressed: -
Key Pressed: P
Key Pressed: R
Key Pressed: O
Key Pressed: C
Key Pressed: E
Key Pressed: S
Key Pressed: S
Key Pressed: [SPACE]
Key Pressed: D
Key Pressed: L
Key Pressed: L
Key Pressed: R
Key Pressed: [TAB]
Key Pressed: [SPACE]
Key Pressed: [SHIFT (LEFT)]
Key Pressed: \
Key Pressed: [SPACE]
Key Released: [SHIFT (LEFT)]
Key Pressed: G
Key Pressed: [BACKSPACE]
Key Pressed: S
Key Pressed: T
Key Pressed: O
Key Pressed: P
Key Pressed: -
Key Pressed: P
Key Pressed: R
Key Pressed: O
Key Pressed: C
Key Pressed: E
Key Pressed: S
Key Pressed: S
Key Pressed: [ENTER]
```

## CTI Notes
- Keystrokes are logged to `%temp%\~DFA512.tmp` (name changed from `%TEMP%\~DFD3O8.tmp` in CTI)
- Keystrokes are using a hook on `WH_KEYBOARD_LL`
- `WM_KEYDOWN`, `WM_KEYUP`, and `WM_SYSKEYDOWN` are the intercepted procedures
- When the EXE loads it creats a session header that includes the hostname
- Current foreground window is checked every 100ms. Window changes are logged as `[%Window Process File Path%: %Window Title%]`

### CTI References:
1. https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
2. https://securelist.com/the-epic-turla-operation/65545/

## Compiling the Binaries

### MINGW64
Using `mingw64` on Windows or Kali Linux (adjust backslashes if on Linux):
```
x86_64-w64-mingw32-g++ -static -std=c++20 -Wall -Wextra -Werror -o Keylogger\bin\keylogger.exe Keylogger\Keylogger\keylogger.cpp -lwtsapi32;
strip -s Keylogger\bin\keylogger.exe;
objdump --syms Keylogger\bin\keylogger.exe;
```

To set up `mingw64` on Windows, `msys2` was installed and used:
    - `choco install msys2`
    - Add `C:\tools\msys64` to your PATH enviromment variable to run `msys2`. Reopen console windows to register the new env variable.
    - Run `msys2` and within the new prompt, run the following:
        - `pacman -Syu`
        - `pacman -S --needed base-devel mingw-w64-x86_64-toolchain`

### Visual Studio 2019
On a machine with Visual Studio 2019 installed, run the following to clean and build x64 release versions of the keylogger EXE:

```
devenv.exe .\Keylogger.sln /clean
devenv.exe .\Keylogger.sln /build Release
```
