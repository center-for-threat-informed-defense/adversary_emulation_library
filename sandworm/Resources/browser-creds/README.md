# Browser Credential Dumper

This repo contains a modified version of the [LaZagne project](https://github.com/AlessandroZ/LaZagne). LaZagne contains functionality for dumping credentials from a variety of sources on various operating systems. However, the code contained here is a shrunken down version that is limited to only dumping credentials from browsers on Windows machines.

## Usage

This directory contains `lazagne.exe`, which is a portable executable that has been tested on Windows 10 machines. To use this executable, simply drop it on the target system and execute from a command prompt.

## Build Instructions

If you would like to build the executable yourself, there are several tools that compile Python code into Windows Executables. The Evals team used `PyInstaller` to generate a portable single file executable.

Compile the code using `PyInstaller` on Windows:

1. Install PyInstaller:
   ```
   python -m install PyInstaller
   ```
   
2. Navigate to the Windows directory within this repo:
   ```
   cd Windows
   ```
   
3. Compile using the following command:
   ```
   pyinstaller --onefile --hidden-import=lazagne.softwares.browsers.chromium_based --hidden-import=lazagne.softwares.browsers.chromium_browsers --hidden-import=lazagne.softwares.browsers.mozilla --hidden-import=lazagne.softwares.browsers.firefox_browsers --hidden-import=lazagne.softwares.browsers.ie --hidden-import=lazagne.softwares.browsers.ucbrowser --hidden-import=lazagne.softwares.windows.windows --hidden-import=lazagne.softwares.windows.credman --hidden-import=lazagne.config.constant --hidden-import=lazagne.config.module_info --hidden-import=lazagne.config.soft_import_module --hidden-import=lazagne.config.crypto.pyDes --hidden-import=lazagne.config.crypto.pyaes --hidden-import=lazagne.config.dico --hidden-import=lazagne.config.winstructure lazagne.py
   ```
   
4. The executable will be found in `Windows\dist\` as `lazagne.exe`.
   
Note: PyInstaller needs to compile all dependencies into the single executable, and does so by examining imports. However, LaZagne dynamically loads many of its modules at runtime, and so PyInstaller is unaware of those dependencies. The compilation command explicitly informs PyInstaller to compile those dependencies as well with the `--hidden-import` option.

## CTI Evidence

https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/