## Overview

The Trickbot client is broken up into the following components - TrickBotClientExe, ReflectiveDLLInjection, ModuleDiscoverPSE, and Module64. These four components are responsible for C2 communications, reflective DLL injection, and information gathering/persistence mechanisms via DLL's.

### TrickbotClientExe

The main executable that is responsible for C2 registration and communication. This executable is designed to be kicked off by Emotet[1]. When building this code, the executable will be output as TrickbotClientExe.exe in the folder TrickBotClientExe\x64\Release. The code is currently printing command output, this should be removed for production. The Trickbot C2 commands are broken up into the following structure:

To run TrickbotClientExe via command line for testing
```
C:\Users\vfleming\AppData\Roaming\WNetval> TrickbotClientExe.exe
```

#### [Registration Command](https://github.com/attackevals/wizard_spider/blob/af8deb87e3d94b1ac6c26e990c80d4dde0da95eb/Resources/TrickBot/TrickBotClientExe/TrickBotClientExe/TbComms.cpp#L243)

The function getBotKey() generates a Trickbot encryption key that is used to encrypt DLL's and config files that are sent down to a victim machine. Encryption is not currently implemeneted.

#### [Get Tasks](https://github.com/attackevals/wizard_spider/blob/bd7d5e387c99dbb43545c290964f978459a1055c/Resources/TrickBot/TrickBotClientExe/TrickBotClientExe/TbComms.cpp#L250)

This request is sent to the server every N number of seconds to check if the C2 server has a job for the client to perform. This request is called within the main function of TrickBotClientExe and continiously loops until the Trickbot Handler kills the clent connection.

#### [Post Command Output](https://github.com/attackevals/wizard_spider/blob/bd7d5e387c99dbb43545c290964f978459a1055c/Resources/TrickBot/TrickBotClientExe/TrickBotClientExe/TbComms.cpp#L254)

This request will send command line output to the Trickbot handler. The request itself is sent using WinHTTP.

#### [Download File](https://github.com/attackevals/wizard_spider/blob/bd7d5e387c99dbb43545c290964f978459a1055c/Resources/TrickBot/TrickBotClientExe/TrickBotClientExe/TbComms.cpp#L258)

This request will download a file that the server tells the client to download. The requests is sent using WinHTTP.

#### [Upload File](https://github.com/attackevals/wizard_spider/blob/bd7d5e387c99dbb43545c290964f978459a1055c/Resources/TrickBot/TrickBotClientExe/TrickBotClientExe/TbComms.cpp#L262)

This request will upload a file from the client to the c2 server. The reuest is sent using WinHTTTP. Because this function wont be used a ton by the Trickbot C2, the current implementation reads the file to upload into a String and then sends the string in a post request. This implmentation should not be used to upload binary files are large files. Small text files with "discovery" information should work fine.

#### [Command ID's](https://github.com/attackevals/wizard_spider/blob/bd7d5e387c99dbb43545c290964f978459a1055c/Resources/TrickBot/TrickBotClientExe/TrickBotClientExe/Commands.h)

Command ID's are stored in an ENUM and used to define which commands are being sent to the TrickBotHandler. Routes are setup within the Trickbot handler to check the Command ID and then route the request to the correct endpoint.

### ReflectiveDLLInjection

An executable responsible for reflectively injecting DLL's into processes. This file is compiled into an executable instead of a DLL. This is a slight derivation from the CTI [1]. When building this code, the executable will be output as inject.64.exe in the folder ReflectiveDLLInjection\x64\Release. The functionality of this code mimics that of Loader.dll described in the CTI. This program can be executed by TrickbotClientExe - see Emulation plan for more information. inject.64.exe only injects into svchost.exe.

To inject into svchost run the following command
```
inject.64.exe {path_to_dll}.dll
```

If you need to change the process to inject to you can edit this line in [Inject.c](https://github.com/attackevals/wizard_spider/blob/af8deb87e3d94b1ac6c26e990c80d4dde0da95eb/Resources/TrickBot/ReflectiveDLLInjection/inject/src/Inject.c#L71). Please note that you must be running as an Administrator or a high integritry process to be able to inject into svchost.exe. 

Testing:

If you are testing a new Reflective DLL and are using MessageBox's to debug your code, you should change the process to inject into to be a user level process like "notepad.exe". This will allow you to see the MessageBox output. If you try this with svchost.exe it your DLL will hang and you will see no output from your DLL.

### ModuleDiscoverPSE

Update: I had issues getting command output to be written to a file using this DLL. Please follow steps in the emulation plan to manually run these commands with the Trickbot client.

A DLL that can be reflectively loaded by inject.x64.exe. This module is equivalent to DLL.dll referenced in the CTI [1]. This DLL runs multiple system commands including nltest, ipconfig, and net commands. The command output is written to a file on disk called out.txt. Discovery.txt must be back hauled by the C2 manually - see Emulation plan for more information. When building this code, the DLL will be output as ModuleDiscoveryPSE.x64.dll in the folder ModuleDiscoveryPSE\x64\Release. 

### Module64

A DLL that can be reflectively loaded by inject.x64.exe. This module is equivalent to MODULE64.DLL referenced in the CTI [1]. This DLL will transform a file named radiance.png into a file called tsickbot.exe and copy it to other locations on the filesystem and network fileshares. When building this code, the DLL will be output as Module64.x64.dll in the folder Module64\x64\Release

To build radiance.png - I used a PNG file called [diamond.png](https://github.com/attackevals/wizard_spider/blob/af8deb87e3d94b1ac6c26e990c80d4dde0da95eb/Resources/TrickBot/WNetval/diamond.png), 

Run the command below to append the contents of the main trickbot executable to a png called radiance.png
```
cat TrickbotClientExe.exe >> diamond.png && mv diamond.png radiance.png"
```

Please note that diamond.png must be used to create radiance.png. The filesize of diamong.png is hard coded in Module64 and used as a filepointer location to carve the trickbot executable out of the PNG. This module is hardcoded to look for radiance.png in C:\Users\{username}\AppData\Roaming\WNetval\radiance.png

To run this DLL:
```
inject.64.exe {path_to_dll}.dll
```

## Note on Reflective DLL's

If new DLL's need to be created for any reason please ensure that the configurations exactly match the other reflective DLL's within this repo - the following files are required - ReflectiveDLLInjection.h, ReflectiveDLLInjection.c, and ReflectiveLoader.h. I had issues using C++ when writing these DLL's - Windows API's and C worked without issue.

## Folder Structuring

The Trickbot folder that is copied onto a victim system should look like the following

```
|
|-TrickBotClientExe.exe
|
|-Data/
|
|---- ReflectiveDLLInjection/
|	  |
|	  |- inject.x64.exe
|
|---- ModuleDiscoverPSE/
|	  |
|	  |- ModuleDiscoveryPSE.x64.dll
|
|---- Module64/
|	  |
|	  |- Module64.x64.dll
```

This folder or its individual contents should be copied to "C:\Users\{username}\AppData\Roaming\WNetval"

## Issues

Any forseeable issues were created as Issues. Please reference the Issue titles that start with "Trickbot"

## References
[1] https://www.cybereason.com/blog/triple-threat-emotet-deploys-trickbot-to-steal-data-spread-ryuk-ransomware
