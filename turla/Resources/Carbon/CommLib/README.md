# CommLibDLL

## Overview


This library will be injected into a Windows process and used to communication with the C2 server. Communication may be direct, or be routed through a different instance of this library on a seperate computer. The messages received from the C2 server are primarily tasks from the C2 server, which are stored in a file for the Carbon Orchestrator to run. This library also checks for task results from the Orchestrator and sends those results to the C2 server.


## C2 Communications
The communication library DLL supports two modes of communication with the C2:
- direct C2 channel using HTTP
- peer-to-peer C2 communication using named pipes

### HTTP Communications
The library module will determine the C2 server address, port, and URL path from the options provided in the config file.
A heartbeat request is sent to the C2 addr/url to check that the server is alive. If alive, the module will then use the `PHPSESSID` cookie in future requests with the appropriate implant ID value to tell the C2 server who the beacon is for.

HTTP `GET` requests are sent to request tasking, and `POST` requests are used to send task output.

For tasking, the server will send an HTML response with the base64-encoded encrypted task information placed as the `value` HTML tag value. The task information will contain payload and command information, which the module will use to do the following:
- write the payload to disk at the specific location (if a payload is provided)
- build a task config file containing the payload location (if a payload is provided) and the command to run. The task config file will be placed in the `C:\Program Files\Windows NT\Nlts\a67s3ofc[task id].txt` filepath. For instance, if the task id is `15`, the config file will be placed in `C:\Program Files\Windows NT\Nlts\a67s3ofc15.txt`
- append the following line to the task list file at `C:\Program Files\Windows NT\0511\workdict.xml`:
    - `task_id | payload_path (optional) | task_config_path | task_output_path | task_log_path`
    - example: `12 | C:\\users\\public\\testpayload | C:\Program Files\Windows NT\Nlts\a67s3ofc15.txt | C:\Program Files\Windows NT\2028\15.yml | C:\Program Files\Windows NT\2028\15.log`
    
For task output, the comms lib module will look for available task output info in the task output metadata file (configurable during compilation, currently set to `C:\Program Files\Windows NT\2028\traverse.gif`). This file contains lines of the following format:
```
task_id | num_files (currently only 1 is supported) | path_to_output_file | implant_id
```

Example:
```
15 | 1 | C:\Program Files\Windows NT\2028\15.log | SOMEUUID
```
The implant will upload the contents of the task output file and clear the task output metadata file.

### Named Pipe Peer-to-Peer
To configure named pipe peer-to-peer options, you can adjust the options under the `[TRANSPORT]` section of the main configuration file:
```
[TRANSPORT]
system_pipe = dsnap
spstatus = yes
adaptable = no
p2p_client = false
peer_pipe = \\peerhost\pipe\dsnap
```

- Currently, `spstatus` and `adaptable` are not used and can be ignored.
- `system_pipe` refers to the name of the pipe used on all machines for peer-to-peer comms
- `p2p_client` toggles whether or not the implant will use named-pipe p2p or HTTP comms to reach the C2 server. To enable, set the value to `true` or `yes`.
- `peer_pipe` indicates the full pipe address (including hostname and pipename) of the peer to connect to for named pipe p2p communication. Note that this pipe address must align with whatever the `system_pipe` value is for the configuration file of the **peer**

If the module is running in HTTP comms mode, it will mark itself as available for p2p requests by listening on the pipe specified in `system_pipe`. Peers can then connect to this pipe if the address is provided in `peer_pipe` in their config file. P2p clients will send beacon requests and task output to p2p listeners, who will then relay this information to the C2 server on behalf of the client, returning any server responses such as tasking and payloads. P2p clients will also listen on their own local named pipe (indicated by `system_pipe` for responses from ther peers.

Note that because no usernames/passwords are explicitly used, any pipe connection will be done under the user context of the process running the comms library DLL module. Thus, operators must make sure that the p2p participants can access each other's named pipes.

## Encryption
The comms library module uses CAST-128 encryption with some of its files and C2 communication<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>:
- CAST-128 encryption is used to encrypt/decrypt certain files on disk:
    - main implant configuration file `C:\Program Files\Windows NT\setuplst.xml`
    - the pending task file for the orchestrator to pick up (`C:\Program Files\Windows NT\0511\workdict.xml`)
    - associated task configuration files (`C:\Program Files\Windows NT\Nlts\a67s3ofc[task id].txt`)
    - task output files (`C:\Program Files\Windows NT\2028\[task id].log`)
    - metadata file containing info on task output to submit to the C2 server (`C:\Program Files\Windows NT\2028\traverse.gif`)
- Named pipe peer-to-peer communication between hosts is encrypted using CAST-128<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>
- The embedded base64 blob in HTML responses from the C2 server contains a 2-part concatenated ciphertext blob. The first 256 bytes contain an RSA ciphertext, which when decrypted provides a base64-encoded random CAST-128 symmetric key. This key is then used to decrypt the rest of the ciphertext blob, which contains the actual task information. The RSA private key used for the first round of decryption is included in the configuration file and is set to (DER-encoded base64):
```
MIIEoQIBAAKCAQEAxcvv98NsuX1Fuff9LDyV5fpp/MAbPvIYiMyoups9uhJz7v0E4MRCZQoM6w49rjmMTgsps3TJe8IR/6waEOTzevVBmma2LFd6Q+wlOnfdHFLa2YjCUyY1fvBP+7poc9U/hjf4mLs9hGih8wBUEPZtNYerA/aZM2bwpH7JjTXdQmCZ0Y7WalNn3me+Y9mEXQS16+uxXX3uEjB0zg9J+18H5dDRe40O91pLToAGKw/+s3bs9wuvLw0sArUQusC0T/msUOAawPgUDDv008w1PJblHRnDq6u1R1WD73VjDo1cGd/OfZH166JkVLiOXsrcgYL820cr1BuQuBoMthER5QUs7wIBEQKCAQAdFnYc6Ah1oXsx78NZVDQpWYgOlLi2buV9h4I5j0zXmU1IytsR/r54RT4ikScwNaOxH8JeJ8NG59V4bCHzbPahJBEtS1cGhVW+sck9TdzAZomYdf51o7ySqt6V9cQRCMWTvO/aOacqD2McNMERjaal/Vzp/p4PFqrrA5YcS6+Y0bZRa2DUwrhC4w6O6F+2TTuCeJy8QvYZ4FUc+mOh28c8pAHpvOnPUCI9LD27ksjwvkwzQCQH+8+lIebQuRqmQR/bsphPHJhmAxNiXP2BdfL/WkdkxM9VIKQQyZpjYHa48nlCTop/uu9vyydVr1gkp9OOmPth9nbjk8AAliElbD51AoGBAOJOrCsLobcz2YakqoxLeBbuTjWNnSsC/U5GdG7UMOjW3ZtBFX0TrQMpGmW3r9UH94tWHVrl7iCWsn2BspARw1xAoTYzIvCiYoR51qiFGRrlncmr6WQE+esbgRVJHS+BuDNhr7OxXlE5726OZHvOBlMxK5sFLJ47yh7L0oWdti1zAoGBAN+/ohjrHzIW7KGNAtOgTD2GaVIC5jmScOPCjc9A8Tqlyyk4P8Jh8sW4ny/eRtNGcVt3oJJ5O4dvgnGtvQige3dtgHJz332A97lWsGp6W7w74uFSiAKZFz0umWchrQVIHS9Y/2E8GbbvY63wJG+6OqStPn0BljBwyaEZdN4VoiOVAoGAXS90Ebl+0vc7c603KrWp61MRJRwxqEyGa4ZsLaKqujpbP+2fb7zOxRDswHjP7k6TG0GTneY04D4NQrzvLEOMrYQGJWBZrmD7Y7myvdxzv8f1rWTnoaeyM6Hp25aTjAg8ydzt/rJyIXI1acIpYCeoQF+KbQIhblTawWL8VSLSiy8CgYEAqxoSi4afYooAP0223hErPht9ty9kwp0pJqPV2rkw8JzmpwzldocjD6tMjgRURzXeNuMCUeQ8lL6vC6L594nH08w1DDp9ulOQQm932PQoCGoH2XtY8u2KPdhXML9mMTclYHE7wtObMYni0E45+xXwnAwCm9QJcFY/1Yvv9R+aGzUCgYBSb0kAPXlL7ZkwuTxfbvc10/93Ks8LDd5WaAb+gnTDFhqFGjNYNRsSF3S09oqfoITt0t4ufZfu4uqtDMFfCCmLA6K2J3asFSFV9A57f4NNtNivgMeoJFsWmLiW0obQRCbpQ1DY3AcgYPuiI8sTS0bobizCA3MenIWpyMlXT71VvQ==
```
Carbon DLL has used a similar encryption setup for C2 responses in the past<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>, with additional components such as an intermediary signature block.

Carbon DLL has used hardcoded encryption keys in the past. For the comms library module, the CAST-128 symmetric key for file encryption is hardcoded as the following (hex-encoded):
`f2d4560891bd948692c28d2a9391e7d9`

Note that in all cases, CAST-128 encryption was done in CBC mode, and RSA encryption was done with OAEP padding and SHA1 hash.

The 2048-bit RSA public/private key pair used for this implant was generated using Crypto++'s `GenerateRandomWithKeySize` method and then
encoded to DER format. To convert from DER to PEM format, you can use the following `openssl` commands:
```
openssl rsa -RSAPublicKey_in -in rsa-public.key -inform DER -outform PEM -out public.pem -pubout
openssl rsa -in rsa-private.key -inform DER -outform PEM -out private.pem

# Used in c2 handler
openssl pkey -in private.pem -traditional -out privatepkcs1.pem 
```

## Logging
To assist operators in troubleshooting, the comms lib will log errors and debugging output to the following file on the target host: `C:\Program Files\Windows NT\2028\dsntport.dat`. Each log file line is base64-encoded and CAST-128 encrypted with the following format:
```
base64(cast128encrypt(log contents))
```

The CAST-128 encryption key is the same hardcoded key used to encrypt/decrypt other files.

To decrypt the logs on a Linux machine, you can use the `decrypt_logs.py` utility:
```
python3 decrypt_logs.py -p path/to/commslib/log -o plaintext/output/log/path
```

## How to Run:
The primary DLL will be injected into browsers by the Carbon Orchestrator DLL.

## How to Perform Cleanup
There is no required cleanup for testing the library. However, for cleaning up Carbon in execution, see the cleanup file at `turla/Resources/cleanup/Carbon/carbon_cleanup.ps1`. 

## How to Build:
This program is using CMake to compile and CL compiler for Windows.

The module requires the Crypto++ library to be built and linked at compile-time. `vcpkg` was used to install crypto++ for x64-windows, and the installation directory is set as the `VCPKG_ROOT` system environment variable.

### Via Commandline
Build the comms library DLL using the following cmake commands in administrator Powershell from the `Resources\Carbon\CommLib` directory. If you want to adjust certain preprocessor directives for the Carbon home directory, config file path on disk, and finished tasks path directory, you can do so in the compilation command:
```
cmake -S . -B build -D CARBON_HOME_DIR="C:\\Program Files\\Windows NT" -D CONFIG_FILE_PATH="C:\\Program Files\\Windows NT\\setuplst.xml" -D FINISHED_TASKS_PATH="C:\\Program Files\\Windows NT\\2028\\traverse.gif"; 

cmake --build build --config Release; 

cp .\build\src\Release\commlib.dll .\bin\commlib.dll;
```

To remove symbols, you can use the `strip` command:
```
strip -s bin\commlib.dll
```

To verify symbol removal, you can run `strings` or `objdump --syms bin\commlib.dll` - you should see an empty symbols table.

Note that the above compilation command will also build the unit tests, which you can run via:
```
cd build; 
ctest --output-on-failure;
```

### On Windows in VSCode Through Visual Studio Tools:
1. Make sure you have the extentions:
    - CMake
    - CMake Tools
1. Setup VSCode to Use MSVC
    - See https://code.visualstudio.com/docs/cpp/config-msvc
    1. Install Build Tools for Visual Studio 2022
    1. From the Start Menu, open "Developer Command Prompt for VS 2022"
    1. Navigate to folder with code, then use `code .` to open VS Code.
    - Alternative option is to setup tasks.json as described on the website. Compiler path in c_cpp_properties.json will also need to change to         "compilerPath": "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.33.31629\\bin\\Hostx86\\x86\\cl.exe"
1. Make sure CMake is installed on your machine
    - `choco install cmake --installargs '"ADD_CMAKE_TO_PATH=System"'`
    - You will need to restart the shell to use cmake.
    - If cmake was already installed but not on your path, fully uninstall and install with the above arguments.
1. Install vcpkg with these commands:
    1. `cd C:\`
    1. `git clone https://github.com/Microsoft/vcpkg.git`
    1. `cd vcpkg`
    1. `./bootstrap-vcpkg.sh`
    1. `./vcpkg integrate install`
    1. Set a system level environment variable named `VCKPG_ROOT` to the root of your installation directory. For example, `VCPKG_ROOT = C:\Users\dev\vcpkg`.
    1. The projects dependencies (cryptopp) will now automatically be installed at build time.
1. Some settings are required for CMake in VSCode:
    - CMake: CMake Path 
        - Set to where ever the cmake executable is located
        - Mine is at `C:\Program Files\Cmake\bin\cmake.exe`.
    - CMake: Generator
        - Make sure this is empty
1. In Command Palette, run `CMake: Build`. Run on any compiler.

## Common Compiling Errors
For all problems: start by deleting the build folder than using the `CMake: Delete Cache and Reconfigure` command. With most changes below, this is needed to actually register the change.

- If the compiler complains that "cryptopp::cryptopp" does not exist, change
    src/CMakeLists.txt on line 37 and 39 from "cryptopp::cryptopp" to "cryptopp-static".
- If the compilation process says it cannot find cryptopp package, manually install cryptopp on the system with matching compiler triplet. 
Example: `vcpkg.exe install cryptopp:x64-windows`.
- If the compiler complains about a missing external symbol within cryptopp, named something like __std_find_trivial_1, change to a different compiler version. Windows compiler version 17.3 seems to be troublesome with cryptopp, but not always. Do the full refresh described above after the compiler change.

## How to Test

To setup testing, you must have the C2 server up and running on a seperate machine, and this code must be run from VS Code in administrator mode. The environment variable VCPKG_ROOT must already be set when opening powershell.

Tests are also run through CMake. Make sure CMake is installed with the instructions above. 

For the tests to run properly, a C2 server providing tasks needs to be at 10.0.2.11:8080 with a resource at /javascript/view.php. To change the address of the C2 server, edit values in dummyConfigFile.txt and testing.h.

#### On Windows in VSCode:
In Command Palette, run `CMake: Run Tests`.

#### In a Shell in Windows Powershell
Once the package is built, run `$ cd build` then `$ ctest`

## CTI Sources

1. https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
2. https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html

## Missing Items

- Some details differ from the CTI. This includes the checks of other websites before connection to the C2 server. Our version of the communications library also does not execute any commands, always passes them on to the orchestrator.

## External Libraries and Tools Used

- CMake is used for compilation, which is distributed under the OSI-approved BSD 3-clause License. None of the CMake code is included in the files.
- Vcpkg is used but not packaged with this code. The software is managed by Microsoft and licensed under the MIT License, authorizing free use of the software.

