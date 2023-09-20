# Carbon-DLL Orchestrator DLL

## Orchestrator
### Overview
The Carbon DLL Orchestrator (orch) will be started from the Carbon installer service and inject the C2 communication DLL (comms lib) into a legitimate process.<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>
The orchestrator will create mutexes for the comms lib and itself to manage file access.<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>
The orchestrator will monitor a specific file to find tasks that the comms lib pulled from the C2.<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>
The orchestrator will publish its completed tasks and relevant information to another file that the comms lib monitors so that the information can be sent back to the C2.<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>

### Files
#### File Structure and Explanation
The file structure for Carbon was based on a combination of Carbon 3.7X Carbon 3.8X file structures<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>
Our file structure differs from CTI in that we do not have a separate task file for both the orchestrator and the comms lib since only the orchestrator executes tasks. We also excluded the two `.png` files in the Carbon 3.8X file tree that do not have an explanation of their purpose.

The files and folders listed here will always be created, but task output file names are defined in each line of `workdict.xml`.

`C:\Program Files\Windows NT` is set as the Carbon working directory. Per CTI, Carbon randomly selects a folder from `C:\Program Files`<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>, but we only use `Windows NT` to maintain consistent evaluations.

| File/Folder  | Description |
| ------------ | ----------- |
| .\0511      | directory for tasks and task configs |
| .\0511\workdict.xml    | orchestrator tasks |
| .\2028      | directory for log and task result files    |
| .\2028\traverse.gif    | list of files to send to c2        |
| .\2028\dsntport.dat | comms lib logging |
| .\Nlts | directory to contain task config files |
| .\MSSVCCFG.DLL      | orchestrator dll        |
| .\MSXHLP.DLL    | comms lib dll        |
| .\bootinfo.dat     | error log        |
| .\history.jpg    | result log        |
| .\setuplst.xml    | main config file        |

#### Configuration File
The Carbon installer will drop an encrypted `setuplst.xml` config file to the working directory that the orchestrator and comms lib will read.
Our config file was based off the Carbon 3.77 config file.<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup> A plain text version of the config file is available in [`bin/configPlainText.xml`](./bin/configPlainText.xml).

These are the different sections, settings, and their descriptions in the config file:
| Section  | Setting | Description |
| ------------ | ----------- | ----------- |
| [NAME] | object_id | The uuid of this implant |
| [PROC] | net_app | A list of the target applications for the orchestrator to inject into |
| [CRYPTO] | rsa_priv | The private RSA key for the comms lib to decrypt communications from the C2 |
| [TIME] |  | not used in our implementation |
| [CW_LOCAL] | quantity | not used in our implementation |
| [CW_INET] | address1 | The URL of the C2 endpoint |
| [TRANSPORT] | system_pipe | The name of the pipe used for p2p |
| ^ | spstatus | not used in our implementation |
| ^ | adaptable | not used in our implementation |
| ^ | p2p_client | If this implant will run in p2p client mode or not |
| ^ | peer_pipe | The pipe to send C2 communications back to |
| [DHCP] | server | not used in our implementation |
| [LOG] | logperiod | not used in our implementation |
| [WORKDATA] |  | not used in our implementation |
| [LOCATION] | task_dir | The name of the directory that contains the task file |
| ^ | log_dir | The name of the directory that contains task output related files |
| ^ | t_cfg_dir | The name of the directory that contains task config files |
| [FILE] | cfg | The name of the main config file |
| ^ | tsk | The name of the task file |
| ^ | send | The name of the file that lists files to send to the C2 |
| ^ | elog | The name of the error log file |
| ^ | log | The name of the regular log file |
| [MTX] | cfg | The name of the mutex for the task file |
| ^ | tsk | The name of the mutex for the task file |
| ^ | send | The name of the mutex for the file that lists files to send to the C2 |
| ^ | elog | The name of the mutex for the error log file |
| ^ | log | The name of the mutex for the regular log file |

Upon startup, the first thing the orchestrator will do is read this config file. If there is an option missing from the config file that the orchestrator is expecting, it will fall back to a default value. These are listed in the [`src/orchestrator.cpp`](./src/orchestrator.cpp) file.

### Functionality
#### Encryption
[source](./src/enc_handler.cpp)

Each file output from the orchestrator will be encrypted with CAST-128.<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>
We used a hardcoded key with a hex value of `f2d4560891bd948692c28d2a9391e7d9` in our implementation.
The orchestrator expects the config file to be encrypted, and will first decrypt it and load configuration information before performing any action.

The orchestrator also expects task-related files to be encrypted and will decrypt tasking information before proceeding to task execution. Task output is encrypted on disk for the comms lib to pick up and send to the C2 server.

#### Mutexes
[source](./src/mutex.cpp)

The orchestrator will create five mutexes to coordinate file access between the comms lib and itself.
The mutexes created were based off Carbon 3.8X.<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>
The number of mutexes used here was reduced by two when compared to the CTI because we do not use an equivalent of `xmlrts.png`, and only the orchestrator is completing tasks, so there is less simultaneous read/write access between the orchestrator and the comms lib.

These are the mutexes created by the orchestrator and their descriptions:
| Mutex  | Description |
| ------------ | ----------- |
| Global\Microsoft.Telemetry.Configuration      | Represent config file `setuplst.xml` ownership |
| Global\DriveEncryptionStd | Represent task file `workdict.xml` ownership |
| Global\DriveHealthOverwatch | Represent send file `traverse.gif` ownership |
| Global\Threading.Management.Info | Represent error log `bootinfo.dat` ownership |
| Global\Stream.Halt.Restoration | Represent regular log `history.jpg` ownership |

#### Injection
[source](./src/injection.cpp)

The orchestrator will inject the 3rd stage communications library into processes that typically generate HTTP traffic, such as a web browser.<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/),[2](https://www.gdatasoftware.com/blog/2015/01/23926-analysis-of-project-cobra),[3](https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html)</sup> For our evaluations, only Microsoft Edge was tested with the orchestrator. Injection into other web browsers should be possible, but this is not tested.

Injection is performed in the following steps:
- enable debug privileges for the current process [source](./src/injection.cpp#L102)
- read the config file for a list of target processes [source](./src/injection.cpp#L166)
- look for those processes on the current machine, and record the PIDs of the ones found [source](./src/injection.cpp#L215)
- get a handle to `KERNEL32.dll` from a target process [source](./src/injection.cpp#L283)
- perform the injection using `GetProcAddress` for `LoadLibraryA`, `OpenProcess` for the target process, `VirtualAllocEx`, `WriteProcessMemory`, and finally `CreateRemoteThread` [source](./src/injection.cpp#L329)

After successful injection, the comms lib DLL will start to communicate with the C2 server.

The orchestrator uses `OpenProcess` and `WaitForSingleObject` to monitor the process that the comms lib was injected into.
If that process is terminated, the orchestrator will attempt to find a new host process to re-inject the comms lib.
  
#### Tasking
[source](./src/tasking.cpp)

The comms lib will post tasks for the orchestrator in `workdict.xml`.
The orchestrator will check `workdict.xml` for updates every 5 seconds.
The format for each task is as follows<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>:
```
task_id | task_filepath | task_config_filepath | task_result_filepath | task_log_filepath
```
| Field  | Description |
| ------------ | ----------- |
| task_id | a number designating which task this is |
| task_filepath | the location of a file that the orchestrator will execute for this task |
| task_config_filepath | the location of the configuration file specific to this task |
| task_result_filepath | the location where the orchestrator will output the task result (i.e. command output) |
| task_log_filepath | the location where the orchestrator will output its log for this task |

The format for a task config file is as follows:
```
[CONFIG]
name = cmd.exe
exe = whoami /all
```
| Field  | Description |
| ------------ | ----------- |
| name | the name of the file to run (cmd.exe by default) |
| exe | the arguments to run the file with |

A task config file can exclude the `name` field, and `cmd.exe` will be filled in by default.
However, an operator should not need to worry about creating the task config files ask this is done automatically by the comms lib, and an operator should refer to the Carbon C2 handler for instructions on how to task the implant.
If tasks are found, the orchestrator will parse them, pick out each section of the task, and then execute the task.
The orchestrator is able to execute multiple tasks sequentially if there are multiple in the tasking file.
Once the orchestrator has completed executing all of the tasks, it will remove them from the tasking file and release the mutex for the tasking file.
Then, the orchestrator will take any output and log information from the task it performed, and put those in the `task_result_filepath` and `task_log_filepath` respectivley.
The orchestrator will then gain ownership of the mutex for and make an entry in the "files to send to the C2" file, `traverse.gif`.
The format for these entries is as follows:
```
task_id | num_files | filepath | uuid
```
| Mutex  | Description |
| ------------ | ----------- |
| task_id | a number designating which task this is |
| num_files | the number of files to send (only 1 is supported) |
| filepath | the path of the file to send |
| uuid | the uuid of the implant, as defined in the config file |

Since only sending 1 file per entry is supported, each task will create two entries in `traverse.gif`, one for the result file and one for the log file.
The comms lib will then check `traverse.gif` for entries, and when found, will send those files to the C2 server.

### Testing Information
**Currently, the orchestrator will output everything it logs to console for testing purposes.**
<br>
**Using any of the testing scripts will perform process injection**<br>

The easiest way to test the orchestrator is to use the Carbon Installer.

If the installer does not have the most recent versions of the orchestrator or comms lib, you can test the orchestrator with the included `output-itest.ps1` script.

`output-itest.ps1` runs the orchestrator and comms lib separately so that the user has console output for both.
Both testing scripts require that files are placed in `turla\Resources\Carbon\Orchestrator\resources`:
- `MSSVCCFG.dll`: the orchestrator
- `MSXHLP.dll`: the comms lib
- `setuplst.xml`: the encrypted config
- `dllrunner.exe`: dll runner used to start the comms lib (output-itest.ps1 only)

These files can be found in these locations respectively:
- [`turla/Resources/Carbon/Orchestrator/bin/MSSVCCFG.dll`](./bin/MSSVCCFG.dll)
- `turla/Resources/Carbon/CommLib/bin/commlib.dll` (needs to be renamed)
- [`turla/Resources/Carbon/Orchestrator/bin/setuplst.xml`](./bin/setuplst.xml)
- `resources/Payloads/DllLoader/dllrunner.exe` (resources repo, not turla)

The c2 server seems to want one task at a time.
You need to start the c2 before you start carbon.

You will need to have a c2 server running and issue a task in order to see that Carbon is working.
The following task was used to test that Carbon is working properly: `./evalsC2client.py --set-task SOMEUUID '{"id": 1, "code": 0, "cmd": "whoami /all"}'`.
You can change the `"cmd": "whoami /all"` section to execute another command, such as `"cmd": "systeminfo"`.
Please ensure that the comms lib is looking at the right IP/port for your c2 server.
This is defined in the config under `address1`, which you only need to change the IP and port.
If you need to edit the config, you can encrypt it by making your changes to [`./bin/configPlainText.xml`](./bin/configPlainText.xml) and running [`./bin/configEncrypt.exe`](./bin/configEncrypt.exe).
This will overwrite [`./bin/setuplst.xml`](./bin/setuplst.xml) with the updates made to [`./bin/configPlainText.xml`](./bin/configPlainText.xml).

After all requisite files are found, `output-itest.ps1` will clean the working directory, `C:\Program Files\Windows NT`, of any artifacts.
Next, `output-itest.ps1` will manually create the directories in `C:\Program Files\Windows NT` that Carbon requires.
Then, it will copy over the files from `turla\Resources\Carbon\Orchestrator\resources`.
Now, it will start Carbon using `dllrunner.exe` and [`./bin/runner.exe`](./bin/runner.exe) to start the comms lib and orchestrator respectivley.
Once you are done testing, you can enter `1` in the script to view the log files, where the script will run [`./bin/castDecrypt.exe`](./bin/castDecrypt.exe) for both `history.jpg` and `bootinfo.dat`.
Finally, the script will clean up any artifacts created from testing.

If you encounter an error, [`./include/orchestrator.h`](./include/orchestrator.h) has a mapping of error code to a basic name of the error to help diagnose the issue.

### Build Instructions
All PE files were build on Windows 10 with MinGW32.
You can use the included `build.ps1` script to automatically remove and rebuild the PE files.
`build.ps1` is designed to build a dll from `.\test\dllspawnnp.cpp` and place it in `.\bin\MSXHLP.dll` so that it can be injected by the orchestrator for testing.
However, having the `.\test\dllspawnnp.cpp` file is not required to be able to build using `build.ps1`, and the script will skip that file if it does not exist.
`build.ps1` will also remove the symbols from the orchestrator dll and check that they have been removed.

If you wish to build the PE files manually, these are the commands that are used to do so.
```
x86_64-w64-mingw32-g++ -static -std=c++20 -lstdc++fs -Wall -Wextra -Werror -o bin/runner.exe test/testdllrunner.cpp
x86_64-w64-mingw32-g++ -I include/ -I "$env:MINGW64_ROOT\include\cryptopp" -static -shared -std=c++20 -lstdc++fs -Wall -Wextra -Werror -o bin/MSSVCCFG.dll src/*.cpp -lWinInet -L "$env:MINGW64_ROOT\lib" -l cryptopp
x86_64-w64-mingw32-g++ -I include/ -I "$env:MINGW64_ROOT\include\cryptopp" -static -std=c++20 -lstdc++fs -Wall -Wextra -Werror -o bin/configEncrypt.exe test/config_encrypt.cpp -lWinInet -L "$env:MINGW64_ROOT\lib" -l cryptopp
x86_64-w64-mingw32-g++ -I include/ -I "$env:MINGW64_ROOT\include\cryptopp" -static -std=c++20 -lstdc++fs -Wall -Wextra -Werror -o bin/castDecrypt.exe test/castDecrypt.cpp -lWinInet -L "$env:MINGW64_ROOT\lib" -l cryptopp
```
You can remove symbols from the orchestrator dll with the following command:
```
strip -s .\bin\MSSVCCFG.dll
```
To verify, you can run `objdump --syms .\bin\MSSVCCFG.dll` - you should see an empty symbols table.

### Cleanup Instructions

When running the orchestrator with the Carbon Installer, refer to the Carbon Installer's `turla/Resources/cleanup/Carbon/carbon_cleanup.ps1` script for cleanup.

### CTI References
1. https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
2. https://www.gdatasoftware.com/blog/2015/01/23926-analysis-of-project-cobra
3. https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
