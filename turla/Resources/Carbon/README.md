# Carbon DLL

## Overview
Carbon DLL is a second-stage malware that Turla has used in operations<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>. Carbon DLL is implemented as 2 usermodule DLLs and is executed via a service binary, acting as a usermode-only variant of the Carbon rootkit and using asymmetric encryption for C2 traffic via HTTP requests.<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/),[2](https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html)</sup>.

## Components
The Carbon DLL resources in this repository include the following components<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/),[3](https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra)</sup>:
- [Carbon DLL dropper/installer](./CarbonInstaller), which drops the components and configuration file and creates and starts the loader service
- [Carbon orchestrator DLL](./Orchestrator), which executes tasks and injects the communications DLL into a browser process
- [Carbon communications DLL](./CommLib), which communicates with the C2 server and relays tasks to the orchestrator DLL
- [Loader DLL](./CarbonInstaller/Loader) that is executed as a service in order to kick off the orchestrator DLL.

### Dropper/Installer
The Carbon DLL dropper will create the following subdirectories in the Carbon working directory:
- `%programfiles%\Windows NT\0511` for tasking info
- `%programfiles%\Windows NT\2028` for task output
- `%programfiles%\Windows NT\Nlts` for task config files

`C:\Program Files\Windows NT` is set as the Carbon working directory. Per CTI, Carbon randomly selects a folder from `C:\Program Files`<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>, but we only use `Windows NT` in the emulated version to maintain consistent evaluations.

The Carbon DLL dropper will drop the following files to disk<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/),[3](https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra)</sup>:
- Configuration file to `%programfiles%\Windows NT\setuplst.xml`
- Loader DLL to `%systemroot%\System32\mressvc.dll`
- Orchestrator DLL to `%programfiles%\Windows NT\MSSVCCFG.dll`
- Communications library DLL to `%programfiles%\Windows NT\MSXHLP.dll`

After successful file writes, the dropper will create a service to execute the loader DLL.<sup>[3](https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra)</sup> 

The service details are as follows:
- Service Name: `WinResSvc`
- Display name: `WinSys Restore Service`
- Bin path: `C:\Windows\System32\svchost.exe -k WinSysRestoreGroup` (svchost is used since we are running a DLL as a service).

Turla has used the same display name in the past, though we changed the service name to avoid using the exact same naming convention.

The dropper then performs two registry writes to make sure that the service can find the loader DLL and that the service will run under svchost:
1. The loader DLL path (`%systemroot%\system32\mressvc.dll`) is written to registry key `HKLM:\SYSTEM\CurrentControlSet\services\WinResSvc\Parameters` under the `ServiceDll` value
1. The service name (`WinResSvc`) is written to registry key `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost` under the `WinSysRestoreGroup` value

Once the service is set up, the dropper will start it before terminating its own execution.

### Loader DLL
The loader DLL is dropped by the Carbon DLL dropper and then executed via service under svchost. The loader DLL exports a `ServiceMain` function in order to be run as a service.

When running as a service, the loader DLL will execute the orchestrator DLL by calling its exported `CompCreate` function, analogous to how Turla executed Carbon DLL with a different exported function name.<sup>[3](https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra)</sup>. Note that the loader DLL grabs the orchestrator DLL from disk.

### Communications DLL
The Carbon communications library DLL is injected into browser processes by the Orchestrator DLL. Its primary role is to communicate with the C2 server as an HTTP client, or via named pipes if running in peer-to-peer mode, to retrieve tasking information and relay it to the Orchestrator DLL for execution.

For more details on how the comms lib DLL functions and interacts with other Carbon DLL artifacts, please refer to the [Comms Lib DLL README file](./CommLib/README.md).

### Orchestrator DLL
The Carbon DLL Orchestrator is run by the Carbon DLL loader service in order to inject the C2 communication DLL (comms lib) into a legitimate process and execute tasks that the comms lib receives from the C2 server.<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>

For more details on how the Orchestrator DLL functions and interacts with other Carbon DLL artifacts, please refer to the [Orchestrator DLL README file](./Orchestrator/README.md).

### Carbon DLL Directory Structure
The file structure used by the emulated Carbon DLL is based on a combination of Carbon 3.7X Carbon 3.8X file structures.<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>

In addition to using different names, the emulated file structure differs from CTI by using only one task file rather than separate ones for both the orchestrator and comms lib DLLs, since only the orchestrator executes tasks in the emulated variant.

The table below lists the files and folders in the Carbon DLL working direcotry. In a successful installation, the files and folders listed below will always be created; however, specific task-related files will have varying names based on the corresponding task ID.

| File/Folder  | Description |
| ------------ | ----------- |
| .\0511      | directory for tasks and task info |
| .\0511\workdict.xml    | orchestrator tasks |
| .\2028      | directory for log and task result files    |
| .\2028\traverse.gif    | list of task result files to send to c2        |
| .\2028\dsntport.dat | comms lib log file |
| .\Nlts | directory for task config files |
| .\MSSVCCFG.DLL      | orchestrator dll        |
| .\MSXHLP.DLL    | comms lib dll        |
| .\bootinfo.dat     | orchestrator error log        |
| .\history.jpg    | orchestrator log file |
| .\setuplst.xml    | main Carbon config file |

For more information on the configuration file and its fields, please see the configuration file section in the [Orchestrator README file](./Orchestrator/README.md#Configuration-File).

## Usage
To install Carbon DLL, simply run the installer executable as an administrator.

Instructions on how to task Carbon DLL can be found in the Carbon DLL C2 handler README file.

For more specific usage information for individual components, please refer to their respective README files.

## Troubleshooting
* If the installer returns an error in its output, the error code will either be a [Windows system error code](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-) or a custom error code defined in [`CarbonInstaller/Dropper/include/file_handler.h`](./CarbonInstaller/Dropper/include/file_handler.h) or [`CarbonInstaller/Dropper/include/service_handler.h`](./CarbonInstaller/Dropper/include/service_handler.h).

* To check if files were dropped, you can open up file explorer on the target host and look in `C:\Program Files\Windows NT`

* To check if the service is created and running, open up task manager, go to the `services` tab, and then look for the `WinResSvc` service.
  * If the service does not exist or is not running, you may need to check privileges or cleanup and try again.
  
* If the `WinResSvc` is stopped, or if it's running and you still don't have a Carbon beacon even with Edge open, you can check for the Carbon Orchestrator log and error files at `C:\Program Files\Windows NT\history.jpg` and `C:\Program Files\Windows NT\bootinfo.dat`, respectively. 
  * These log files can be decrypted on a Windows machine using the `Orchestrator/bin/castDecrypt.exe` utility.
  * The `bootinfo.dat` error file will likely explain why injection into Edge failed, or if the orchestrator failed in an earlier spot.
  * If neither file exists, it's likely the service was unable to start, and you will likely need to perform cleanup and try executing the installer again.

* If you're still having issues obtaining an initial beacon despite successful injection, or if you obtained a beacon and then lost communication from the Carbon implant, look for the `C:\Program Files\Windows NT\2028\dsntport.dat` communications module log file. 
  * This log file can be decrypted on a Linux machine using the [`CommLib/decrypt_logs.py`](./CommLib/decrypt_logs.py) utility:
  >```
  >python3 decrypt_logs.py -p /path/to/commslib/log -o /plaintext/output/log/path
  >```
  * If this file does not exist, then that means the communications library was either not injected or was not even able to start up.
* Once decrypted, you can look through the log for indicators of problems, such as pipe communication issues for peer-to-peer.
  * Error codes in the log file will either be a [Windows system error code](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-) or a custom error code defined in header files within the `CommLib/include` directory. 

## Cleanup
To remove artifacts, run the [Carbon cleanup](../cleanup/Carbon/carbon_cleanup.ps1) Powershell Script as an administrator on the target host(s).

You can do so from a domain controller using the following powershell command (from a directory containing the script):
```
$targethosts = "host1","host2","host3"
foreach ($targethost in $targethosts) {
    Write-Host "[+] Performing Carbon cleanup on $targethost"
    Invoke-Command -ComputerName $targethost -FilePath .\carbon_cleanup.ps1
}
```

For example, to cleanup the Carbon Scenario from evaluations:
* From the Kali Linux machine (`176.59.15.33`):
  * ```
    cd /opt/day1/turla
    xfreerdp +clipboard /u:skt\\\evals_domain_admin /p:"DuapQj7k8Va8U1X27rw6" /v:10.20.10.9 /drive:X,Resources/cleanup
    ```
* From the domain controller RDP session, open an Admin PowerShell and execute the cleanup script:
  * ```
    cd \\TSCLIENT\X\Carbon
    $targethosts = "hobgoblin","bannik","khabibulin"
    foreach ($targethost in $targethosts) {
        Write-Host "[+] Performing Carbon cleanup on $targethost"
        Invoke-Command -ComputerName $targethost -FilePath .\carbon_cleanup.ps1
    }
    ```
* Sign out of the RDP session when finished.

## Build
For specific build instructions, refer to the README files for each individual component.

## Testing
For specific test instructions, refer to the README files for each individual component.

## References and CTI
1. https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
2. https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
3. https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra
