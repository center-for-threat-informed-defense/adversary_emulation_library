# OSX.OceanLotus

| Components | Use | Description |
| ---------- | --- | ----------- |
| Application Bundle | First stage | Masquerades as a Word doc, executes script on click that drops and executes the Second Stage Implant |
| Implant | Second stage | Installs persistence and performs backdoor capabilities |
| Comms | C2 communication | Library containing C2 communication functionality |

## Description

### Application Bundle (First Stage)
This component is an application bundle containing the following items:
- Bash script
- Decoy Word document 
- Microsoft Word icon
- Launchd plist file (PkgInfo)

The bash script contains the base64 encoded Implant (Second Stage)
embedded within it. On application bundle open, the bash script is executed and
performs the following actions:
- Removes quarantine flag on files within the application bundle
- Extracts and base64 decodes the embedded Implant (Second Stage) payload and its Communication Library component as `/Users/hpotter/Library/WebKit/com.apple.launchpad` and `/Users/hpotter/Library/WebKit/b2NlYW5sb3R1czIz`, respectively
- Prepares persistence via LaunchAgent or LaunchDaemon
  - **NOTE:** This script *does not* activate the persistence mechanism
  and the implant, once executed, should be tasked to execute the following
  command:
    ```
    launchctl load -w /Users/bob/Library/LaunchAgents/com.apple.launchpad
    ```
  - This will return a second OSX implant session, at which point, it is safe
  to exit or disregard the initial implant session in preference of utilizing
  the persistent implant session
- Uses `touch` to update the timestamps of the Implant (Second Stage) artifacts
- Uses `chmod` to make the Implant (Second Stage) binary file executable by
changing file permissions to 755
- Executes the Implant (Second Stage) binary
- Replaces the application bundle with the decoy Word document

### Implant (Second Stage)
This component is a fat binary embedded within the bash script in the
Application Bundle (First Stage) that performs the backdoor capabilities. On
execution, the Implant (Second Stage) automatically performs the following
actions:
- Collects OS information
- Registers with C2 server

#### C2 Communication

The OSX.OceanLotus implant communicates over HTTP to a hardcoded IP address
within the Comms library.

Data received and sent to the C2 server is contained within the HTTP request 
body. The data is formatted using the following structure:

| Offset | Length | Section Name | Data |
| ------ | ------ | ---- | --- |
| 0      | 4 bytes | Header | Magic bytes `{0x3B, 0x91, 0x01, 0x10}` |
| 8      | 4 bytes | Header | Length `x` of payload |
| 12     | 2 bytes | Header | Length `y` of encryption key |
| 14     | 4 bytes | Header | Command instruction bytes |
| 19     | 1 byte  | Header | Magic marker byte `0xC2` |
| 24     | 1 byte  | Header | Magic marker byte `0xE2` |
| 29     | 1 byte  | Header | Magic marker byte `0xC2` |
| 75     | 1 byte  | Header | Magic marker byte `0xFF` |
| 82     | `y` bytes | Key | Encryption key bytes (if no encryption, will be empty and `y` will therefore be 0) |
| 82 + `y` | `x` bytes | Payload | Payload bytes (if no encryption, will be plaintext and start at index 82) |

*C2 Registration*

For initial registration with the C2 server, OSX.OceanLotus will send an HTTP
POST request, in which a generated UUID and discovered OS information will be
stored within the "Payload" section of the above structure.

The generated UUID will be stored as a Cookie within **all following HTTP
requests to the C2 server.**

*Heartbeat*

For checking in with the C2 server, OSX.OceanLotus will send an HTTP GET
request. The C2 server identifies the request as a valid request based on the
UUID within the Cookie.

*Task Results*

For tasks that return output to the C2 server (output of executed commands and
exfiltrated files), OSX.OceanLotus will send an HTTP POST request, in which
the returned data will be stored within the "Payload" section of the above
structure. This POST request will be sent immediately after OSX.OceanLotus has
completed the task.

*Ingressed Downloads to Victim*

OSX.OceanLotus will write downloaded files to `osx.download` in the current
working directory of the executed implant binary. At this time, no additional
HTTP requests are sent back to the C2 server to confirm the download succeeded.

#### Available Instructions

> Note: Because the "Command instruction bytes" is 4 bytes in length, the 
following instructions are appended with null bytes to pad the remaining length
of the instruction.

| Instruction | Action | Details |
| ----------- | ------ | ------- |
| 0x55 | Heartbeat | Default empty response from C2 server |
| 0x72 | Upload file | "Payload" section of C2 server response should contain the file path to exfiltrate. OSX.OceanLotus will POST the file bytes |
| 0x23 or 0x3C | Download file | "Payload" section of C2 server response should contain the file bytes to write |
| 0xAC | Run command in terminal | "Payload" section of C2 server response should contain the command to execute. OSX.OceanLotus will execute the command then POST the command output |
| 0xA2 | Download file and execute | "Payload" section of C2 server response should contain the file bytes to write. OSX.OceanLotus will add the executable bit to the written file then POST the output of executing the file |
| 0x07 | Get configuration information | OSX.OceanLotus will POST the implant configuration information (UUID, path to the executing process, and install time) |
| 0x33 | Get file size | "Payload" section of C2 server response should contain the file path to get the file size of. OSX.OceanLotus will POST the file size in bytes |
| 0xE8 | Exit | OSX.OceanLotus will terminate its process

#### Obfuscation

*Not implemented*

## For Operators

### Execution

:bulb: Click [here](../controlServer/handlers/oceanlotus#osxoceanlotus) for
examples of interacting with an active implant using `evalsC2client.py` to
task the above instructions.

To execute the persistence mechanism at the user context, task the implant to
execute the following command:
```
launchctl load -w /Users/bob/Library/LaunchAgents/com.apple.launchpad
```

Replace the above path with `/Library/LaunchAgents/com.apple.launchpad` if the
implant is running in an elevated (root) context.

### Troubleshooting

**Application Bundle artifacts did not drop as expected**

* Check the group/file ownership of `conkylan.app` to ensure the executing
user can access all files within the application bundle. If the executing
user does not have access, the file permissions of `conkylan.app` can be
changed using `chown -r`

**Implant did not register with the C2**

* Check the following components were dropped:
  * Implant binary - `/Users/hpotter/Library/WebKit/com.apple.launchpad`
  * Communication library dylib - `/Users/hpotter/Library/WebKit/b2NlYW5sb3R1czIz`
  * If either of the above are missing, the artifacts are not dropping as
  expected and there may be file write permission issues
* The dropped communication library is hardcoded to connect to the IP address
`10.90.30.26`. To modify this address, update the address [here](./Comms/Comms/Comms.cpp#L125)
then refer to [Building](#building) for rebuilding the application bundle.
* Check a `/tmp/store` file is created that is identical to `/Users/hpotter/Library/WebKit/b2NlYW5sb3R1czIz` (compare MD5 or SHA256)
* Check debug output of the implant by executing the Implant binary directly
from the Terminal. Debug messages are prepended with `[IMPLANT]` for messages
printed by the Implant binary and `[COMMS]` for messages printed by the loaded
Communication Library. Examples:
  * "[IMPLANT] unable to load libComms.dylib ("/tmp/store")"
    * This would point to a failure within [loadComms](./Implant/Implant/main.cpp#L53-L99).
    * There are most likely additional error messages above this one that may
    imply exactly where the failure occurred:
      * Write/read permissions
      * Communication Library missing from current working directory
      * Communication Library could not be opened
  * "[IMPLANT] unable to load libComms.dylib sendRequest"
    * This would point to a failure to load the exported `sendRequest` function
    from the Communication Library dylib
    * Check the symbol table for `/tmp/store` (the copied Communication Library
    dylib) to ensure `sendRequest` exists
    * If modifications were made:
      * Ensure the function definitions expected within[`ClientPP::performHTTPRequest`](./Implant/Implant/ClientPP.cpp#L331)
      match the definition in [Comms.hpp](./Comms/Comms/Comms.hpp#L43) and
      [Comms.cpp](./Comms/Comms/Comms.cpp#L90)
      * Ensure the `extern` keyword is used and visibility attribute is set to
      `default` for `sendRequest`
  * "[IMPLANT] Received unfamiliar instruction"
    * This would point to a C2 issue in which the communications from the C2
    are malformed, instruction command IDs are being tasked that are not within
    the Implant's [available instruction set](#available-instructions)
  * "[COMMS] Connection Failed"
    * This would point to the socket being unable to connect to the intended
    IP address of the C2 server
  * "[COMMS] No response received from C2"
    * This would point to a successful connection but the C2 server discarded
    or ignored the communication from the implant. This can happen if the C2
    server was restarted after the Implant has registered and no longer
    recognizes follow up heartbeats from the Implant. To resolve, re-execute
    the Implant binary

**Implant LaunchAgent is not working**

* Check `/Users/hpotter/Library/LaunchAgents` directory exists. If not, create
it, [cleanup](#cleanup), then re-execute the application bundle
* Check `/Users/hpotter/Library/LaunchAgents/com.apple.launchpad/com.apple.launchpad.plist`
exists and contains the following:
  ```
  <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.apple.launchpad</string>
        <key>ProgramArguments</key>
        <array>
            <string>/Users/hpotter/Library/WebKit/com.apple.launchpad</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>KeepAlive</key>
        <true/>
    </dict>
    </plist>
  ```

**Implant registered to the C2 server with a different UUID than what is listed in the [Emulation Plan](../../Emulation_Plan/OceanLotus_Scenario.md)**

* The implant UUID is created from the following values:
  * IOPlatformSerialNumber
  * IOPlatformUUID
  * MAC address (`ifconfig en0 | awk '/ether/{print $2}'`)
* If the above values are different from the deployed infrastructure used in
the Emulation Plan, the UUID for all tasking commands must be updated
accordingly

**Multiple OSX.OceanLotus Implants executed on the same host all have the same UUID**

* For easy replication of the executed scenario, the implant UUID is created
from the following values:
  * IOPlatformSerialNumber
  * IOPlatformUUID
  * MAC address (`ifconfig en0 | awk '/ether/{print $2}'`)
* For a new, random UUID to be generated with each execution of the implant,
uncomment [this line](./Implant/Implant/ClientPP.cpp#L317) and comment out the
[following line of code](./Implant/Implant/ClientPP.cpp#L318)
  * This adds the output of `uuidgen` to the creation of the implant UUID

**Implant command execution lists an unexpected current working directory**

* It has been observed that usage of `popen` to execute commands may end up
executing from an effective current working directory of `/` instead of the
expected Implant binary location (within `/Users/hpotter/Library/WebKit`).
Always use full paths for listing directories and accessing the file system

**Relative path in executed command fails unexpectedly**

* It has been observed that usage of `~` does not resolve properly. Similar to
 the above issue (`popen` using `/` as its current working directory), always
 use full paths for interacting with the file system

**Implant download is missing**

* The implant will write downloaded files to `/Users/hpotter/Library/WebKit/osx.download`
or wherever `com.apple.launchpad` (Implant binary) was executed from.
  * Look in the directory where the Implant binary exists
  * Look `osx.download` file on the system if the location of the Implant
  binary is unknown
* Check the C2 server for output reporting the expected payload was not found
  * For tasking the OSX.OceanLotus implant, the C2 server will look for
  payloads in the `ocean-lotus/Resources/payloads/ocean-lotus` directory

### Cleanup

Execute the [cleanup script](../cleanup/OSX.OceanLotus/cleanup_osx.oceanlotus.sh)
and provide the path to the folder where the application bundle was executed:

> NOTE: Do not include the trailing slash in the target path

```
./cleanup_osx.oceanlotus.sh $HOME/Downloads
```

Expected output:
```
Identified executing directory as: /Users/hpotter/Downloads/

[+] /Users/hpotter/Library/WebKit/com.apple.launchpad exists, removing...
  [+] /Users/hpotter/Library/WebKit/com.apple.launchpad was removed successfully
[+] /Users/hpotter/Library/WebKit/b2NlYW5sb3R1czIz exists, removing...
  [+] /Users/hpotter/Library/WebKit/b2NlYW5sb3R1czIz was removed successfully
[+] /Users/hpotter/Downloads//conkylan.doc exists, removing...
  [+] /Users/hpotter/Downloads//conkylan.doc was removed successfully
[+] /tmp/store exists, removing...
  [+] /tmp/store was removed successfully
[+] Persistence found, removing...
/Users/hpotter/Library/LaunchAgents/com.apple.launchpad/com.apple.launchpad.plist: Operation now in progress
[+] Unloaded LaunchAgent persistence
[+] /Users/hpotter/Library/LaunchAgents/com.apple.launchpad directory exists, removing...
  [+] /Users/hpotter/Library/LaunchAgents/com.apple.launchpad directory was removed successfully
[-] No /tmp/*.log files found
[+] TextEdit found, killing...
```

## For Developers 

### Dependencies

To build the OSX.OceanLotus implant the following requirements must be met:
- Building on a macOS host [Catalina 10.15.7](https://support.apple.com/en-us/HT211683) ~8.25GB
- Full Xcode application is installed (version 12.4 compatible with Catalina 10.15)
- Xcode developer tools are installed (used in the terminal)

### Building

**Build All**

To build all, run the build script from the OSX.OceanLotus directory:
```
./build_osx.oceanlotus.sh
```

Expected output:
```
Command line invocation:
    /Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild -scheme Implant clean -configuration Release

note: Using new build system
note: Building targets in parallel

** CLEAN SUCCEEDED **

Command line invocation:
    /Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild -scheme Implant build -configuration Release

note: Using new build system
note: Building targets in parallel
note: Planning build
note: Using build description from disk
...

** BUILD SUCCEEDED **

Command line invocation:
    /Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild -scheme Comms clean -configuration Release

note: Using new build system
note: Building targets in parallel

** CLEAN SUCCEEDED **

Command line invocation:
    /Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild -scheme Comms build -configuration Release

note: Using new build system
note: Building targets in parallel
note: Planning build
note: Constructing build description
...

** BUILD SUCCEEDED **

W8BN.icns -> conkylan.app/Contents/Resources/icon.icns
decoy.doc -> conkylan.app/Contents/Resources/default.config
first_stage.sh -> conkylan.app/Contents/MacOS/conkylan
Launchd.plist -> conkylan.app/Contents/PkgInfo
Application bundle created at '/Users/bob/ocean-lotus/Resources/OSX.OceanLotus/ApplicationBundle/conkylan.app'
```

**Application Bundle**

To build the application bundle, run the following script from the
`ApplicationBundle` directory:

```
./build_bundle.sh -s first_stage.sh -i W8BN.icns -d decoy.doc -p Launchd.plist -n "TestApp"
```

Expected output:
```
W8BN.icns -> TestApp.app/Contents/Resources/icon.icns
decoy.doc -> TestApp.app/Contents/Resources/default.config
first_stage.sh -> TestApp.app/Contents/MacOS/TestApp
Launchd.plist -> TestApp.app/Contents/PkgInfo
Application bundle created at '/Users/bob/ocean-lotus/Resources/OSX.OceanLotus/ApplicationBundle/TestApp.app'
```

**Implant**

To build the implant, run the follow command from the `Implant` directory:

```
xcodebuild -scheme Implant build -configuration Release
```

Expected output:
```
Command line invocation:
    /Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild -scheme Implant build -configuration Release

note: Using new build system
note: Building targets in parallel
note: Planning build
...

** BUILD SUCCEEDED **
```

**Comms**
To build the Comms library, run the follow command from the `Comms` directory:

```
xcodebuild -scheme Comms build -configuration Release
```

Expected output:
```
Command line invocation:
    /Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild -scheme Comms build -configuration Release

note: Using new build system
note: Building targets in parallel
note: Planning build
note: Constructing build description
...

** BUILD SUCCEEDED **
```

> :information_source: **Note:** The compiled libComms.dylib should be placed
> in the same directory as the Implant binary. The Implant will traverse its
> current working directory, copy files to `/tmp/store`, and attempt to load
> the files as shared objects using `dlopen`

### Testing

## CTI Reporting
1. https://www.trendmicro.com/en_us/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.html
1. https://unit42.paloaltonetworks.com/unit42-new-improved-macos-backdoor-oceanlotus/
1. https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
1. https://www.welivesecurity.com/2019/04/09/oceanlotus-macos-malware-update/

## Resources
- appify - https://gist.github.com/oubiwann/453744744da1141ccc542ff75b47e0cf
- https://otx.alienvault.com/indicator/file/be43be21355fb5cc086da7cee667d6e7
- https://www.virustotal.com/gui/file/48e3609f543ea4a8de0c9375fa665ceb6d2dfc0085ee90fa22ffaced0c770c4f/detection
