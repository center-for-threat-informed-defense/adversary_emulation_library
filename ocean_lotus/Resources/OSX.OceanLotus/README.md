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
- Extracts, base64 decodes, and executes the embedded Implant (Second
Stage) payload
- Prepares persistence install via LaunchAgent or LaunchDaemon
  - **NOTE:** This script *does not* activate/install the persistence mechanism
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

## For Operators

### Execution

To activate the persistence mechanism at the user context, task the implant to
execute the following command:
```
launchctl load -w /Users/bob/Library/LaunchAgents/com.apple.launchpad
```

Replace the above path with `/Library/LaunchAgents/com.apple.launchpad` if the
implant is running in an elevated (root) context.

### Troubleshooting

### Cleanup

Execute the [cleanup script](../cleanup/OSX.OceanLotus/cleanup_osx.oceanlotus.sh)
and provide the path to the folder where the application bundle was executed:

> NOTE: Do not include the trailing slash in the target path

```
./cleanup_osx.oceanlotus.sh $HOME/Downloads
```

Expected output:
```
Identified executing directory as: /Users/bob/Downloads

[+] /Users/bob/Library/WebKit/com.apple.launchpad exists, removing...
  [+] /Users/bob/Library/WebKit/com.apple.launchpad was removed successfully
[+] /Users/bob/Downloads/Decoy.doc exists, removing...
  [+] /Users/bob/Downloads/Decoy.doc was removed successfully
[+] /tmp/store exists, removing...
  [+] /tmp/store was removed successfully
[+] Persistence found, removing...
/Users/bob/Library/LaunchAgents/com.apple.launchpad/com.apple.launchpad.plist: Operation now in progress
[+] Unloaded LaunchAgent persistence
[+] /Users/bob/Library/LaunchAgents/com.apple.launchpad directory exists, removing...
  [+] /Users/bob/Library/LaunchAgents/com.apple.launchpad directory was removed successfully
[-] No /tmp/*.log files found
[+] TextEdit found, killing...
```

## For Developers 

### Dependencies

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
