# README for the Windows Webshell

## Execution Instructions / Resources

These instructions assume that you received
the executables in a zip archive.

Parameters should be enclosed in double quotes (`" "`).

### Executing Webshells with the Wrapper

* Location: `build/windows/wrapper.exe`
  * You should be in this directory to start the executable
    with its default settings.
* Flags:
  * `-commandTimeDelay`: Time in seconds between running commands.
    * Type: integer (not in double quotes)
    * Default: `10`
  * `-loopTimeDelay`: Time in second between looping back through commands.
    * Type: integer (not in double quotes)
    * Default: `20`
  * `-runTime`: Time in seconds to run webshell for (0 to run forever).
    Must be longer than total command and loop time.
    * Type: integer (not in double quotes)
    * Default: `120`
    * This has a known bug. Refer to [Known Issue With Killing Child Processes](#known-issue-with-killing-child-processes).
  * `-shellDest` (string): Webshell will be copied here.
    * Type: string (must be in double quotes)
    * Default: `"./windowswebshell.exe"`
    * Relative to location of `wrapper.exe`.
  * `-shellHost`: The hostname or IP you want the shell to run on.
    * Type: string (must be in double quotes)
    * Default: `"localhost"`
  * `-shellPort`: The port you want the shell to run on.
    * Type: string (must be in double quotes)
    * Default: `"8080"`
  * `-shellSrc`: Location to copy webshell from.
    * Type: string (must be in double quotes)
    * Default: `"shell/windowswebshell.exe"`
    * Relative to location of `wrapper.exe`.

Use `wrapper.exe -h` to view help information for the flags.

The flags can be given in any order.

Example with no flags:

```
> .\wrapper.exe
Copied webshell shell/windowswebshell.exe to ./windowswebshell.exe.
Webshell will be started: ./windowswebshell.exe -hostname=localhost -port=8080 -runTime=120
2022/05/26 11:47:53 Process started.
Started webshell. It will be killed after 120 seconds.
2022/05/26 11:47:53 Starting the client.

2022/05/26 11:47:53 Sending command: " whoami /groups"
Command: whoami /groups
Response:
<br />Group Name                                                    Type             SID          Attributes            
<br />============================================================= ================ ============ ======================
<br />Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabl
<br />NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Group used for deny on
<br />BUILTIN\Administrators                                        Alias            S-1-5-32-544 Group used for deny on
<br />BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabl
<br />NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4      Mandatory group, Enabl
<br />CONSOLE LOGON                                                 Well-known group S-1-2-1      Mandatory group, Enabl
<br />NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabl
<br />NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabl
<br />NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabl
<br />LOCAL                                                         Well-known group S-1-2-0      Mandatory group, Enabl
<br />NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabl
<br />Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192                        
<br />
```

Example with `-runTime` and `-shellPort`:

```
> .\wrapper.exe -runTime=0 -shellPort=10110
Copied webshell shell/windowswebshell.exe to ./windowswebshell.exe.
Webshell will be started: ./windowswebshell.exe -hostname=localhost -port=10110 -runTime=0
runTime is 0 (run forever). The webshell will run until Ctrl+C.
Started webshell. Waiting for kill signal.
2022/05/26 11:56:20 Starting the client.

2022/05/26 11:56:20 Sending command: "whoami /groups"
2022/05/26 11:56:21 Process started.
Command: whoami /groups
Response:
<br />Group Name                                                    Type             SID          Attributes            
<br />============================================================= ================ ============ ======================
<br />Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabl
<br />NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Group used for deny on
<br />BUILTIN\Administrators                                        Alias            S-1-5-32-544 Group used for deny on
<br />BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabl
<br />NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4      Mandatory group, Enabl
<br />CONSOLE LOGON                                                 Well-known group S-1-2-1      Mandatory group, Enabl
<br />NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabl
<br />NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabl
<br />NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabl
<br />LOCAL                                                         Well-known group S-1-2-0      Mandatory group, Enabl
<br />NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabl
<br />Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192                        
<br />
Process terminated without errors.

Finished.
```
In this output, the Ctrl+C is sent by the user just before "Process terminated without errors" appears.

### Webshell Wrapper Discovery Commands

After the windowswebshell server is started, the wrapper will execute one of
a set of pre-defined OS discovery commands at random in a loop until the `runTime`
expires, or until the wrapper is killed with Ctrl+C.

| Command | Purpose |
| ------- | ------- |
| `whoami /groups` | Enumerate the current user's groups. |
| `netstat -ano` | Enumerate open ports and active connections numerically. Includes process ID. |
| `qwinsta` | Displays information about user sessions. |
| `tasklist` | Enumerate running processes. |

In the console, the output for each command begins with "Sending command:",
followed by the output.

```
2022/05/26 11:48:03 Sending command: " netstat -ano"
Command: netstat -ano
Response:
<br />  UDP    [::1]:49665            *:*                                    6032
```

#### Known Issue With Killing Child Processes

When the `-runTime` expires or Ctrl+C is sent, the process started by the `wrapper.exe` to execute the `windowswebshell.exe` kills that process, but may not kill the child processes (e.g., of the web server) completely. This is a known issue.

If you use Powershell's `netstat -a` to examine connections after the wrapper exits, there may be leftover connections in the `TIME_WAIT` state with a "local address" of `<source hostname>:<high port number>`
and a "foreign address" of `<this host>:<server's port>`. There may be up to one such connection for each client request sent to the server.

While the server is running on localhost:8080, you would see something like this after two CURL requests are made to the server.
```
>netstat -a

Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    127.0.0.1:8080         MSEDGEWIN10:0          LISTENING
  TCP    127.0.0.1:49789        MSEDGEWIN10:8080       TIME_WAIT
  TCP    127.0.0.1:49791        MSEDGEWIN10:8080       TIME_WAIT
```

After the server has been killed, the connections with `TIME_WAIT` remain.
```
>netstat -a

Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    127.0.0.1:49789        MSEDGEWIN10:8080       TIME_WAIT
  TCP    127.0.0.1:49791        MSEDGEWIN10:8080       TIME_WAIT
```

The OS kills these connections on its own after a few minutes.

### Executing the Windows Webshell

* Location: `build/shells/windowswebshell.exe`
* Flags:
    * `-hostname`: Server will bind to this hostname. It can be an IP, but it must be on the local host.
      * Type: A string (must be in double quotes).
      * Default: `"localhost"`
    * `-port`: Server will bind to localhost with this port number.
      * Type: A string (must be in double quotes).
      * Default: `"8080"`
    * `-runTime`: Time in seconds to run webshell for (`0` to run forever).
      * Type: An integer (not in double quotes).
      * Default: `120`

Use `windowswebshell.exe -h` to view help information for the flags.

Start the webshell by double-clicking it, or by running `webshell.exe` in a shell.

It binds to `localhost:8080` by default.

```
webshell.exe
```

You can also start the webshell with a custom hostname, port,
and running time in seconds. The hostname must be valid for the
host where the webshell is being executed.

```
webshell.exe -hostname="localhost" -port="12345" -runTime=30
```

If `-runTime=0`, the webshell will run forever until you quit with `Ctrl+C`.

```
webshell.exe -hostname="localhost" -port="12345" -runTime=0
```

Commands can be sent to the webshell at `localhost:8080` or your
custom `hostname:port` by submitting a form request that contains the command
in a field named `c`. The `curl` tool is an easy way to do this.

Starting with Windows 10, it is also available on Windows in Powershell.
* https://curl.se/windows/microsoft.html
* On Windows, you must explicitly use `curl.exe`, otherwise you will get
the Powershell `curl` *alias* for Invoke-WebRequest, which works differently.

```
curl.exe -X POST -F 'c=ipconfig /all' http://localhost:8080
```

At this time the webshell's shell doesn't have awareness of the `PATH`
and may require absolute paths to reach some executables.

#### Webshell JSON Responses 

The webshell will send some output to its console, and a JSON-formatted
response to whatever sent the POST request:

Console output for the command `ipconfig /all`:
```
ipconfig /all
exec: ipconfig /all
```

Raw example response:
```
{"Command":"ipconfig /all","Error":"","ErrorString":"","Result":"\r\u003cbr /\u003eWindows IP Configuration\r\u003cbr /\u003e\r\u003cbr /\u003e   Host Name . . . . . . . . . . . . : MSEDGEWIN10\r\u003cbr /\u003e   Primary Dns Suffix  . . . . . . . : \r\u003cbr /\u003e   Node Type . . . . . . . . . . . . : Hybrid\r\u003cbr /\u003e   IP Routing Enabled. . . . . . . . : No\r\u003cbr /\u003e   WINS Proxy Enabled. . . . . . . . : No\r\u003cbr /\u003e"}
```

Response with formatting for readability:
```
{
  "Command":"ipconfig /all",
  "Error":"",
  "ErrorString":"",
  "Result":"\r\u003cbr /\u003eWindows IP Configuration\r\u003cbr /\u003e\r\u003cbr /\u003e   Host Name . . . . . . . . . . . . : MSEDGEWIN10\r\u003cbr /\u003e   Primary Dns Suffix  . . . . . . . : \r\u003cbr /\u003e   Node Type . . . . . . . . . . . . : Hybrid\r\u003cbr /\u003e   IP Routing Enabled. . . . . . . . : No\r\u003cbr /\u003e   WINS Proxy Enabled. . . . . . . . : No\r\u003cbr /\u003e"
}
```
* "Command" is the original command.
* "Error" is an internal error code returned by Golang after running the command, if there was an error.
* "ErrorString" is the stderr output of the command, if any.

The output contains Unicode-escaped HTML that any application handling the webshell's responses may need to post-process.

* `\r\u003cbr /\u003e` is a Unicode-escaped `\r<br />`:
  * A carriage return `\r` followed by an HTML line break `<br />`.
  * `\u003c` is `<` and `\u003e` is `>`.

For itself, the wrapper un-escapes these back into a `<br />` when it displays the responses.

### Customizing the Executables

The behavior of the executable can be further tailored by modifying the variables used by the build scripts and then rebuilding the project from source.

Refer to [Customizing the Executables](BUILD_windows_webshell.md#Customizing-The-Executables) in the building document for more details.
