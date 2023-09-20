# EPIC Guard

## Overview
This is the second stage guard DLL for the EPIC implant. It is compiled as a DLL, and loads the third stage payload or an arbitrary .dll substitute
as an embedded resource. The guard, once compiled, can only be run via it's exported function `Protection`. A small DLL_Run solution is included
to run guard directly from Visual Studio. It can also be run via rundll32.exe, but console output and debugging will be unavailable.

The guard, like its parent injector, behaves differently based on what permissions it has, and evaluates said permissions at runtime. 
If the guard does not have elevated permissions then it will target a browser or other low privilege internet enabled application for injection with its payload.

However, when run from a process with elevated privileges, such as PsExec, Services.exe, or an elevated injector, guard will change its target.
In order to ensure elevated permissions for its payload Guard changes the injection target to another elevated process- 
i.e. an instance of svchost.exe with SE_DEBUG privileges (but not its current process).

## Set Up

### Visual Studio
Ensure that the correct character set is selected: 

`Project Properties > Advanced > Character Set > select No Set`.

Check that the project has a Resource.rc file. If one does not exist create one: 

`right-click project > Add > New Item > Resource > Resource File`.

If one alreadys exists, check that the Resource.rc file has no resources loaded, and delete any found: 

`double-click Resource.rc > drop down menu > right-click IDR_EXAMPLE_BIN1 > delete`.

Remove Compilation Warnings: 

`Project Properties > C/C++ > Preprocessor > Preprocessor Definitions > Edit > new line > _CRT_SECURE_NO_WARNINGS`.

### Resource Preparation
1. Compile the payload you would like to use, or DLL_Test solution (included), as you would any other DLL ("build" in VS works fine)

2. Follow [this guide](https://www.ired.team/offensive-security/code-injection-process-injection/reflective-shellcode-dll-injection) 
for converting the payload to shellcode.
    * Clone the [sRDI repo](https://github.com/monoxgas/sRDI), 
    Note that you must checkout the sRDI repo to commit `5690685aee6751d0dbcf2c50b6fdd4427c1c9a0a` or it will not function.
    * Open Powershell and navigate to the Powershell directory of the sRDI repo (double check that you're checked out to the correct commit).
    * Move a copy of the compiled .dll file to the Powershell directory (GUI or mv cmd work).
    * Import the conversion module: `Import-Module .\ConvertTo-Shellcode.ps1`
    * Perform the conversion: 
    ```
    $sc = ConvertTo-Shellcode -File DLL_Test.dll -FunctionName "MsgBox" 
    $sc2 = $sc | % { write-output ([System.String]::Format('{0:X2}', $_)) }
    $sc2 -join "" > payload.txt
    ```
    * Paste the contents of the payload.txt file into HxD and save it as a binary (i.e. DLLTest.bin).
    Remember the location of this binary, you will need it for the next step.

3. Once the .dll file has been converted to a shellcode binary follow 
[this guide](https://www.ired.team/offensive-security/code-injection-process-injection/loading-and-executing-shellcode-from-portable-executable-resources) 
for adding it as a resource.
	* Click on `Resource Files` in Solution Explorer and selected `Add > Resource`. (Note that if your project does not have a .rc file you will need to create one)
	* Click `Import` and navigate to wherever you stored the .bin file from Step 2 above.
	* Give the resource a type name; I suggest something simple as you will need to remember it later. Ex "TEST_BIN"
	* The resource file should now show up in your program's resource view
	* Change the arguements of the `FindResourceW()` call in Source.cpp to match the new resource name. If you used the examples above it would be:
      `FindResourceW(NULL, MAKEINTRESOURCEW(IDR_TEST_BIN1), L"TEST_BIN")`

4. Build the updated reflective-guard solution in VS

## Build Instructions

**From Visual Studio:**

From Solution Explorer:

`Build > Build Solution`

The compiled executable(s) should appear in:

`turla\Resources\EPIC\Defense-Evasion\reflective-guard\x64\Release\DLL_Run.exe`

`turla\Resources\EPIC\Defense-Evasion\reflective-guard\x64\Release\Intermediary.dll`


## Execution
The Reflective Guard is intended to execute in the scenario as an embedded resource inside of EPIC's Reflective Injector, which is subsequently embedded in the SimpleDropper executable. Executing either the Injector or SimpleDropper executables will result in it's execution. To execute *just* the Guard DLL and it's embedded resource, spawn an `msedge.exe` process and then run `DLL_Run.exe`. See [here](../../#troubleshooting) if you encounter any issues.

### From Visual Studio

Build the executable from Visual Studio as instructed above

At the top of the VS window click "Local Windows Debugger" or "Start Without Debugging"

### As A Service

Build the executable from Visual Studio as instructed above

From an admin command prompt run:

`sc.exe create [service name] binpath= turla\Resources\EPIC\Defense-Evasion\reflective-guard\x64\Release\DLL_Run.exe type= own start= demand error= normal`

Open Services.exe and start the service with [service name]

### From PsExec

Build the executable from Visual Studio as instructed above

From an admin command prompt run:

`psexec -i -s turla\Resources\EPIC\Defense-Evasion\reflective-guard\x64\Release\DLL_Run.exe`

## Cleanup Instructions

### Logging Enabled

From an admin command prompt run:

`del C:\Users\Public\guard_log.txt`

### As A Service

From an admin command prompt run:

`sc delete [service name]`

## CTI References
1. https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
2. https://securelist.com/the-epic-turla-operation/65545/
