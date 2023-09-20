# Simple "NotFlash" Executable Dropper

## Overview

This is a "simple" dropper program that combines two needs:

1. Delivery of an executable to a subtle location on the victim machine after they double-click a "NotFlash installer" file.

2. Alteration/addition of registry keys so that the delivered executable runs on the user's next login.

Much of this README is cribbed from the EPIC's Reflective Injector README and may, in the future, be upgraded to fully allow entirety of what is bundled in the dropper to never touch disk. As it is, an executable is placed inside the user's hidden AppData\Local\TEMP directory.

The Registry Key modification is notably of the H_KEY_CURRENT_USER, not H_KEY_LOCAL_MACHINE - the WinLogon trigger requires the same user to log in. The executable is run via the `Shell` Registry Key - on logon, a Command Prompt is opened and will run the dropped executable before running a second exe: explorer.exe. Thus it appears normal login execution resumes and the Desktop is available.

## Set Up

### Prior Assumtions & Requirements

This dropper program needs an existing executable file as a resource. This README assumes that Reflective Injector, or whichever other payload you choose, is already created as an executable file.

### Visual Studio Setup
Ensure that the correct character set is selected: 

`Project Properties > Advanced > Character Set > select No Set`.

Check that the project has a Resource.rc file. If one does not exist create one: 

`right-click project > Add > New Item > Resource > Resource File`.

If one alreadys exists, check that the Resource.rc file has no resources loaded: 

`double-click Resource.rc > drop down menu > right-click IDR_EXAMPLE_BIN1 > delete`.

Remove Compilation Warnings: 

`Project Properties > C/C++ > Preprocessor > Preprocessor Definitions > Edit > new line > _CRT_SECURE_NO_WARNINGS`.

### Resource Preparation

Click on `Resource Files` in Solution Explorer and selected `Add > Resource`.

Click `Import` and navigate to wherever your executable file is located.

Give the resource a type name; I suggest something simple as you will need to remember it later. Ex "SHINY_BOI"

The resource file should now show up in your program's resource view

Change the arguements of the `FindResourceW()` call in Source.cpp to match the new resource name. If you used the examples above it would be:

      `FindResourceW(NULL, MAKEINTRESOURCEW(IDR_SHINY_BOI1), L"SHINY_BOI")`

## Build Instructions

**From Visual Studio**

From Solution Explorer:

`Build > Build Solution`

The compiled executable should appear in:

`turla\Resources\EPIC\SimpleDropper\x64\Release\SimpleDropper.exe`

## Execution
To execute the SimpleDropper, run the compiled executable `SimpleDropper.exe`. If the Reflective Injector and Reflective Guard are embedded, ensure you have the explorer.exe and msedge.exe processes running. See [here](../../#troubleshooting) if you encounter any issues.

### From Visual Studio

Build the executable from Visual Studio as instructed above.

At the top of the VS window click "Local Windows Debugger" or "Start Without Debugging"

### Test Instructions 

Much of the following is noted in the code in comments:

Testing the SimpleDropper to ensure that it delivers a working exe is tricky, as it is reasonable that you want to make sure your embedded exe works, but you don't want to hijack your own machine.

When testing, you really only need to see that you are able to modify a registry key to run *an executable of your choice* on startup.

So, test your executable separately, and then test the dropper by simply running the dropper itself on startup. To test:

1. Compile *and run* SimpleDropper (you need to run it to change the registry.)
2. Take the compiled SimpleDropper executable and place it on your desktop, or whichever other place you assign to the exe_location variable.
3. Delete your newly-dropped injector exe, which is located in your local AppData\Local\Temp folder until further updates
4. Log out and back in again.

SimpleDropper should run (again) on startup, depositing an executable file in the same place. If your deleted injector reappears, your dropper is working. Comment out the test-assignment of exe_location and uncomment the release-assignment (should be right below in the code, setting exe_location equal to `full_path`, the path to the embedded exe you just dropped in AppData\Local\Temp. Thus, instead of running itself on startup, someone who double-clicks the SimpleDropper will run an executable of your choice on startup)

## Cleanup Instructions

* Restore the Winlogon key altered at the executing user's `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` so that only 'C:\Windows\explorer.exe' is run on login
* Remove the EPIC injector executable in the executing user's *AppData\Local\Temp* directory: '`%TEMP%\mxs_installer.exe`
* Cleanup the embedded artifacts ([Guard](../../Defense-Evasion/reflective-guard/reflective-guard#cleanup-instructions)/[Payload](../../payload#cleanup-instructions))

## CTI / References

1. https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
2. https://securelist.com/the-epic-turla-operation/65545/
3. https://stackoverflow.com/questions/71073166/how-to-embed-an-exe-file-into-another-exe-file-as-a-resource-in-c