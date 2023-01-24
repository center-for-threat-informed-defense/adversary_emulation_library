Sub Main()
    dim oFso, oShell, oShellEnv, computerName, target, source
    const overwrite = true
    set oFso      = CreateObject("Scripting.FileSystemObject")
    set oShell    = WScript.CreateObject("WScript.Shell")
    set oShellEnv = oShell.Environment("Process")
    computerName  = LCase(oShellEnv("ComputerName"))
    WScript.Echo computerName
end Sub
call Main