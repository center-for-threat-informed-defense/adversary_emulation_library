'Make copy of wscript.exe in AppData\Local
Dim oFSO, strAppData, wshShell
Set wshShell = CreateObject("Wscript.Shell")
Set oFSO = CreateObject("Scripting.FileSystemObject")
strLocalAppData = wshShell.ExpandEnvironmentStrings( "%LOCALAPPDATA%" ) + "\"
oFSO.CopyFile "C:\Windows\System32\wscript.exe", strLocalAppData