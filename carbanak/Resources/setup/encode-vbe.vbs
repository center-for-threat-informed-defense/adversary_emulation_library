' This script encodes a Visual Basic Script file into VBE format
' See link for detailed info about the VBE encode method: 
' http://www.jose.it-berater.org/scripting/scrrun/iscriptencoder_encodescriptfile.htm
'
' Example usage:
'     C:\> cscript.exe <input_file.vbs>
'     C:\> cscript.exe C:\Windows\Temp\test.vbs
'
' VBE script will be written to current working directory


' read input file
inputFile = WScript.Arguments.Item(0)
start = "[i] encoding input file: " + inputFile
WScript.Echo(start)
Set fileSystem = CreateObject("Scripting.FileSystemObject")
Set fileHandle = fileSystem.OpenTextFile(inputFile)
scriptContents = fileHandle.ReadAll
fileHandle.Close

' encode file to VBE format
set encoder = CreateObject("Scripting.Encoder") 
sDest = encoder.EncodeScriptFile(".vbs",scriptContents,0,"VBScript")

' write encoded script to disk
outFile = Left(inputFile, Len(inputFile) - 3) & "vbe"
Set encodedFile = fileSystem.CreateTextFile(outFile) 
encodedFile.Write sDest
encodedFile.Close
complete = "[+] Encoded file written to current working directory: " + outFile
WScript.Echo(complete)