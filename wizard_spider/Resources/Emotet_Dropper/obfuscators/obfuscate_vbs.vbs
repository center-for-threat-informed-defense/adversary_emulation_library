'=============================================================================================
'
'       file_name:  drop_emotet_stage1.script_contents
'
'    Description:  This script, based on DoctorLai's script_contentscript_Obfuscator project,
'                  obfuscates a script_contents file replacing all characters with non human readable
'                  symbols.
'   
'        Version:  1.0
'        Created:  March 1st, 2021
'
'      Author(s):  Michael C. Long II
'   Organization:  MITRE Engenuity
'
'  References(s): https://github.com/DoctorLai/script_contentscript_Obfuscator
'
'=============================================================================================

Option Explicit

Function script_contents_obfuscator(n)
	Dim r, k
	r = Round(Rnd() * 10000) + 1
	k = Round(Rnd() * 2) + 1
	Select Case k
		Case 0
			script_contents_obfuscator = "CLng(&H" & Hex(r + n) & ")-" & r
		Case 1
			script_contents_obfuscator = (n - r) & "+CLng(&H" & Hex(r) & ")"
		Case Else
			script_contents_obfuscator = (n * r) & "/CLng(&H" & Hex(r) & ")"
	End Select			
End Function

Function Obfuscator(script_contents)
	Dim length, s, i
	length = Len(script_contents)
	s = ""
	For i = 1 To length
		s = s & "chr(" & script_contents_obfuscator(Asc(Mid(script_contents, i))) + ")&"
	Next
	s = s & "vbCrlf"
	Obfuscator = "Execute " & s
End Function


function Main()

	If WScript.Arguments.Count = 0 Then
		WScript.Echo "Missing parameter(s): script_contentscript source file(s)"
		WScript.Quit
	End If

	Dim file_system
	Set file_system = CreateObject("Scripting.FileSystemObject")

	Dim file_name
	file_name = WScript.Arguments(0)

	Const read_mode = 1

	Dim source_file
	Set source_file = file_system.OpenTextFile(file_name, read_mode)

	Dim dest_file
	Set dest_file = file_system.CreateTextFile("obfuscated_emotet_dropper.vbs",true)

	Dim script_contents
	script_contents = source_file.ReadAll	

	dest_file.write(Obfuscator(script_contents))
	
	source_file.Close
	dest_file.close()

	WScript.Echo "[+] File written in current working directory: 'obfuscated_emotet_dropper.vbs'"
	
	Set file_system = Nothing
End Function

Main()