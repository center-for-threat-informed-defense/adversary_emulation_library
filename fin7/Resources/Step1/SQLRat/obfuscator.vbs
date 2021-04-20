'VBS Obfuscator by st0le

Randomize
set fso = CreateObject("Scripting.FileSystemObject")
fileName = Inputbox("Enter Path of the File to scramble : ")
set src = fso.OpenTextfile(fileName,1)
body = src.readall
set rep  = fso.createtextfile("Obfuscated.vbs",true)
rep.writeline "Execute(" & Obfuscate(body) & " ) "

Function Obfuscate(txt)
enc = ""
for i = 1 to len(txt)
enc = enc & "chr( " & form( asc(mid(txt,i,1)) ) & " ) & "
next
Obfuscate = enc & " vbcrlf "
End Function


Function form(n)

r = int(rnd * 10000)
k = int(rnd * 3)
if( k = 0) then ret = (r+n) & "-" & r
if( k = 1) then ret = (n-r) & "+" & r
if( k = 2) then ret = (n*r) & "/" & r
form = ret
End Function