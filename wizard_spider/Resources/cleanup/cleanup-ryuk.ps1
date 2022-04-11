Remove-Item -path "C:\Users\Public" -recurse -include "RyukReadMe.txt"
Remove-Item -path "Z:\Users\Public" -recurse -include "RyukReadMe.txt"
Remove-Item "ryuk.exe"

# This two files should already have been removed if you ran the step to the end.
if (Test-Path "kill.bat") {
	Remove-Item "kill.bat"
}
if (Test-Path "window.bat" {
	Remove-Item "window.bat"
}
