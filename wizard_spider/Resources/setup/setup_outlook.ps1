# remove Outlook prompt when DLL is accessing Outlook via PowerShell.
Write-Host "[i] Supressing OutLook 'allow access' prompt"
New-Item –Path "HKLM:\SOFTWARE\Microsoft\Office\16.0\Outlook" –Name Security
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\16.0\Outlook\Security" -Name "ObjectModelGuard" -Value 2 -PropertyType "DWord"