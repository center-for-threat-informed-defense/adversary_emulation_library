<#
	Simple Base64 File Encoder

	Example Usage:
		.\encode-file.ps1 -document sidetwist.exe
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$payload
)

$encodedstring = [Convert]::ToBase64String((Get-Content -path $payload -Encoding Byte))
Write-Host -ForegroundColor Green "[+] Base64-encoded file is:"
Write-Host -ForegroundColor Cyan $encodedstring
