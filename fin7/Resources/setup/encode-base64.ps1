param (
    [Parameter(Mandatory=$true)][string]$inFile
 )

$FileName = $inFile
$base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes($FileName))
$base64string