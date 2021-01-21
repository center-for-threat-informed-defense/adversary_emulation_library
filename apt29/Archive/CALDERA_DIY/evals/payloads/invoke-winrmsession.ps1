Function Get-RandomName 
{
    param (
        [int]$Length
    )
    $set    = 'abcdefghijklmnopqrstuvwxyz'.ToCharArray()
    $result = ''
    for ($x = 0; $x -lt $Length; $x++) 
    {$result += $set | Get-Random}
    return $result
}
Function Invoke-WinRMSession {
param (
$username,
$Password,
$IPAddress
)
$PSS = ConvertTo-SecureString $password -AsPlainText -Force
$getcreds = new-object system.management.automation.PSCredential $username,$PSS

return (New-PSSession -ComputerName $IPAddress -Credential $getcreds)
}
