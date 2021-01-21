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

$randomvar = (Get-RandomName 5)
New-Variable -Name $randomvar -Scope Global -Value (New-PSSession -ComputerName $IPAddress -Credential $getcreds)
$randomvar = "$"+"$randomvar"
Return "`nSession opened, to run a command do the following:`nInvoke-Command -Session $randomvar -scriptblock {Get-Process} | out-string"

}