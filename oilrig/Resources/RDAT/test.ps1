# skip SSL-Validation for websocket communication:
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

if (Test-Path bin\Release\net6.0\win10-x64\publish\RDAT.exe) 
{
    $user = $args[0]
    $password = $args[1]
    $domain = $args[2]
    $server = $args[3]
    $email = $user + "@" + $domain

    Import-Module .\Microsoft.Exchange.WebServices.dll
    $Credentials = New-Object Microsoft.Exchange.WebServices.Data.WebCredentials("$user","$password","$domain")
    $exchService = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService
    $exchService.Credentials = $Credentials
    $exchService.Url = "https://$server/EWS/Exchange.asmx"
    $InboxFolder = New-Object Microsoft.Exchange.WebServices.Data.FolderId([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox, "$email")
    $Inbox = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($exchService,$InboxFolder)

    $originalcount = $Inbox.UnreadCount

    .\bin\Release\net6.0\win10-x64\publish\RDAT.exe --path="README.md" --to="$email" --from="$email" --server="$server" --password="$password" --chunksize="2000"

    # Pause for 3 seconds
    Start-Sleep -Seconds 3

    # Get new count
    $Inbox = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($exchService,$InboxFolder)
    $newcount = $Inbox.UnreadCount

    if ($originalcount -lt $newcount)
    {
        Write-Output "RDAT Test Passed"
    }
    else
    {
        Write-Output "RDAT Test Failed"
    }
}
else
{
    Write-Output "RDAT was not found"
}