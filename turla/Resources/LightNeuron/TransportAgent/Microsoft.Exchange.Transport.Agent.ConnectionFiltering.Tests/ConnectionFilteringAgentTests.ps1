param(
    [string]$sender,
    [string]$senderPassword,
    [string]$receiver,
    [string]$receiverPassword,
    [string]$domain,
    [string]$server
)

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

$exchCredential = New-Object System.Management.Automation.PSCredential("$domain\$sender", $(ConvertTo-SecureString $senderPassword -AsPlainText -Force))
$exchSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$server/PowerShell/" -Authentication Kerberos -Credential $exchCredential
$global:senderExchService = $null
$global:receiverExchService = $null
$senderEmail = $sender + "@" + $domain
$receiverEmail = $receiver + "@" + $domain

#===============================================================================
#   Console Output functions
#===============================================================================

function Write-Failure() {
    param (
        $output_received,
        $output_expected
    )
    Write-Host "-------------------------------------------------"
    Write-Host "Test Failed!!!" -ForegroundColor Red
    Write-Host "-------------------------------------------------"
    Write-Host "[Received Output]:" -ForegroundColor Yellow
    Write-Host $output_received
    Write-Host "-------------------------------------------------"
    Write-Host "[Output Expected]:" -ForegroundColor Yellow
    Write-Host $output_expected
    Write-Host "-------------------------------------------------"
}

function Write-Success() {
    param (
        $description
    )
    Write-Host "[+] $description : Passed!" -ForegroundColor Green
}

function Write-TestInfo() {
    param (
        $message
    )
    Write-Host $message -ForegroundColor Yellow
}

#===============================================================================
#   Setups and Tear Downs
#===============================================================================

function Install-TransportAgent() {
    Write-TestInfo "[+] Copying Transport Agent DLL to Exchange Server $server"
    Copy-Item -Path ..\Microsoft.Exchange.Transport.Agent.ConnectionFiltering\Microsoft.Exchange.Transport.Agent.ConnectionFiltering.dll `
    -Destination "\\$server\C$\Program Files\Microsoft\Exchange Server\v15\bin\Microsoft.Exchange.Transport.Agent.ConnectionFiltering.dll"

    Write-TestInfo "[+] Installing Transport Agent"
    Invoke-Command -Session $exchSession -FilePath msiex_test.ps1

    Invoke-Command -ComputerName $server -ScriptBlock { Restart-Service MSExchangeTransport }

}

function New-ExchService {
    param(
        $user,
        $password
    )

    Write-TestInfo "[+] Creating Exchange Service for $user"

    Import-Module .\Microsoft.Exchange.WebServices.dll
    $Credentials = New-Object Microsoft.Exchange.WebServices.Data.WebCredentials("$user","$password","$domain")
    $exchService = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService
    $exchService.Credentials = $Credentials
    $exchService.Url = "https://$server/EWS/Exchange.asmx"

    return $exchService
}

function Setup {
    Install-TransportAgent
    $global:senderExchService = New-ExchService -user $sender -password $senderPassword
    $global:receiverExchService = New-ExchService -user $receiver -password $receiverPassword
}

function Send-Email {
    $message = New-Object Microsoft.Exchange.WebServices.Data.EmailMessage -ArgumentList $senderExchService
    $message.Subject = "Hello!"
    $message.Body = "Hello there!"
    $message.ToRecipients.Add($receiverEmail)
    $message.Attachments.AddFileAttachment($(Get-Location).ToString() + "\snake2_hat.jpg")
    $message.SendAndSaveCopy()

    # Pause for 3 seconds
    Start-Sleep -Seconds 3
}

function Teardown() {

    Write-TestInfo "[+] Tearing down Transport Agent tests..."

    Invoke-Command -Session $exchSession -FilePath uninstall-transport-agent.ps1

    Remove-PSSession -Session $exchSession

    # clearing up IIS worker processes (w3wp.exe found to hold an open handle to the Microsoft.Exchange.Security.Interop.dll for some reason on install...)
    Invoke-Command -ComputerName $server -ScriptBlock { IISReset /NoForce }

    Invoke-Command -ComputerName $server -ScriptBlock { Stop-Service MSExchangeTransport }

    Remove-Item "\\$server\C$\Program Files\Microsoft\Exchange Server\v15\bin\Microsoft.Exchange.Transport.Agent.ConnectionFiltering.dll"
    Remove-Item "\\$server\C$\Windows\serviceprofiles\networkservice\appdata\Roaming\Microsoft\Windows\msxfer.dat"

    # TODO Replace with Companion DLL
    Remove-Item "\\$server\C$\Program Files\Microsoft\Exchange Server\v15\bin\exdbdata.dll"
    Remove-Item "\\$server\C$\Windows\serviceprofiles\networkservice\appdata\Roaming\Microsoft\Windows\TestIngestDebug"

    Invoke-Command -ComputerName $server -ScriptBlock { Start-Service MSExchangeTransport }

}

#===============================================================================
#   Tests
#===============================================================================

function Invoke-TransportAgentTests {

    Write-TestInfo "===============================================================================`n"
    Write-TestInfo "[Test 1]: Companion DLL Returns 0"
    Write-TestInfo "`n==============================================================================="

    Write-TestInfo "[+] Copying TestIngestStruct (return 0) to $server"
    Copy-Item -Path TestIngestStruct\TestIngestStruct_0.dll -Destination "\\$server\C$\Program Files\Microsoft\Exchange Server\v15\bin\exdbdata.dll"

    $receiverInboxFolder = New-Object Microsoft.Exchange.WebServices.Data.FolderId([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox, "$receiverEmail")
    $receiverInbox = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($receiverExchService,$receiverInboxFolder)
    $originalcount = $receiverInbox.UnreadCount

    Send-Email

    # check that the Transport Agent logged the email
    $line = (Get-Content "\\$server\C$\Windows\serviceprofiles\networkservice\appdata\Roaming\Microsoft\Windows\msxfer.dat")
    Write-TestInfo $line
    $pattern = '(?<=\[).+?(?=\])'
    $maildate = [DateTime][regex]::Matches($line, $pattern).Value
    $timediff = New-TimeSpan -Start $maildate -End $(Get-Date)

    if ($timediff.TotalSeconds -lt 60) {
        Write-Success -description "Logged mail received from $senderEmail"
    } else {
        Write-Failure -output_received $line -output_expected "[date] Received mail item from $senderEmail"
    }

    # check that the receiver received the email
    $receiverInbox = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($receiverExchService,$receiverInboxFolder)
    $newcount = $receiverInbox.UnreadCount

    if ($originalcount -lt $newcount)
    {
        Write-Success -description "Mail to $receiverEmail received successfully"
    }
    else
    {
        Write-Failure -output_received "Original unread emails $originalcount is not less than new unread emails $newcount" `
        -output_expected "`$originalcount < `$newcount"
    }

    # check base64 attachment bytes logged by the TestIngestStruct match
    $testIngestDebug = (Get-Content "\\$server\C$\Windows\serviceprofiles\networkservice\appdata\Roaming\Microsoft\Windows\TestIngestDebug")
    $expectedB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($(Get-Location).ToString() + "\snake2_hat.jpg"))
    $receivedB64 = $testIngestDebug[-1]

    if ($receivedB64 -eq $expectedB64) {
        Write-Success -description "Expected base64 encoded JPG matched TestIngestStruct received and logged bytes"
    }
    else {
        Write-Failure -output_received $receivedB64 -output_expected $expectedB64
    }

    Write-TestInfo "===============================================================================`n"
    Write-TestInfo "[Test 2]: Companion DLL Returns 2"
    Write-TestInfo "`n==============================================================================="

    Invoke-Command -ComputerName $server -ScriptBlock { Stop-Service MSExchangeTransport }

    Write-TestInfo "[+] Copying TestIngestStruct (return 2) to $server"
    Copy-Item -Path TestIngestStruct\TestIngestStruct_2.dll -Destination "\\$server\C$\Program Files\Microsoft\Exchange Server\v15\bin\exdbdata.dll"

    Invoke-Command -ComputerName $server -ScriptBlock { Start-Service MSExchangeTransport }

    $receiverInbox = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($receiverExchService,$receiverInboxFolder)
    $originalcount = $receiverInbox.UnreadCount

    Send-Email

    # check that the receiver did not receive the email
    $receiverInbox = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($receiverExchService,$receiverInboxFolder)
    $newcount = $receiverInbox.UnreadCount

    if ($originalcount -eq $newcount)
    {
        Write-Success -description "Mail to $receiverEmail blocked successfully"
    }
    else
    {
        Write-Failure -output_received "Original unread emails $originalcount is not equal to unread emails $newcount" `
        -output_expected "`$originalcount == `$newcount"
    }

}

Setup
Invoke-TransportAgentTests
Teardown
