 # ---------------------------------------------------------------------------
 # send-email-to-egle.ps1 - Authenticates as Zilvinas and sends an email to Egle

 # Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
 # Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

 # http://www.apache.org/licenses/LICENSE-2.0

 # Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 # This project makes use of ATT&CK®
 # ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 
 
 # Usage: ./send-email-to-egle.ps1
 # 
 
 # Revision History:
 
 # --------------------------------------------------------------------------- 

$sender = "Zilvinas"
$senderPassword = "Producer2!"
$receiver = "Egle"
$domain = "nk.local"
$server = "drebule"
$fileData = @'
Hi Egle,
After our meeting earlier I spoke with Tenko about the SAP integration issue that was preventing the users from logging in. I did a little digging and noticed there is an authentication error on the SAP server.

When you get a few minutes could you check to make sure the service account is still active and the credentials have not expired? The account name is SVC_SAP2.
'@


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

function Write-TestInfo() {
    param (
        $message
    )
    Write-Host $message -ForegroundColor Yellow
}


#===============================================================================
#   Setups and Tear Downs
#===============================================================================


$exchCredential = New-Object System.Management.Automation.PSCredential("$domain\$sender", $(ConvertTo-SecureString $senderPassword -AsPlainText -Force))
$exchSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$server/PowerShell/" -Authentication Kerberos -Credential $exchCredential
$global:senderExchService = $null
$senderEmail = $sender + "@" + $domain
$receiverEmail = $receiver + "@" + $domain

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
    $global:senderExchService = New-ExchService -user $sender -password $senderPassword
}

function Send-Email {
    Write-TestInfo "[+] Sending email"
    $message = New-Object Microsoft.Exchange.WebServices.Data.EmailMessage -ArgumentList $senderExchService
    $message.Subject = "Hello!"
    $message.Body = $fileData
    $message.ToRecipients.Add($receiverEmail)
    $message.SendAndSaveCopy()

    # Pause for 3 seconds
    Start-Sleep -Seconds 3
}

Setup
Send-Email