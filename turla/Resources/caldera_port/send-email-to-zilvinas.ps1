 # ---------------------------------------------------------------------------
 # send-email-to-zilvinas.ps1 - Authenticates as Egle and sends an email to Zilvinas

 # Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
 # Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

 # http://www.apache.org/licenses/LICENSE-2.0

 # Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 # This project makes use of ATT&CK®
 # ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 
 
 # Usage: ./send-email-to-zilvinas.ps1
 # 
 
 # Revision History:
 
 # --------------------------------------------------------------------------- 

$sender = "Egle"
$senderPassword = "Producer1!"
$receiver = "Zilvinas"
$domain = "nk.local"
$server = "drebule"
$fileData = @'
Zilvinas,

I just checked on the service account. It appears that the account was still active, but the password had expired. I've adjusted the settings for the account, so the password should not expire again.

The new password is: dfsbH%T5RWf3bwq3aeGR$3%

Let me know if this fixes the authentication issue.

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