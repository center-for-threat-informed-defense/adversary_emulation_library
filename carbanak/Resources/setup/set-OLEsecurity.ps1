 # set-OLEsecurity adds a registry key to allow OLE execution in MS Word
# https://support.office.com/en-us/article/packager-activation-in-office-365-desktop-applications-52808039-4a7c-4550-be3a-869dd338d834?NS=WINWORD&Version=90&SysLcid=1033&UiLcid=1033&AppVer=ZWD900&HelpId=93371&ui=en-US&rs=en-US&ad=US

$lowerSecurity = 0
$oleRegistryKey = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\Security"

# get-oleSecurity queries the registry to check if MS Word OLE execution is allowed
function get-oleSecurity{
    Write-Host "[*] Checking MS Word OLE security settings"
    $result = Get-ItemProperty -Path $oleRegistryKey
    if ($result.PackagerPrompt -ne $lowerSecurity){
        Write-Host "[-] MS Word OLE security settings not set"
        return $false
    }
    Write-Host ""
    Write-Host "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
    Write-Host "[+] MS Word OLE security is disabled"
    Write-Host "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
    return $true
}

# set-oleSecurity applies a registry key to allow OLE execution from MS Word
function set-oleSecurity{
    Write-Host "[*] Setting MS Word security to allow OLE execution"
    Set-ItemProperty -Path $oleRegistryKey -Name PackagerPrompt -Value $lowerSecurity
}

# main function
$isSet = get-oleSecurity
if ($isSet -eq $false){
    set-oleSecurity
    get-oleSecurity
}
