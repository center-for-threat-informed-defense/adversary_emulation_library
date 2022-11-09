$SingleFiles = @(
    "C:\Program Files\Microsoft\Exchange Server\V15\ClientAccess\exchweb\ews\contact.aspx",
    "C:\Windows\System32\m64.exe",
    "C:\Windows\Temp\01.txt",
    "C:\Windows\System32\ps.exe",
    "C:\Windows\temp\Nt.dat",
    "C:\Windows\System32\mom64.exe"
)

foreach ($file in $SingleFiles) {
    if (Test-Path $file) {
        Remove-Item -Force $file;
    }
}

Restart-Computer -Force;
