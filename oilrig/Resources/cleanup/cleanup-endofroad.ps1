$SingleFiles = @(
    "C:\ProgramData\VMware\VMware.exe",
    "C:\ProgramData\VMware\",
    "C:\ProgramData\Nt.dat",
    "C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Backup\guest.bmp",
    "C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Backup\guest.bmp.tmp"
)

foreach ($file in $SingleFiles) {
    if (Test-Path $file) {
        Remove-Item -Force $file;
    }
}

Restart-Computer -Force;
