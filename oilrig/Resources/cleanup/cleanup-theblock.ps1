schtasks.exe /delete /tn "SystemFailureReporter";

$SingleFiles = @(
    "C:\Users\gosta\AppData\Local\SystemFailureReporter\update.xml",
    "C:\Users\gosta\AppData\Local\SystemFailureReporter\SystemFailureReporter.exe",
    "C:\users\gosta\AppData\Local\SystemFailureReporter\b.doc",
    "C:\users\gosta\AppData\Local\SystemFailureReporter\",
    "C:\users\gosta\Downloads\Marketing_Material.zip",
    "C:\users\gosta\Downloads\GGMS Overview.doc",
    "C:\users\gosta\AppData\Roaming\b.exe",
    "C:\users\gosta\AppData\Roaming\fsociety.dat",
    "C:\Users\Public\Downloads\plink.exe",
    "C:\Users\Public\contact.aspx"
)

foreach ($file in $SingleFiles) {
    if (Test-Path $file) {
        Remove-Item -Force $file;
    }
}

Restart-Computer -Force;
