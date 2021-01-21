function wmi {
	
	$FilterArgs = @{name='WindowsParentalControlMigration';
                EventNameSpace='root\CimV2';
                QueryLanguage="WQL";
                Query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LoggedOnUser' AND TargetInstance.__RELPATH like '%$($env:UserName)%'";}
	$Filter=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs

	$ConsumerArgs = @{name='WindowsParentalControlMigration';
                CommandLineTemplate="";}
	$Consumer=New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs

	$FilterToConsumerArgs = @{
		Filter = [Ref] $Filter
		Consumer = [Ref] $Consumer
	}
	$FilterToConsumerBinding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $FilterToConsumerArgs
}