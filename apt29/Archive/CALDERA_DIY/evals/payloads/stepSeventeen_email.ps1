function psemail {
	Add-type -assembly "Microsoft.Office.Interop.Outlook" | out-null
	$olFolders = "Microsoft.Office.Interop.Outlook.olDefaultFolders" -as [type]
	$outlook = new-object -comobject outlook.application
	$namespace = $outlook.GetNameSpace("MAPI")
	$folder = $namespace.getDefaultFolder($olFolders::olFolderInBox)
	$folder.items | Select-Object -Property Subject, ReceivedTime, SenderName, Body
}