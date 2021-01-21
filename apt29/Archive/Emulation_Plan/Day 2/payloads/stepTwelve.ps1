function detectav {
	$AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct

    $ret = @()
    foreach($AntiVirusProduct in $AntiVirusProducts){

        #Create hash-table for each computer
        $ht = @{}
        $ht.Name = $AntiVirusProduct.displayName
        $ht.'Product GUID' = $AntiVirusProduct.instanceGuid
        $ht.'Product Executable' = $AntiVirusProduct.pathToSignedProductExe
        $ht.'Reporting Exe' = $AntiVirusProduct.pathToSignedReportingExe
		$ht.'Timestamp' = $AntiVirusProduct.timestamp


        #Create a new object for each computer
        $ret += New-Object -TypeName PSObject -Property $ht 
    }
    Return $ret
} 
function software {
	$comp = $env:ComputerName
	$keys = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                   "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
	$type = [Microsoft.Win32.RegistryHive]::LocalMachine
	$regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($type, $comp)
	$ret = ""
	foreach ($key in $keys) {
		$a = $regKey.OpenSubKey($key)
		$subkeyNames = $a.GetSubKeyNames()
		foreach($subkeyName in $subkeyNames) {
                    $productKey = $a.OpenSubKey($subkeyName)
                    $productName = $productKey.GetValue("DisplayName")
                    $productVersion = $productKey.GetValue("DisplayVersion")
                    $productComments = $productKey.GetValue("Comments")
					$out = $productName + " | " + $productVersion + " | " + $productComments + "`n"
					$ret += $out
		}
	}
	Return $ret
}