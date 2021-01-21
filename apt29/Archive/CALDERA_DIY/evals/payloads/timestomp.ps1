function timestomp {
	[CmdletBinding()] param (
		[string] $dest
	)
	$source = (gci ((gci env:windir).Value + '\system32') | ? { !$_.PSIsContainer } | Where-Object { $_.LastWriteTime -lt $(get-date -format "MM/dd/yyyy") } | Get-Random | %{ $_.FullName })
	[IO.File]::SetCreationTime($dest, [IO.File]::GetCreationTime($source))
	[IO.File]::SetLastAccessTime($dest, [IO.File]::GetLastAccessTime($source))
	[IO.File]::SetLastWriteTime($dest, [IO.File]::GetLastWriteTime($source))
}
