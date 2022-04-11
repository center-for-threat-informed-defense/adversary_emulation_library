param($installPath, $toolsPath, $package, $project)

if(!$project) { Return; } # PM

$manager = "DllExport.bat"
Copy-Item "$installPath\\$manager" "$PWD" -Force

$pdir = "$PWD\\packages\\DllExport." + $package.Version
if(!(Test-Path -Path $pdir)) {
    Get-ChildItem -Path $installPath | ForEach-Object {
        if($_.PSIsContainer) {
            # without this some files in subdirs can be copied in root folder: https://github.com/3F/coreclr/blob/4fde65a5695d8d4c2f73959e71fb38357ae02a28/pack.ps1
            $null = New-Item -ItemType Directory -Force -Path ($pdir + '\\' + $_.Name)
        }
        Copy-Item $_.fullname $pdir -Recurse -Force
    }
}

$project.Save($project.FullPath)
Start-Process -FilePath ".\\$manager" -WorkingDirectory "$PWD"