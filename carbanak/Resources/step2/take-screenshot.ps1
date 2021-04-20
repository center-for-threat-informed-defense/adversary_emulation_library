# Originally named screenshot__.ps1
# Takes screenshot and creates screenshot__.png in script directory
$ErrorActionPreference="stop";

function screenshot([Drawing.Rectangle]$bounds, $path){ 
    $bmp = New-Object System.Drawing.Bitmap($bounds.width, $bounds.height)
    $graphics = [Drawing.Graphics]::FromImage($bmp)
    $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size)
    $bmp.Save($path)
    $graphics.Dispose()
    $bmp.Dispose()
}

try{ 
    [Reflection.Assembly]::LoadWithPartialName("System.Drawing")
    $ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
    $pth = $ScriptDir + "\screenshot__.png"
    $bounds = [Drawing.Rectangle]::FromLTRB(0, 0, 1500, 1000)
    screenshot $bounds $pth;
} catch{
} 
