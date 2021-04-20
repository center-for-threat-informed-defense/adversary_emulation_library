Add-Type -AssemblyName System.Windows.Forms
Add-type -AssemblyName System.Drawing
 
# Path for saved screenshot
$tempfolder = $env:temp
$pth = $tempfolder + "\image.png"
 
# Gather Screen resolution information
$screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
$width = $screen.Width
$height = $screen.Height
$left = $screen.Left
$top = $screen.Top
 
# Create bitmap using the top-left and bottom-right bounds
$bitmap = New-Object System.Drawing.Bitmap $width, $height
 
# Create Graphics object
$graphic = [System.Drawing.Graphics]::FromImage($bitmap)
 
# Capture screen
$graphic.CopyFromScreen($left, $top, 0, 0, $bitmap.Size)
 
# Save to file
$bitmap.Save($pth)