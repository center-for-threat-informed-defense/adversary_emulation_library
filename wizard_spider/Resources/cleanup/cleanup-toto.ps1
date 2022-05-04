taskkill /F /IM rubeus.exe
taskkill /F /IM uxtheme.exe
Remove-Item $env:AppData\rubeus.exe
Remove-Item $env:AppData\uxtheme.exe