# This sets up a service principal name to allow for rubeus kerberoasting
Write-Host "Setting up Service Principal Name (for kerberoasting)"
setspn -s exchange/oz.local oz.local\vfleming