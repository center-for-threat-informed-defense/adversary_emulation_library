# create domain user
Write-Host "[i] Creating domain users"
net user /add /domain judy Passw0rd!
net user /domain judy /EXPIRES:NEVER

net user /add /domain bill Fall2021
net user /domain bill /EXPIRES:NEVER

net user /add /domain vendor-da ChangeMe!2 /LOGONPASSWORDCHG:YES
net user /domain vendor-da /EXPIRES:NEVER

net user /add /domain evals-team-da Attack123!
net user /domain evals-team-da /EXPIRES:NEVER