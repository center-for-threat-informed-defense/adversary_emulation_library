# add Judy to RDP group
Write-Host "[i] Giving OZ\judy and OZ\bill RDP rights"
net localgroup "Remote Desktop Users" OZ\judy /add
net localgroup "Remote Desktop Users" OZ\bill /add

# We add judy to the local admin group so she can write
# to C:\Windows\SysWoW64\
net localgroup Administrators /add judy