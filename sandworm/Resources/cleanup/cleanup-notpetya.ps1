# clean up ransom note
del C:\README.txt

# delete persistent schtask
schtasks /delete /tn Restart /F

# delete notpetya from disk
del C:\Windows\perfc.dat