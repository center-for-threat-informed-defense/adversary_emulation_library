net stop mssqlserver
net start mssqlserver -m"SQLCMD"
call sqlcmd -Q "IF SUSER_ID ('evals_user') IS NULL CREATE LOGIN evals_user WITH PASSWORD = 'Password1234'"
call sqlcmd -Q "SP_ADDSRVROLEMEMBER evals_user,'SYSADMIN'"
call sqlcmd -Q "use tempdb; create user evals_user from login evals_user"
call sqlcmd -Q "use tempdb; exec SP_ADDROLEMEMBER 'db_owner', 'evals_user'"
netsh advfirewall firewall add rule name="Open Port 1433" dir=in action=allow protocol=TCP localport=1433
REG ADD "HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQLServer" /v "LoginMode" /t REG_DWORD /d 2 /f
net stop mssqlserver && net start mssqlserver