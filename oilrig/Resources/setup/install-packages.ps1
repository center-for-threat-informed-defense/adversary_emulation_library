# This script holds the packages necesarry to execute (Only some of these were used on each machine, but having them alll installed should not effect execution)
choco install --confirm microsoft-office-deployment   # Used on theblock to open malicious file macros
choco install --confirm libreoffice-fresh             # Used as a backup on theblock to run malicious file macros
choco install --confirm sql-server-management-studio  # Used to manage SQL Server on both waterfalls and endofroad

# Install SQLCMD - Used on waterfalls for persistant SQL Connection
New-Item -Path "C:\temp" -ItemType Directory
wget -O 'C:\temp\mssql-cmdln-utils.msi' 'https://go.microsoft.com/fwlink/?linkid=2142258'
msiexec.exe mssql-cmdln-utils.msi /quiet

# Non-required Quality of life tools
choco install --confirm vscode                        # Used as a file editor
choco install --confirm microsoft-edge                # Used as alternative to IE

#Reboot computer after all installs to make sure they are all functional
Restart-Computer 