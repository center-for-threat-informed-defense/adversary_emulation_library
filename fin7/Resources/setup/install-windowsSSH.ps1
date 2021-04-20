# This script install OpenSSH Server for Windows

# Install OpenSSH on Windows
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start the SSH server
Start-Service sshd

# Execute SSH server at startup
Set-Service -Name sshd -StartupType 'Automatic'
