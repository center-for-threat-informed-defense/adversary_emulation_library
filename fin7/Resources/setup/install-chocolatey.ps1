# This script installs a Windows package manager, Chocolatey.
# Chocolatey enables command line installation of common programs.
# Reference: https://chocolatey.org/
# Example:
#     choco install googlechrome
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
