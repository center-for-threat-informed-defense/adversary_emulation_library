# Implant Build Script
The provided script will automatically build SideTwist, VALUEVAULT and RDAT from
a Kali Linux host. The script utilizes MingW to compile SideTwist, golang to
compile VALUEVAULT, and dotnet to compile RDAT.

**NOTE:** RDAT requires an additional DLL to be downloaded and placed in the
/Resources/RDAT directory prior to compilation. Review RDAT's documentation for
instructions on retrieving this DLL.

The script should be run from the current `build_implants` directory.

For installing MingW:
```
sudo apt -y install mingw-w64
sudo apt -y install g++-mingw-w64-x86-64
```

For installing golang:
```
sudo apt install golang-go
```

For installing dotnet:
```
wget https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb
sudo apt-get update && sudo apt-get install -y dotnet-sdk-6.0
```
