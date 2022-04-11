# Exaramel for Windows

What is the purpose of this binary?
How does it work?
What does it do?

## Quick Start

```
# Start your control server on Kali
sudo ./controlServer

# build Exaramel on Windows
make.bat

# run the DLL
rundll32.exe Exaramel-Windows.dll,Start

# catch the shell on your control server
```

## Build Instructions

Run make.bat on Windows.

It will output "Exaramel-Windows.dll" in the Exaramel-Windows folder.

```
cd sandworm\Resources\Exaramel-Windows\
make
```

## Test Instructions


```
cd sandworm\Resources\Exaramel-Windows\
go test -v ./...
````

## Usage Examples

```bash
TBD
```

### Cleanup Instructions

```bash
TBD
```

### CTI Evidence

TBD