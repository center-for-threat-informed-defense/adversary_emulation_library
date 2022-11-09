# VALUEVAULT

VALUEVAULT is a Golang compiled version of the “Windows Vault Password Dumper” browser credential theft tool from Massimiliano Montoro, the developer of Cain & Abel.[1]

## Quick Start

```
# build VALUEVAULT on Windows
go build -mod vendor -trimpath -o b.exe -a main.go

# copy binary to Resources\payloads\SideTwist
copy b.exe ..\Resources\payloads\SideTwist

# run the executable
./b.exe
```

## Build Instructions

### Windows

```
go build -mod vendor -trimpath -o b.exe -a main.go
```

## Test Instructions

To run `vault` unit tests:

```
# from the Resources\VALUEVAULT directory

go test vault -a -v
```

To run `db` unit tests:

```
# from the Resources\VALUEVAULT directory

go test db -a -v
```

## Seed Credentials in Internet Explorer
Open Internet Explorer
OWA credentials:
```
1. Enter https://10.1.0.6/owa/auth/logon.aspx in address bar
2. Bypass certificate errors
3. Enter account credentials
4. A small prompt will appear on the bottom of the page prompting to save the credentials
5. Save credentials
```

## Usage Examples

Will create SQLite database with output of Windows Credential Value for Internet Explorer

Execute:
```
./b.exe
```

Output:
```
{homedir}\{username}\AppData\Roaming\fsociety.dat or %AppData%
```

Database layout:
```
logins(
    	origin_url VARCHAR NOT NULL,
        username_value VARCHAR,
        password VARCHAR
      )
```

### Cleanup Instructions

```
Remove {homedir}\{username}\AppData\Roaming\fsociety.dat
Remove b.exe
```

### Read DB contents
Requires Python3
```
cd .\read-db
python3 -m venv env
env/Scripts/activate.bat
pip3 install -r requirements.txt
python3 .\read-db.py
```

### CTI Evidence

[1] https://www.mandiant.com/resources/hard-pass-declining-apt34-invite-to-join-their-professional-network

### References
- http://web.archive.org/web/20190316025511/http://oxid.it/downloads/vaultdump.txt
- https://github.com/danieljoos/winvault
- https://github.com/google/uuid
- https://github.com/mattn/go-sqlite3
- https://pkg.go.dev/golang.org/x/sys