# ATT&CK Evaluations TrickBot Handler

The ATT&CK Evaluations TrickBot Handler is used to handle communications between the Trickbot Client and control server via a REST API. 

The TrickBot Handler provides features to communicate with the Trickbot Client and forwarding control information to the Control Server.

The Trickbot Handler must be run as root because it needs to bind to a standard port.

## Build from source

go build main.go

### Install dependencies

Install Go version 1.15 or higher.

```
sudo apt-get install golang
```

Enter the control server directory, and then run tests. Go should automatically fetch needed dependencies.

```
cd wizard_spider/Resources/handlers/

sudo go test -v ./trickbot
```

Look at the go.mod file if you want to see the dependencies in detail.

### Run Tests

```
cd wizard_spider/Resources/control_server/handlers/trickbot/
sudo go test ./...
```

### Go Build
```
cd wizard_spider/Resources/control_server/
go build main.go
```
### Registration Example

On server:
```
cd wizard_spider/Resources/control_server/
sudo ./main
```

On client or another server shell:
```
 curl {hostip}:447/camp1/DMIN_W617601.HATGSF1265TRQIKSH54367FSGDHUIA11/0/Windows7x64/1234/0.0.0.0/GAVHSGFD12345ATGSHBDSAFSGTAGSBHSGFSDATQ12345AGSFSGBDISHJKAGS2343/C:/1111/2222/HAGSTGST123
```

### Get Task Example
On client or another server shell:
```
curl {hostip}:447/camp1/DMIN_W617601.HATGSF1265TRQIKSH54367FSGDHUIA11/80/HAGSTGST123
```

### Post Task Output Example

On client or another server shell:
```
curl {hostip}:447/camp1/DMIN_W617601.HATGSF1265TRQIKSH54367FSGDHUIA11/10/cmd/messageouput/HAGSTGST123 
```