# ATT&CK Evaluations Emotet Handler

The ATT&CK Evaluations Emotet Handler is used to handle communications between the Emotet Client and control server via a REST API. 

The Emotet Handler provides features to communicate with the Emotet Client and forwarding control information to the Control Server.

The Emotet Handler must be run as root because it needs to bind to standard port 80. Optionally, you can start it with a different port and IP address by giving it command line params.

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

sudo go test -v ./emotet
```

Look at the go.mod file if you want to see the dependencies in detail.

### Run Tests

```
cd wizard_spider/Resources/control_server/handlers/emotet/
sudo go test ./...
```

### Go Build
```
cd wizard_spider/Resources/control_server/
go build main.go
```

### Example usage
View functions from emotet_test.go for an example on how to interact with the control server