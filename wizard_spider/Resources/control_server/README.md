# ATT&CK Evaluations Control Server

This ATT&CK Evaluations Control Server is used to execute behaviors under test during ATT&CK Evaluations.

The Control Server provides features for generating implant stagers, controlling agents, and executing modules.

The Control Server is backed with a REST API to support automation and integration with other tools.

## Build from source

```
go build -o controlServer main.go
```

```
./controlServer
```

## Test Instructions

```
go test ./...
```

## Usage Examples

1. Start the control server:

```
./controlServer
```

Alternatively run direct from source:

```
go run main.go
```


## Installation Dependencies

Install Go version 1.15 or higher.

```
sudo apt-get install golang
```

Enter the control server directory, and then run tests. Go should automatically fetch needed dependencies.

```
cd wizard_spider/Resources/control_server

go test ./...
```

Look at the go.mod file if you want to see the dependencies in detail.

# ATT&CK Evaluations C2 Client

This client is provided to interact with the C2 server via its REST API.

## Build Instructions

Install dependencies using pip3:

```
pip3 install -r requirements.txt
```

## Test Instructions

```
To Do - need to write unit tests
```

## Usage Examples

1. Start the control server:

```
./controlServer
```

2. Establish an implant session

```
TBD - for now, just use the dummy session provided by
default in controlServer
```

3. Run the client

```
# view help
./evalsC2client.py --help

# list sessions; pay attention to session guids
./evalsC2client.py --get-sessions

# get detailed info for a session
./evalsC2client.py --get-session <guid>

# delete a session
./evalsC2client.py --del-session <guid>

# set session task
./evalsC2client.py --set-task <guid> <cmd>

# get session task
./evalsC2client.py --get-task <guid>

# delete session task
./evalsC2client.py --del-task <guid>

# get task output
./evalsC2client.py --get-output <guid>

```
