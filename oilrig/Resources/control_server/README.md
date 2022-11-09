# ATT&CK Evaluations Control Server

This ATT&CK Evaluations Control Server is used to execute behaviors under test during ATT&CK Evaluations.

The Control Server provides features for generating implant stagers, controlling agents, and executing modules.

The Control Server is backed with a REST API to support automation and integration with other tools.

## Usage
This repository is meant to act as a submodule within other adversary emulation or ATT&CK evaluation repositories. To use this control server repository, you may either run the binary as is or reference the entire repository as a submodule.

The control server expects the following folder structure for payloads/uploads:
- File uploads will be stored in the `files` subdirectory of the current working directory of the C2 server. The repository already has this directory available, but you will need to create the folder before running the binary from a different location.
- Payload downloads will be fetched from the `payloads` folder of the parent directory of the C2 server's working location. The repository does not contain this payload directory, since the end user will be responsible for providing the payloads according to their specific use case. Ensure that this folder exists in the parent directory when running the C2 server. For example, if the control server is being run from the `Resources/control_server` directory, the payloads must be placed in `Resources/payloads/` in order for the handlers to successfully serve them. The SideTwist handler in particular expects its payloads to be in a separate `SideTwist` directory under the `payloads` directory (e.g. `Resources/payloads/SideTwist`)

## Build from source

```
go build -o controlServer main.go
```

```
sudo ./controlServer
```

## Test Instructions

```
sudo go test ./...
```
Note: you may need to specify the full path to your golang binary if running under `sudo`.

For example: 
```
sudo /usr/local/go/bin/go test ./...
```

## Usage Examples
1. Enable C2 handlers and adjust configuration values to change IP address and ports to listen on by editing the `config/handler_config.yml` file. 
To enable a handler, set `enabled` to `true`, like below:
```
sidetwist:
  host: 192.168.0.8
  port: 443
  enabled: true
```

To disable a handler, set `enabled` to `false`, like below:
```
sidetwist:
  host: 192.168.0.8
  port: 443
  enabled: false
```

1. Start the control server:

```
sudo ./controlServer
```

Alternatively run direct from source:

```
go run main.go
```

Note: you may need to specify the full path to your golang binary if running under `sudo`.

For example: 
```
sudo /usr/local/go/bin/go run main.go
```


## Installation Dependencies

Install Go version 1.15 or higher.

```
sudo apt-get install golang
```

Run tests from the main repository directory. Go should automatically fetch needed dependencies.

```
sudo go test ./...
```

Note: you may need to specify the full path to your golang binary if running under `sudo`.

For example: 
```
sudo /usr/local/go/bin/go test ./...
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
1. Enable C2 handlers and adjust configuration values to change IP address and ports to listen on by editing the `config/handler_config.yml` file. 
To enable a handler, set `enabled` to `true`, like below:
```
sidetwist:
  host: 192.168.0.8
  port: 443
  enabled: true
```

To disable a handler, set `enabled` to `false`, like below:
```
sidetwist:
  host: 192.168.0.8
  port: 443
  enabled: false
```

1. Start the control server:

```
sudo ./controlServer
```

1. Establish an implant session

Run an implant program of your choice to connect to the C2 (make sure that the corresponding handler was enabled). 

1. Run the client python script to manage implant sessions.

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

# set a bootstrap task for a handler
./evalsC2client.py --set-bootstrap-task <handler> <cmd>

# get current bootstrap task for a handler
./evalsC2client.py --get-bootstrap-task <handler>

# delete current bootstrap task for a handler
./evalsC2client.py --del-bootstrap-task <handler>
```

For specific instructions on tasking a particular implant, reference the appropriate README.

