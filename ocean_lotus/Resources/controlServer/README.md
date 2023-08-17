# ATT&CK Evaluations Control Server

This ATT&CK Evaluations Control Server is used to execute behaviors under test during ATT&CK Evaluations.

The Control Server provides features for generating implant stagers, controlling agents, and executing modules.

The Control Server is backed with a REST API to support automation and integration with other tools.

## Usage
This repository is meant to act as a submodule within other adversary emulation or ATT&CK evaluation repositories. To use this control server repository, you may either run the binary as is or reference the entire repository as a submodule.

The control server expects the following folder structure for payloads/uploads:
- File uploads will be stored in the `files` subdirectory of the current working directory of the C2 server. The repository already has this directory available, but you will need to create the folder before running the binary from a different location.
- Payload downloads will be fetched from the `payloads` folder of the parent directory of the C2 server's working location. The repository does not contain this payload directory, since the end user will be responsible for providing the payloads according to their specific use case. Ensure that this folder exists in the parent directory when running the C2 server. For example, if the control server is being run from the `Resources/control_server` directory, the payloads must be placed in `Resources/payloads/` in order for the handlers to successfully serve them. The SideTwist handler in particular expects its payloads to be in a separate `SideTwist` directory under the `payloads` directory (e.g. `Resources/payloads/SideTwist`)

## Usage
1. Build the binary from source
    ```
    go build -o controlServer main.go
    ```
    
1. Execute the binary
    ```
    sudo ./controlServer
    ```
    
1. Establish an implant session - Run an implant program of your choice (on a victim machine) to connect to the C2. Ensure the corresponding handler is enabled described in the [configuration](##Configuration). 

1. Use the client python script ([evalsC2client.py](../control_server/evalsC2client.py)) to interact with the implant sessions. Use the implant's `README.md` for further information on how to interact with the implant. 

Example commands often but not always implemented
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

## Configuration

1.  Navigate to the `config/handler_config.yml` [file](../control_server/config/handler_config.yml). Each implant (usually) has a corrosponding listener with the same name. Locate the listener with the implant name in the file. 
1.  Enable the C2 handler and adjust configuration values to match your enviornment.
     - Change the IP address
     - Change the port
     - Enable the handler. Set the `enabled` field to `true` in the `config/handler_config.yml` file.
       ```
        oceanlotus:
          host: 123.456.7.8
          port: 443
          enabled: true
       ```
    - Disable handlers not in use. Set the `enabled` field to `false` in the `config/handler_config.yml` file.
        ```
        sidetwist:
          host: 123.456.7.8
          port: 443
          enabled: false
        ```

1. Start the control server

    ```
    sudo ./controlServer
    ```
    An alternative way to execute the C2 Server
        
    Run direct from source
    ```
    go run main.go
    ```

        
    Note: you may need to specify the full path to your golang binary if running under `sudo`.
    
    For example: 
    ```
    sudo /usr/local/go/bin/go run main.go
    ```


## Dependencies

On the attacker host, the following needs to be installed. 

1. Go version 1.15 or higher. This is used to build and execute the C2 server. 

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

    Review the (go.mod)[/control_server/go.mod] file to view the dependencies in detail.
  
1. ATT&CK Evaluations C2 Client. The client interacts with the C2 server via it's REST API.
    ```
    pip3 install -r requirements.txt
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


