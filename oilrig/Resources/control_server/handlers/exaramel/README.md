# ATT&CK Evaluations Exaramel for Linux Handler

The ATT&CK Evaluations Exaramel for Linux handler is used to handle communications between the ATT&CK Evaluations Exaramel for Linux client and the Control Server via a REST API.

This handler uses Task IDs to maintain state regarding the tasks that are sent to the client and the responses that are returned. It serves only HTTPS communications.

This handler must be run as root as it is intended to bind to port 443.

## Usage

This handler is automatically loaded by the control server when the control server is started.

### Tasking Commands

Task commands to the Exaramel for Linux client using [`evalsC2Client.py`](../../evalsC2Client.py):
```
wizard_spider/Resources/control_server/evalsC2Client.py --set-task <exaramel-guid> <command>
```

Note: The ATT&CK Evaluations version of Exaramel for Linux uses a static GUID of: `exaramel-implant`.

Commands that can be provided to the implant:

    Set persistence:
        persist [cron|systemd]
    
    Execute a shell command:
        exec <shell_command>

    Download a file from the target:
        get <file_on_target> <filename_to_save_as>

    Upload file to target:
        put <file_to_upload> <filepath_on_target_to_upload_to>

## Run Tests

Install Go version 1.15 or higher.

```
sudo apt-get install golang
```

Enter the control server directory, and run Exaramel for Linux tests. Go will automatically fetch dependencies.

```
cd wizard_spider/Resources/handlers/exaramel
sudo go test -v ./...
```

## Install Dependencies

Dependencies will be automatically installed by Go when running the tests.

The `go.mod` file contains detailed information on the dependencies.
