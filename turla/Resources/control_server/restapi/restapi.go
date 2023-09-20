package restapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/display"
	"attackevals.mitre-engenuity.org/control_server/handlers/util"
	"attackevals.mitre-engenuity.org/control_server/logger"
	restapi_util "attackevals.mitre-engenuity.org/control_server/restapi/util"
	"attackevals.mitre-engenuity.org/control_server/sessions"
	"attackevals.mitre-engenuity.org/control_server/tasks"
	"github.com/gorilla/mux"
)

var Server *http.Server

const VERSION_STR = "ATT&CK Evaluations Control Server 1.0"

var CalderaForwardingEndpoint string

// Start enables the REST API server
func Start(listenAddress, payloadDir string) {
	r := mux.NewRouter()
	r.HandleFunc("/api/v1.0/version", GetVersion).Methods("GET")
	r.HandleFunc("/api/v1.0/config", GetConfig).Methods("GET")
	r.HandleFunc("/api/v1.0/sessions", GetSessions).Methods("GET")
	r.HandleFunc("/api/v1.0/session", CreateSession).Methods("POST")
	r.HandleFunc("/api/v1.0/session/{guid}", GetSessionByGuid).Methods("GET")
	r.HandleFunc("/api/v1.0/session/exists/{guid}", SessionExists)
	r.HandleFunc("/api/v1.0/session/delete/{guid}", RemoveSession).Methods("DELETE")
	r.HandleFunc("/api/v1.0/session/{guid}/task", GetTaskCommandBySessionId).Methods("GET")
	r.HandleFunc("/api/v1.0/session/{guid}/task", SetTaskBySessionId).Methods("POST")
	r.HandleFunc("/api/v1.0/session/{guid}/task", RemoveTaskBySessionId).Methods("DELETE")
	r.HandleFunc("/api/v1.0/bootstraptask/{handler}", GetBootstrapTask).Methods("GET")
	r.HandleFunc("/api/v1.0/bootstraptask/{handler}", SetBootstrapTask).Methods("POST")
	r.HandleFunc("/api/v1.0/bootstraptask/{handler}", RemoveBootstrapTask).Methods("DELETE")
	r.HandleFunc("/api/v1.0/session/{guid}/task/output", GetTaskOutputBySessionId).Methods("GET")
	r.HandleFunc("/api/v1.0/session/{guid}/task/output", SetTaskOutputBySessionId).Methods("POST")
	r.HandleFunc("/api/v1.0/session/{guid}/task/output", RemoveTaskOutputBySessionId).Methods("DELETE")
	r.HandleFunc("/api/v1.0/upload/{file}", UploadFile).Methods("POST")
	r.HandleFunc("/api/v1.0/task/{guid}", GetTask).Methods("GET")
	r.HandleFunc("/api/v1.0/task/output/{guid}", GetTaskOutput).Methods("GET")
	r.HandleFunc("/api/v1.0/task/output/{guid}", SetTaskOutput).Methods("POST")
	r.HandleFunc("/api/v1.0/task/output/{guid}", RemoveTaskOutput).Methods("DELETE")
	r.HandleFunc("/api/v1.0/forwarder/session/{guid}", ForwardSessionBeacon).Methods("POST")

	// serve files located in specified payload directory
	r.PathPrefix("/api/v1.0/files/").Handler(http.StripPrefix("/api/v1.0/files/", http.FileServer(http.Dir(payloadDir))))

	Server = &http.Server{
		Addr:         listenAddress,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r,
	}
	
	// set CALDERA forwarding endpoint
	CalderaForwardingEndpoint = config.GetRestAPICalderaForwardingAddress() + "/beacons"
	
	// start rest api in goroutine so it doesn't block
	go func() {
		err := Server.ListenAndServe()
		if err != nil && err.Error() != "http: Server closed" {

			if strings.Contains(err.Error(), fmt.Sprintf("listen tcp %s: bind: address already in use", listenAddress)) {
				logger.Warning(err)
				return
			} else {
				logger.Error(err)
			}
		}
	}()
}

// Stop disables the REST API server
func Stop() {
	emptyContext := context.Background()
	err := Server.Shutdown(emptyContext)
	if err != nil {
		logger.Error(fmt.Sprintf("REST server failed to shut down: %s", err.Error()))
	}
}

// GetVersion returns the current application version
func GetVersion(w http.ResponseWriter, r *http.Request) {
    logger.Debug("Responding to GetVersion API request.")
    resp := restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_VERSION, restapi_util.RESP_STATUS_SUCCESS, VERSION_STR)
    logger.Debug(fmt.Sprintf("GetVersion response:\n%s", string(resp)))
    w.Write(resp)
}

// GetConfig returns the current server configuration
func GetConfig(w http.ResponseWriter, r *http.Request) {
    resp := restapi_util.CreateConfigResponseJSON(restapi_util.RESP_STATUS_SUCCESS, config.RestAPIConfig)
    w.Write(resp)
}

// GetStagers returns a list of files that are used to stage implants on target
// for example, droppers, download-exec 1-liners, etc.
func GetStagers() error {
	return errors.New("not implemented")
}

// GetStagerOptions returns detailed information and options for a given stager
func GetStagerOptions() error {
	return errors.New("not implemented")
}

// SetStager returns a stager configured with options specified by the user
func SetStager() error {
	return errors.New("not implemented")
}

// CreateSession registers a new C2 session to the control server
func CreateSession(w http.ResponseWriter, r *http.Request) {
	// read POST request body from client
	req, err := ioutil.ReadAll(r.Body)
	if err != nil {
	    logger.Error(fmt.Sprintf("CreateSession: %s", err.Error()))
	    w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}

	// convert JSON data into a session struct
	var session sessions.Session
	err = json.Unmarshal(req, &session)
	if err != nil {
		logger.Error(fmt.Sprintf("CreateSession: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}
	// pass session struct to handler
	err = sessions.AddSession(session)
	if err != nil {
		logger.Error(fmt.Sprintf("CreateSession: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}
	// send success message to client
	w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_SUCCESS, "Successfully added session."))

	// log new session
	display.PrintSession(session)
}

// GetSessions returns a list of all current C2 sessions
func GetSessions(w http.ResponseWriter, r *http.Request) {
	sessionList := sessions.GetSessionList()

	// send session list to client
	resp := restapi_util.CreateSessionsResponseJSON(restapi_util.RESP_STATUS_SUCCESS, sessionList)
    w.Write(resp)

	// log display session list
	display.PrintSessionList(sessionList)
}

// GetSessionByGuid returns detailed info for the specified session
func GetSessionByGuid(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid := vars["guid"]
	retSession, err := sessions.GetSessionByGuid(guid)
	if err != nil {
		logger.Error(fmt.Sprintf("GetSessionByGuid: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}
	
	// send session list to client - will contain 1 element
	resp := restapi_util.CreateSessionsResponseJSON(restapi_util.RESP_STATUS_SUCCESS, []sessions.Session{retSession})
    w.Write(resp)
}

// SessionExists returns boolean true if the GUID exists
func SessionExists(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid := vars["guid"]
	exists, _ := sessions.SessionExists(guid)
	w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_SUCCESS, strconv.FormatBool(exists)))
	logger.Info(fmt.Sprintf("Checking UUID %s exists: %t", guid, exists))
}

// RemoveSession terminates the specified C2 session
func RemoveSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid := vars["guid"]
	err := sessions.RemoveSession(guid)
	if err != nil {
		logger.Error(fmt.Sprintf("RemoveSession: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}
	message := fmt.Sprintf("Successfully removed session: %s", guid)
	w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_SUCCESS, message))
	logger.Success(message)
}

// SetTaskBySessionId allows users to issue commands to the specified session
func SetTaskBySessionId(w http.ResponseWriter, r *http.Request) {
    logger.Info("Received SetTaskBySessionId request")
    vars := mux.Vars(r)
    sessionGuid := vars["guid"]
    // Returns header value if provided, empty string otherwise
    taskGuid := r.Header.Get("X-Task-Guid")
    req, err := ioutil.ReadAll(r.Body)
    if err != nil {
        logger.Error(fmt.Sprintf("SetTaskBySessionId: %s", err.Error()))
        w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
        return
    }
    taskCommand := string(req)
    newTask, err := sessions.SetTask(sessionGuid, taskGuid, taskCommand)
    if err != nil {
        logger.Error(fmt.Sprintf("SetTaskBySessionId: %s", err.Error()))
        w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
        return
    }
    w.Write(restapi_util.CreateTaskInfoResponseJSON(restapi_util.RESP_STATUS_SUCCESS, *newTask))
    logger.Success(fmt.Sprintf("Successfully set task for session: %s", sessionGuid))
}

// GetTaskCommandBySessionId allows users to issue commands to the specified session
func GetTaskCommandBySessionId(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid := vars["guid"]
	task, err := sessions.GetTask(guid)
	if err != nil {
		logger.Error(fmt.Sprintf("GetTaskCommandBySessionId: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}

    // For now do not use JSON format because handlers currently expect just the task command string. TODO: change this and handler code later
	if task != nil && task.Status == tasks.TASK_STATUS_NEW {
		task.Status = tasks.TASK_STATUS_PENDING
		
		fmt.Fprintf(w, "%v", task.Command)
	} else {
		fmt.Fprint(w, "")
	}
}

// RemoveTaskBySessionId deletes the currently queued tasking
func RemoveTaskBySessionId(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid := vars["guid"]
	err := sessions.RemoveTask(guid)
	if err != nil {
		logger.Error(fmt.Sprintf("RemoveTaskBySessionId: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}
	message := fmt.Sprintf("Successfully removed task for session: %s", guid)
	w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_SUCCESS, message))
	logger.Success(message)
}

// SetBootstrapTask allows users to set a default bootstrap task for sessions that support this feature.
func SetBootstrapTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	handlerName := strings.ToLower(vars["handler"])
	logger.Info(fmt.Sprintf("Received SetBootstrapTask request for handler %s", handlerName))
	if _, ok := util.RunningHandlers[handlerName]; !ok {
		errMsg := fmt.Sprintf("SetBootstrapTask: handler %s is not currently running. Failed to set bootstrap task.", handlerName)
		logger.Error(errMsg)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, errMsg))
		return
	}
	req, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Error(fmt.Sprintf("SetBootstrapTask: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}
	task := string(req)
	sessions.SetBootstrapTask(handlerName, task)
	message := fmt.Sprintf("Successfully set bootstrap task for handler %s", handlerName)
	logger.Success(message)
	w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_SUCCESS, message))
}

// GetBootstrapTask returns the currently set bootstrap task.
func GetBootstrapTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	handlerName := strings.ToLower(vars["handler"])
	task := sessions.GetBootstrapTask(handlerName)
	
	// For now do not use JSON format because handlers currently expect just the task command string. TODO: change this and handler code later
	fmt.Fprintf(w, "%v", task)
}

// RemoveBootstrapTask deletes the currently set bootstrap task
func RemoveBootstrapTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	handlerName := strings.ToLower(vars["handler"])
	if _, ok := util.RunningHandlers[handlerName]; !ok {
		errMsg := fmt.Sprintf("RemoveBootstrapTask: handler %s is not currently running. Cannot manage bootstrap tasks.", handlerName)
		logger.Error(errMsg)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, errMsg))
		return
	}
	sessions.RemoveBootstrapTask(handlerName)
	message := fmt.Sprintf("Successfully removed bootstrap task for handler %s", handlerName)
	logger.Success(message)
	w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_SUCCESS, message))
}

// SetTaskOutputBySessionId sets the output following task execution
func SetTaskOutputBySessionId(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid := vars["guid"]
	req, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Error(fmt.Sprintf("SetTaskOutputBySessionId: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}
	taskOutput := string(req)
	err = sessions.SetTaskOutput(guid, taskOutput, true)
	if err != nil {
		logger.Error(fmt.Sprintf("SetTaskOutputBySessionId: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}
	logger.Info("Received task output for session: ", guid)
	logger.Task(taskOutput)
	w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_SUCCESS, "Successfully set task output."))
}

// GetTaskOutputBySessionId returns the last task's output
func GetTaskOutputBySessionId(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid := vars["guid"]
	taskOutput, err := sessions.GetTaskOutput(guid)
	if err != nil {
		logger.Error(fmt.Sprintf("GetTaskOutputBySessionId: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}
	w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_TASK_OUTPUT, restapi_util.RESP_STATUS_SUCCESS, taskOutput))
}

// RemoveTaskOutputBySessionId clears the current task's output
func RemoveTaskOutputBySessionId(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid := vars["guid"]
	err := sessions.DeleteTaskOutput(guid)
	if err != nil {
		logger.Error(fmt.Sprintf("RemoveTaskOutputBySessionId: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}
	message := fmt.Sprintf("Successfully deleted task output for session: %s", guid)
	w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_SUCCESS, message))
}

func UploadFile(w http.ResponseWriter, r *http.Request) {
	// get uploaded file name
	vars := mux.Vars(r)
	fileName := vars["file"]

	// read file data from HTTP POST request
	req, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Error(fmt.Sprintf("UploadFile: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}

	// write file data to disk
	filePath := "./files/" + fileName
	err = ioutil.WriteFile(filePath, req, 0444)
	if err != nil {
		logger.Error(fmt.Sprintf("UploadFile: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}
	message := fmt.Sprintf("Successfully uploaded file to control server at './files/%s'", fileName)
	w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_SUCCESS, message))
}

// Retrieves task by GUID
func GetTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid := vars["guid"]
	retrievedTask, err := tasks.GetTaskById(guid)
	if err != nil {
		logger.Error(fmt.Sprintf("GetTask: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
        return
	}
	w.Write(restapi_util.CreateTaskInfoResponseJSON(restapi_util.RESP_STATUS_SUCCESS, *retrievedTask))
}

// Retrieves output for task with GUID
func GetTaskOutput(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid := vars["guid"]
	taskOutput, err := tasks.GetTaskOutputById(guid)
	if err != nil {
		logger.Error(fmt.Sprintf("GetTaskOutput: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}
	// send output to client
	w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_TASK_OUTPUT, restapi_util.RESP_STATUS_SUCCESS, taskOutput))
}

// Sets output for task by GUID
func SetTaskOutput(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid := vars["guid"]
	req, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Error(fmt.Sprintf("SetTaskOutput: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}
	taskOutput := string(req)
	err = tasks.SetTaskOutputById(guid, taskOutput, true)
	if err != nil {
		logger.Error(fmt.Sprintf("SetTaskOutput: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}
	logger.Task(taskOutput)
	message := fmt.Sprintf("Successfully set task output for task: %s", guid)
	logger.Success(message)
	w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_SUCCESS, message))
}

// Clears output for task by GUID
func RemoveTaskOutput(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid := vars["guid"]
	err := tasks.SetTaskOutputById(guid, "", false)
	if err != nil {
		logger.Error(fmt.Sprintf("RemoveTaskOutput: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}
	message := fmt.Sprintf("Successfully removed task output for task: %s", guid)
	logger.Success(message)
	w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_SUCCESS, message))
}

// Forwards Handler Implant Sessions to the CALDERA Emu Plugin
func ForwardSessionBeacon(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid := vars["guid"]

	sessionObject, err := sessions.GetSessionByGuid(guid)
	if err != nil {
		logger.Error(fmt.Sprintf("ForwardSessionBeacon: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}
	sessionJson, err := json.Marshal(sessionObject)
	if err != nil {
		logger.Error(fmt.Sprintf("ForwardSessionBeacon: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}

	// initialize HTTP request
	req, err := http.NewRequest("POST", CalderaForwardingEndpoint, bytes.NewBuffer([]byte(sessionJson)))
	if err != nil {
		logger.Error(fmt.Sprintf("ForwardSessionBeacon: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}
	req.Header.Set("Content-Type", "application/json")

	// execute HTTP POST request and read response
	client := &http.Client{
	    Timeout : 5 * time.Second,
    }
	response, err := client.Do(req)
	if err != nil {
		logger.Error(fmt.Sprintf("ForwardSessionBeacon: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
	    errMsg := fmt.Sprintf("obtained non-200 HTTP response code %d from forwarding POST request.", response.StatusCode)
		logger.Error(fmt.Sprintf("ForwardSessionBeacon: %s", errMsg))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, errMsg))
		return
	}

	// Read response from CALDERA
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		logger.Error(fmt.Sprintf("ForwardSessionBeacon: %s", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
        w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_FAILURE, err.Error()))
		return
	} else {
		message := fmt.Sprintf("Forwarded beacon for session: %s, received response: %s", guid, string(body))
		logger.Success(message)
	    w.Write(restapi_util.CreateStringResponseJSON(restapi_util.RESP_TYPE_CTRL, restapi_util.RESP_STATUS_SUCCESS, message))
	}
}
