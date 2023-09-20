package restapi

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"

	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/handlers/util"
	"attackevals.mitre-engenuity.org/control_server/logger"
	restapi_util "attackevals.mitre-engenuity.org/control_server/restapi/util"
	"attackevals.mitre-engenuity.org/control_server/sessions"
	"attackevals.mitre-engenuity.org/control_server/tasks"
	"attackevals.mitre-engenuity.org/control_server/test_utils"
)

const ( 
    BASE_URL = "http://127.0.0.1:9999/api/v1.0/"
    PAYLOAD_TEST_DIR = "./test_payloads"
    TEST_SESSION_1_GUID = "test-session-1"
    TEST_SESSION_2_GUID = "test-session-2"
    TEST_TASK_GUID = "test-task-guid"
    TEST_TASK_COMMAND = "whoami > file.txt"
    TEST_TASK_OUTPUT = "newly-set-output"
)

var TEST_SESSION_1 = sessions.Session{
    GUID:           TEST_SESSION_1_GUID,
    IPAddr:         "127.0.0.1",
    HostName:       "myHostName",
    User:           "myUserName",
    Dir:            "C:\\MyDir\\",
    PID:            1234,
    PPID:           4,
    SleepInterval:  60,
    Jitter:         1.5,
}

var TEST_SESSION_2 = sessions.Session{
    GUID:           TEST_SESSION_2_GUID,
    IPAddr:         "127.0.0.2",
    HostName:       "myHostName2",
    User:           "myUserName2",
    Dir:            "C:\\MyDir2\\",
    PID:            3456,
    PPID:           5,
    SleepInterval:  61,
    Jitter:         2,
}

var NEW_TEST_TASK = tasks.Task{
	GUID: TEST_TASK_GUID,
	Command: TEST_TASK_COMMAND,
	Output: "",
	Status: tasks.TASK_STATUS_NEW,
	ExitCode: -1,
}

var TEST_SESSION_WITH_TASK = sessions.Session{
	GUID:          TEST_SESSION_1_GUID,
	IPAddr:        "127.0.0.1",
	HostName:      "myHostName",
	User:          "myUserName",
	Dir:           "C:\\MyDir\\",
	PID:           1234,
	PPID:          4,
	SleepInterval: 60,
	Jitter:        1.5,
	Task:		   &NEW_TEST_TASK,
}

var TEST_RESP_SESSION_LIST = []sessions.Session{
    TEST_SESSION_1,
    TEST_SESSION_2,
}

var TEST_FINISHED_TASK = tasks.Task {
    GUID: TEST_TASK_GUID,
    Command: TEST_TASK_COMMAND,
    Output: TEST_TASK_OUTPUT,
    Status: tasks.TASK_STATUS_FINISHED,
    ExitCode: -1,
}


func startRESTapi(testConfigPath string) {
	// set current working directory to Resources/control_server
	// this is needed so that the unit tests can find ./config/config.yml
	cwd, _ := os.Getwd()
	os.Chdir("../")
	defer os.Chdir(cwd) // restore cwd at end of test
	configPath := "./config/test_config.yml" // default config path if none specified
	if len(testConfigPath) > 0 {
	    configPath = testConfigPath
	}
	err := config.SetRestAPIConfig(configPath)
	if err != nil {
		logger.Fatal(err)
	}

	restAPIaddress := config.GetRestAPIListenAddress()
	Start(restAPIaddress, PAYLOAD_TEST_DIR)
	time.Sleep(50 * time.Millisecond)
}

func stopRESTapi() {
    // Clear sessions list in between tests
    sessions.SessionList = nil
 
    time.Sleep(50 * time.Millisecond)
    Stop()
}

// Creates session on server for testing.
func createTestSession(session sessions.Session) {
	// http://localhost:9999/api/v1.0/session
	createSessionURL := BASE_URL + "session"

	// convert testSession object into JSON
	testSessionJSON, err := json.Marshal(session)
	if err != nil {
		logger.Fatal(err)
	}

	// setup HTTP POST request
	req, err := http.NewRequest("POST", createSessionURL, bytes.NewBuffer(testSessionJSON))
	if err != nil {
		logger.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	// execute HTTP POST request and read response
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		logger.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		logger.Fatal(fmt.Sprintf("Expected error code 200, got %v", response.StatusCode))
	}
}

func fetchSession(t *testing.T, sessionGuid string) *sessions.Session {
	// http://localhost:9999/api/v1.0/session/{guid}
	url := fmt.Sprintf("%ssession/%s", BASE_URL, sessionGuid)

	// setup HTTP GET request
	req, err := http.NewRequest("GET", url, nil)
	req.Close = true
	if err != nil {
		t.Error(err)
	}

	// execute HTTP GET and read response
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Errorf("Expected error code 200, got %v", response.StatusCode)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}

    var apiResponse restapi_util.ApiSessionsResponse
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		t.Error(err)
	}
	if len(apiResponse.Data) < 1 {
	    t.Errorf("API query returned 0 sessions for ID %v", sessionGuid)
	}
	returnedSession := apiResponse.Data[0]
	return &returnedSession
}

// Creates new task on server associated with input sessionGuid.
func createTestTaskForSession(sessionGuid string, taskGuid string, taskCommand string) {
	// http://localhost:9999/api/v1.0/session/abcdef123456/task
	url := fmt.Sprintf("%ssession/%s/task", BASE_URL, sessionGuid)

	// setup HTTP POST request
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(taskCommand))
	req.Header.Set("X-Task-Guid", taskGuid)
	req.Close = true
	if err != nil {
		logger.Fatal(err)
	}

	// execute HTTP POST and read response
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		logger.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		logger.Fatal(fmt.Sprintf("Expected error code 200, got %v", response.StatusCode))
	}
}

func TestJsonMarshalIndentNoHtmlEncode(t *testing.T) {
    toEncode := restapi_util.ApiStringResponse{
        ResponseType: 0,
        Status: 0,
        Data: "&<test encode>\ns",
    }
    want := `{
  "type": 0,
  "status": 0,
  "data": "&<test encode>\ns"
}
`
    
    encoded, err := restapi_util.JsonMarshalIndentNoHtmlEncode(toEncode)
    if err != nil {
        t.Error(err)
    }
    got := string(encoded)
    if got != want {
		t.Errorf("Got '%v', expected '%v'", got, want)
	}
}

func TestStartStopRESTapi(t *testing.T) {
	startRESTapi("")
	defer stopRESTapi()
	want := "http://10.2.3.4:8888/plugins/emu/beacons"
	if CalderaForwardingEndpoint != want {
		t.Errorf("Got '%v', expected '%v'", CalderaForwardingEndpoint, want)
	}
}

func TestGetVersion(t *testing.T) {
	startRESTapi("")
	defer stopRESTapi()

	getVersionURL := BASE_URL + "version"
	httpResponse, err := http.Get(getVersionURL)
	if err != nil {
		t.Error(err)
	}
	defer httpResponse.Body.Close()

	httpBody, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		t.Error(err)
	}

	got := string(httpBody)
	want := `{
  "type": 1,
  "status": 0,
  "data": "ATT&CK Evaluations Control Server 1.0"
}
`
	if got != want {
		t.Errorf("Got '%v', expected '%v'", got, want)
	}
}

func TestGetConfig(t *testing.T) {
	startRESTapi("")
	defer stopRESTapi()

	getConfigURL := BASE_URL + "config"
	httpResponse, err := http.Get(getConfigURL)
	if err != nil {
		t.Error(err)
	}
	defer httpResponse.Body.Close()

	httpBody, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		t.Error(err)
	}

	want := `{
  "type": 2,
  "status": 0,
  "data": {
    "Address": "127.0.0.1:9999",
    "CalderaForwardingAddress": "http://10.2.3.4:8888/plugins/emu",
    "EnableCalderaForwarding": true
  }
}
`
    got := string(httpBody)
	if got != want {
		t.Errorf("Got '%v', expected '%v'", got, want)
	}
}

func TestCreateSession(t *testing.T) {
	// setup test dependencies
	startRESTapi("")
	defer stopRESTapi()

	// http://localhost:9999/api/v1.0/session
	createSessionURL := BASE_URL + "session"

	// convert testSession object into JSON
	testSessionJSON, err := json.Marshal(TEST_SESSION_1)
	if err != nil {
		t.Error(err)
	}

	// setup HTTP POST request
	req, err := http.NewRequest("POST", createSessionURL, bytes.NewBuffer(testSessionJSON))
	if err != nil {
		t.Error(err)
	}
	req.Header.Set("Content-Type", "application/json")

	// execute HTTP POST request and read response
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Error(err)
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}
	want := `{
  "type": 0,
  "status": 0,
  "data": "Successfully added session."
}
`
    got := string(body)
	if got != want {
		t.Errorf("Got '%v', expected '%v'", got, want)
	}
}

func TestGetSessions(t *testing.T) {
	startRESTapi("")
	defer stopRESTapi()

	createTestSession(TEST_SESSION_1)
	createTestSession(TEST_SESSION_2)
	
	url := BASE_URL + "sessions"
	resp, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	var apiResponse restapi_util.ApiSessionsResponse
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		t.Error(err)
	}
	want := restapi_util.ApiSessionsResponse{
	    ResponseType: restapi_util.RESP_TYPE_SESSIONS,
	    Status: restapi_util.RESP_STATUS_SUCCESS,
	    Data: TEST_RESP_SESSION_LIST,
	}
	
	// ignore checkin times
	// have to do by index because range will copy values
	for i, _ := range apiResponse.Data{
	    apiResponse.Data[i].FirstCheckIn = ""
	    apiResponse.Data[i].LastCheckIn = ""
	}
	
	if !reflect.DeepEqual(apiResponse, want) {
		t.Errorf("Expected \"%v\", got \"%v\"", want, apiResponse)
	}
}

func TestGetSessionByName(t *testing.T) {
	startRESTapi("")
	defer stopRESTapi()

    createTestSession(TEST_SESSION_1)
	url := BASE_URL + "session/" + TEST_SESSION_1_GUID
	resp, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	var apiResponse restapi_util.ApiSessionsResponse
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		t.Error(err)
	}
	want := restapi_util.ApiSessionsResponse{
	    ResponseType: restapi_util.RESP_TYPE_SESSIONS,
	    Status: restapi_util.RESP_STATUS_SUCCESS,
	    Data: []sessions.Session{
	        TEST_SESSION_1,
	    },
	}
	
	// ignore checkin times
	for i, _ := range apiResponse.Data{
	    apiResponse.Data[i].FirstCheckIn = ""
	    apiResponse.Data[i].LastCheckIn = ""
	}
	
	if !reflect.DeepEqual(apiResponse, want) {
		t.Errorf("Expected \"%v\", got \"%v\"", want, apiResponse)
	}
}

func TestSetTaskBySessionId(t *testing.T) {
	startRESTapi("")
	defer stopRESTapi()
	
	createTestSession(TEST_SESSION_1)

	// setup HTTP POST request
	url := fmt.Sprintf("%ssession/%s/task", BASE_URL, TEST_SESSION_1_GUID)
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(TEST_TASK_COMMAND))
	req.Header.Set("X-Task-Guid", TEST_TASK_GUID)
	req.Close = true
	if err != nil {
		t.Error(err)
	}

	// execute HTTP POST and read response
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		t.Errorf("Expected error code 200, got %v", response.StatusCode)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}
	var apiResponse restapi_util.ApiTaskResponse
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		t.Error(err)
	}
	want := restapi_util.ApiTaskResponse{
	    ResponseType: restapi_util.RESP_TYPE_TASK_INFO,
	    Status: restapi_util.RESP_STATUS_SUCCESS,
	    Data: NEW_TEST_TASK,
	}

	if !reflect.DeepEqual(apiResponse, want) {
		t.Errorf("Expected \"%v\", got \"%v\"", want, apiResponse)
	}
}

func TestGetTaskCommandBySessionId(t *testing.T) {
	startRESTapi("")
	defer stopRESTapi()
	
	// Set up session and task
	createTestSession(TEST_SESSION_1)
	createTestTaskForSession(TEST_SESSION_1_GUID, TEST_TASK_GUID, TEST_TASK_COMMAND)
	
	url := fmt.Sprintf("%ssession/%s/task", BASE_URL, TEST_SESSION_1_GUID)
	resp, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()
	returnedCommand, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}

	if string(returnedCommand) != TEST_TASK_COMMAND {
		t.Errorf("Expected \"%v\", got \"%v\"", TEST_TASK_COMMAND, returnedCommand)
	}

	// The second request should return empty string, as the Task has already been assigned
	resp, err = http.Get(url)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()
	returnedCommand, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}

	if string(returnedCommand) != "" {
		t.Errorf("Expected empty task command, got \"%v\"", returnedCommand)
	}
}

func TestBootstrapTask(t *testing.T) {
	startRESTapi("")
	defer stopRESTapi()
	
	// register dummy handler
	handlerName := "testhandler"
	util.RunningHandlers[handlerName] = nil
	defer delete(util.RunningHandlers, handlerName)

	// http://localhost:9999/api/v1.0/bootstraptask/handler
	url := BASE_URL + "bootstraptask" + "/" + handlerName
	task := "whoami"

	// setup HTTP POST request
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(task))
	if err != nil {
		t.Error(err)
	}

	// execute HTTP POST and read response
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		t.Errorf("Expected error code 200, got %v", response.StatusCode)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}
	expectedOutput := `{
  "type": 0,
  "status": 0,
  "data": "Successfully set bootstrap task for handler testhandler"
}
`
	if string(body) != expectedOutput {
		t.Errorf("Expected \"%v\", got \"%v\"", expectedOutput, string(body))
	}
	
	getResp, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}
	defer getResp.Body.Close()
	taskData, err := ioutil.ReadAll(getResp.Body)
	if err != nil {
		t.Error(err)
	}
	if string(taskData) != task {
		t.Errorf("Expected '%v' got '%v'", task, string(taskData))
	}
	
	delReq, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		t.Error(err)
	}
	delResp, err := client.Do(delReq)
	if err != nil {
		t.Error(err)
	}
	defer delResp.Body.Close()
	respData, err := ioutil.ReadAll(delResp.Body)
	if err != nil {
		t.Error(err)
	}
	expectedOutput = `{
  "type": 0,
  "status": 0,
  "data": "Successfully removed bootstrap task for handler testhandler"
}
`
	if string(respData) != expectedOutput {
		t.Errorf("Expected '%v' got '%v'", expectedOutput, string(respData))
	}
}

func TestBootstrapTaskNotRunningHandler(t *testing.T) {
	startRESTapi("")
	defer stopRESTapi()

	handlerName := "notrunning"
	url := BASE_URL + "bootstraptask" + "/" + handlerName
	task := "whoami"

	// setup HTTP POST request
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(task))
	if err != nil {
		t.Error(err)
	}

	// execute HTTP POST and read response
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer response.Body.Close()

	if response.StatusCode != 500 {
		t.Errorf("Expected error code 500, got %v", response.StatusCode)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}
	expectedOutput := `{
  "type": 0,
  "status": 1,
  "data": "SetBootstrapTask: handler notrunning is not currently running. Failed to set bootstrap task."
}
`
	if string(body) != expectedOutput {
		t.Errorf("Expected \"%v\", got \"%v\"", expectedOutput, string(body))
	}
	
	getResp, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}
	defer getResp.Body.Close()
	taskData, err := ioutil.ReadAll(getResp.Body)
	if err != nil {
		t.Error(err)
	}
	if len(string(taskData)) > 0 {
		t.Errorf("Expected empty task, got %s", string(taskData))
	}
	
	delReq, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		t.Error(err)
	}
	delResp, err := client.Do(delReq)
	if err != nil {
		t.Error(err)
	}
	defer delResp.Body.Close()
	if delResp.StatusCode != 500 {
		t.Errorf("Expected error code 500, got %v", delResp.StatusCode)
	}
	
	respData, err := ioutil.ReadAll(delResp.Body)
	if err != nil {
		t.Error(err)
	}
	expectedOutput = `{
  "type": 0,
  "status": 1,
  "data": "RemoveBootstrapTask: handler notrunning is not currently running. Cannot manage bootstrap tasks."
}
`
	if string(respData) != expectedOutput {
		t.Errorf("Expected '%v' got '%v'", expectedOutput, string(respData))
	}
}

func TestSetTaskOutputBySessionId(t *testing.T) {
	startRESTapi("")
	defer stopRESTapi()

	createTestSession(TEST_SESSION_1)
	createTestTaskForSession(TEST_SESSION_1.GUID, TEST_FINISHED_TASK.GUID, TEST_FINISHED_TASK.Command)

	url := BASE_URL + "session/" + TEST_SESSION_1.GUID + "/task/output"

	// setup HTTP POST request
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(TEST_TASK_OUTPUT))
	if err != nil {
		t.Error(err)
	}

	// execute HTTP POST and read response
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Errorf("Expected error code 200, got %v", response.StatusCode)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}
	var apiResponse restapi_util.ApiStringResponse
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		t.Error(err)
	}
	expectedOutput := restapi_util.ApiStringResponse{
	    ResponseType: restapi_util.RESP_TYPE_CTRL,
		Status: 0,
		Data: "Successfully set task output.",
	}

	if !reflect.DeepEqual(expectedOutput, apiResponse) {
		t.Errorf("Expected \"%v\", got \"%v\"", expectedOutput, apiResponse)
	}
	returnedSession := fetchSession(t, TEST_SESSION_1.GUID)
	if !reflect.DeepEqual(*(returnedSession.Task), TEST_FINISHED_TASK) {
		t.Errorf("Expected \"%v\", got \"%v\"", TEST_FINISHED_TASK, *(returnedSession.Task))
	}
} 

func TestGetTaskOutputBySessionId(t *testing.T) {
	startRESTapi("")
	defer stopRESTapi()
	
	createTestSession(TEST_SESSION_1)
	createTestTaskForSession(TEST_SESSION_1.GUID, TEST_FINISHED_TASK.GUID, TEST_FINISHED_TASK.Command)
	
	// set task output
	url := BASE_URL + "session/" + TEST_SESSION_1.GUID + "/task/output"
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(TEST_TASK_OUTPUT))
	if err != nil {
		t.Error(err)
	}

	// execute HTTP POST and read response
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Errorf("Expected error code 200, got %v", response.StatusCode)
	}

    // get task output
	resp, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()
	apiResponse, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	preformatted := `{
  "type": 5,
  "status": 0,
  "data": "%s"
}
`
    want := fmt.Sprintf(preformatted, TEST_TASK_OUTPUT)
    
	// The first request should return Task output
	if string(apiResponse) != want{
		t.Errorf("Expected '%v' got '%v'", want, string(apiResponse))
	}
}

func TestRemoveTaskOutputBySessionId(t *testing.T) {
	startRESTapi("")
	defer stopRESTapi()
	createTestSession(TEST_SESSION_WITH_TASK)

	url := BASE_URL + "session/" + TEST_SESSION_WITH_TASK.GUID + "/task/output"

	// setup HTTP POST request
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		t.Error(err)
	}

	// execute HTTP DELETE request and read response
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Error(err)
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}
	preformatted := `{
  "type": 0,
  "status": 0,
  "data": "Successfully deleted task output for session: %s"
}
`
    expectedOutput := fmt.Sprintf(preformatted, TEST_SESSION_WITH_TASK.GUID)
	if string(body) != expectedOutput {
		t.Errorf("Expected '%v' got '%v'", expectedOutput, string(body))
	}
}

func TestRemoveSession(t *testing.T) {
	startRESTapi("")
	defer stopRESTapi()

	createTestSession(TEST_SESSION_1)
	url := BASE_URL + "session/delete/" + TEST_SESSION_1.GUID
	
	// setup HTTP POST request
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		t.Error(err)
	}

	// execute HTTP DELETE request and read response
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Error(err)
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}
	preformatted := `{
  "type": 0,
  "status": 0,
  "data": "Successfully removed session: %s"
}
`
    expectedOutput := fmt.Sprintf(preformatted, TEST_SESSION_1.GUID)
	if string(body) != expectedOutput {
		t.Errorf("Expected '%v' got '%v'", expectedOutput, string(body))
	}
}

func TestGetFile(t *testing.T) {
	startRESTapi("")
	defer stopRESTapi()

	// set current working directory to wizard_spider/Resources/control_server
	// this is needed so that the unit tests can find ./config/config.yml
	cwd, _ := os.Getwd()
	os.Chdir("../")
	defer os.Chdir(cwd) // restore cwd at end of test

	// http://localhost:9999/api/v1.0/files/
	url := BASE_URL + "files/hello_world.elf"
	resp, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()
	testFile, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	// MD5 hash of control_server/files/hello_world.elf
	expectedMD5 := "fe7c47d38224529c7d8f9a11a62cdd7a"

	// hash test file after download and convert to string
	hash := md5.Sum(testFile)
	actualMD5 := hex.EncodeToString(hash[:])

	// the test passes if the hashes match
	if actualMD5 != expectedMD5 {
		t.Errorf("Expected '%v' got '%v'", expectedMD5, actualMD5)
	}

	// test non-existent file
	url = BASE_URL + "files/does_not_exist.txt"
	resp, err = http.Get(url)
	if err != nil {
		t.Error(err)
	}
	statusCode := resp.Status
	expectedErr := "404 Not Found"
	if statusCode != expectedErr {
		t.Errorf("expected '%v', got '%v'", expectedErr, statusCode)
	}
}

func TestUploadFile(t *testing.T) {
	startRESTapi("")
	defer stopRESTapi()

	// set current working directory to wizard_spider/Resources/control_server
	// this is needed so that the unit tests can find ./config/config.yml
	cwd, _ := os.Getwd()
	os.Chdir("../")
	defer os.Chdir(cwd) // restore cwd at end of test

	// read file
	fileData, err := ioutil.ReadFile("test_payloads/hello_world.elf")
	if err != nil {
		t.Error(err)
	}

	// upload file via HTTP POST
	url := BASE_URL + "upload/test_file.elf"
	contentType := http.DetectContentType(fileData)
	response, err := http.Post(url, contentType, bytes.NewBuffer(fileData))
	if err != nil {
		t.Error(err)
	}
	defer response.Body.Close()

	// confirm HTTP request succeeded
	if response.StatusCode != 200 {
		t.Error(err)
	}

	// confirm success message
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}
	
	expectedOutput := `{
  "type": 0,
  "status": 0,
  "data": "Successfully uploaded file to control server at './files/test_file.elf'"
}
`
	if string(body) != expectedOutput {
		t.Errorf("Expected '%v' got '%v'", expectedOutput, string(body))
	}

	// get MD5 hash from uploaded file
	uploadedTestFile := "./files/test_file.elf"
	data, err := ioutil.ReadFile(uploadedTestFile)
	if err != nil {
		t.Error(err)
	}
	hash := md5.Sum(data)
	testMD5 := hex.EncodeToString(hash[:])
	expectedMD5 := "fe7c47d38224529c7d8f9a11a62cdd7a"

	// the test passes if the hashes match
	if expectedMD5 != testMD5 {
		t.Errorf("Expected %v got %v", expectedMD5, testMD5)
	}

	err = os.Remove(uploadedTestFile)
	if err != nil {
		t.Error(err)
	}
}

func TestGetTask(t *testing.T) {
	startRESTapi("")
	defer stopRESTapi()
	createTestSession(TEST_SESSION_1)
	createTestTaskForSession(TEST_SESSION_1.GUID, NEW_TEST_TASK.GUID, NEW_TEST_TASK.Command)

	// http://localhost:9999/api/v1.0/task/output/{guid}
	url := fmt.Sprintf("%stask/%s", BASE_URL, NEW_TEST_TASK.GUID)

	resp, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}

	var apiResponse restapi_util.ApiTaskResponse
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		t.Error(err)
	}
	
	want := restapi_util.ApiTaskResponse{
	    ResponseType: restapi_util.RESP_TYPE_TASK_INFO,
	    Status: restapi_util.RESP_STATUS_SUCCESS,
	    Data: NEW_TEST_TASK,
	}

	if !reflect.DeepEqual(apiResponse, want) {
		t.Errorf("Expected \"%v\", got \"%v\"", want, apiResponse)
	}
}

func TestSetGetAndRemoveTaskOutput(t *testing.T) {
	startRESTapi("")
	defer stopRESTapi()
	createTestSession(TEST_SESSION_1)
	createTestTaskForSession(TEST_SESSION_1.GUID, TEST_FINISHED_TASK.GUID, TEST_FINISHED_TASK.Command)

	// http://localhost:9999/api/v1.0/task/output/{guid}
	url := fmt.Sprintf("%stask/output/%s", BASE_URL, TEST_FINISHED_TASK.GUID)
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(TEST_TASK_OUTPUT))
	if err != nil {
		t.Error(err)
	}
	// execute HTTP POST and read response
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
    preformatted := `{
  "type": 0,
  "status": 0,
  "data": "Successfully set task output for task: %s"
}
`
	expectedOutput := fmt.Sprintf(preformatted, TEST_FINISHED_TASK.GUID)
	if expectedOutput != string(body) {
		t.Errorf("Expected \"%v\", got \"%v\"", expectedOutput, string(body))
	}
	returnedSession := fetchSession(t, TEST_SESSION_1.GUID)
	if !reflect.DeepEqual(*(returnedSession.Task), TEST_FINISHED_TASK) {
		t.Errorf("Expected \"%v\", got \"%v\"", TEST_FINISHED_TASK, *(returnedSession.Task))
	}
	
	// http://localhost:9999/api/v1.0/task/output/{guid}
	url = fmt.Sprintf("%stask/output/%s", BASE_URL, TEST_FINISHED_TASK.GUID)
	getResp, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}

	defer getResp.Body.Close()
	body, err = ioutil.ReadAll(getResp.Body)
	if err != nil {
		t.Error(err)
	}
	
	preformatted = `{
  "type": 5,
  "status": 0,
  "data": "%s"
}
`
    expectedOutput = fmt.Sprintf(preformatted, TEST_TASK_OUTPUT)
	if expectedOutput != string(body) {
		t.Errorf("Expected \"%v\", got \"%v\"", expectedOutput, string(body))
	}

    // Remove task output
	url = fmt.Sprintf("%stask/output/%s", BASE_URL, TEST_FINISHED_TASK.GUID)
	delReq, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		t.Error(err)
	}
	client = &http.Client{}
	delResp, err := client.Do(delReq)
	if err != nil {
		t.Error(err)
	}
	defer delResp.Body.Close()
	body, err = ioutil.ReadAll(delResp.Body)
	if err != nil {
		t.Error(err)
	}
	preformatted = `{
  "type": 0,
  "status": 0,
  "data": "Successfully removed task output for task: %s"
}
`
    expectedOutput = fmt.Sprintf(preformatted, TEST_FINISHED_TASK.GUID)
	if expectedOutput != string(body) {
		t.Errorf("Expected \"%v\", got \"%v\"", expectedOutput, string(body))
	}
}

func TestForwardSessionBeacon(t *testing.T) {
	startRESTapi("")
	defer stopRESTapi()
	test_utils.StartMockCalderaServer()
	CalderaForwardingEndpoint = "http://127.0.0.1:8888/plugins/emu/beacons"
	defer test_utils.StopMockCalderaServer()

	createTestSession(TEST_SESSION_1)

	// http://localhost:9999/api/v1.0/forwarder/session/{guid}
	url := fmt.Sprintf("%sforwarder/session/%s", BASE_URL, TEST_SESSION_1.GUID)
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(""))
	if err != nil {
		t.Error(err)
	}
	// execute HTTP POST and read response
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	var apiResponse restapi_util.ApiStringResponse
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		t.Error(err)
	}
	want := restapi_util.ApiStringResponse{
        ResponseType: restapi_util.RESP_TYPE_CTRL,
        Status: restapi_util.RESP_STATUS_SUCCESS,
        Data: fmt.Sprintf("Forwarded beacon for session: %s, received response: CALDERA server successfully received session: %s", TEST_SESSION_1.GUID, TEST_SESSION_1.GUID),
	}

	if !reflect.DeepEqual(want, apiResponse) {
		t.Errorf("Expected \"%v\", got \"%v\"", want, apiResponse)
	}
}
