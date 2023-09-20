// Unit testing for HTTP-based Carbon C2 handler

package carbon

import (
	"bytes"
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
	handlerName                     = "graphene"
	restAPIlistenHost               = "127.0.0.1:9990" // need to check on port
	restAPIBaseURL                  = "http://" + restAPIlistenHost + "/api/v1.0/"
	heartbeatURL                    = "http://127.0.0.1:8888/"
	heartbeatResponseWant           = "200 OK"
	registerURL                     = "http://127.0.0.1:8888/javascript/register.php"
	jsBaseURL                       = "http://127.0.0.1:8888/javascript/"
	commandURL                      = "http://127.0.0.1:8888/javascript/view.php"
	postURL                         = "http://127.0.0.1:8888/javascript/"
	commandResponseName             = "nameField"
	exampleTask                     = "{\"id\": 1, \"routing\": \"routingblob\", \"code\": 1, \"payload\": \"examplepayload.txt\", \"payload_dest\": \"C:\\\\users\\\\public\\\\test.bat\", \"cmd\": \"cmd.exe /c C:\\\\users\\\\public\\\\test.bat\"}"
	exampleTaskMissingId            = "{\"routing\": \"routingblob\", \"code\": 1, \"payload\": \"examplepayload.txt\", \"payload_dest\": \"C:\\\\users\\\\public\\\\test.bat\", \"cmd\": \"cmd.exe /c C:\\\\users\\\\public\\\\test.bat\"}"
	exampleTaskMissingPayloadDest   = "{\"id\": 1, \"routing\": \"routingblob\", \"code\": 1, \"payload\": \"examplepayload.txt\", \"cmd\": \"cmd.exe /c C:\\\\users\\\\public\\\\test.bat\"}"
	exampleTaskBadIntId             = "{\"id\": \"string\", \"routing\": \"routingblob\", \"code\": 1, \"payload\": \"examplepayload.txt\", \"payload_dest\": \"C:\\\\users\\\\public\\\\test.bat\", \"cmd\": \"cmd.exe /c C:\\\\users\\\\public\\\\test.bat\"}"
	exampleTaskBadIntCode           = "{\"id\": 1, \"routing\": \"routingblob\", \"code\": \"string\", \"payload\": \"examplepayload.txt\", \"payload_dest\": \"C:\\\\users\\\\public\\\\test.bat\", \"cmd\": \"cmd.exe /c C:\\\\users\\\\public\\\\test.bat\"}"
	exampleTaskNoRoutingBlob        = "{\"id\": 1, \"code\": 1, \"payload\": \"examplepayload.txt\", \"payload_dest\": \"C:\\\\users\\\\public\\\\test.bat\", \"cmd\": \"cmd.exe /c C:\\\\users\\\\public\\\\test.bat\"}"
	exampleTaskNoPayload            = "{\"id\": 1, \"routing\": \"routingblob\", \"code\": 1, \"cmd\": \"cmd.exe /c C:\\\\users\\\\public\\\\test.bat\"}"
	exampleTaskb64                  = "AQAAAAsAAAByb3V0aW5nYmxvYgEAAAATAAAAdGVzdGluZ3BheWxvYWRieXRlc1MAAABbQ09ORklHXQpuYW1lID0gQzpcdXNlcnNccHVibGljXHRlc3QuYmF0CmV4ZSA9IGNtZC5leGUgL2MgQzpcdXNlcnNccHVibGljXHRlc3QuYmF0Cg=="
	exampleTaskNoRoutingBlobB64     = "AQAAAAAAAAABAAAAEwAAAHRlc3RpbmdwYXlsb2FkYnl0ZXNTAAAAW0NPTkZJR10KbmFtZSA9IEM6XHVzZXJzXHB1YmxpY1x0ZXN0LmJhdApleGUgPSBjbWQuZXhlIC9jIEM6XHVzZXJzXHB1YmxpY1x0ZXN0LmJhdAo="
	exampleTaskNoPayloadB64         = "AQAAAAsAAAByb3V0aW5nYmxvYgEAAAAAAAAAMwAAAFtDT05GSUddCmV4ZSA9IGNtZC5leGUgL2MgQzpcdXNlcnNccHVibGljXHRlc3QuYmF0Cg=="
	commandResponseBlankWant        = "<!DOCTYPE html>\n<input name=\"" + commandResponseName + "\" value=\"\">"
	commandResponseFilledWant       = "<!DOCTYPE html>\n<input name=\"" + commandResponseName + "\" value=\"" + exampleTaskb64 + "\">"
	cmdRespFilledWantNoRoutingBlob  = "<!DOCTYPE html>\n<input name=\"" + commandResponseName + "\" value=\"" + exampleTaskNoRoutingBlobB64 + "\">"
	cmdRespFilledWantNoPayload      = "<!DOCTYPE html>\n<input name=\"" + commandResponseName + "\" value=\"" + exampleTaskNoPayloadB64 + "\">"
	serverMsgOK                     = "200 OK"
	serverMsgBadReq                 = "400 Bad Request"
	serverMsgNotFound               = "404 Not Found"
	serverMsgMethodNotAllowed       = "405 Method Not Allowed"
	serverMsgInternalError          = "500 Internal Server Error"
)

var exampleTaskStruct = Task{
	taskID: 1,
	lenRoutingBlob: 11,
	routingBlob: []byte("routingblob"),
	taskCode: 1,
	lenPayload: 19,
	payloadData: []byte("testingpayloadbytes"),
	lenConfig: 83,
	configData: []byte("[CONFIG]\nname = C:\\users\\public\\test.bat\nexe = cmd.exe /c C:\\users\\public\\test.bat\n"),
}

var exampleTaskNoRoutingBlobStruct = Task{
	taskID: 1,
	lenRoutingBlob: 0,
	routingBlob: []byte{},
	taskCode: 1,
	lenPayload: 19,
	payloadData: []byte("testingpayloadbytes"),
	lenConfig: 83,
	configData: []byte("[CONFIG]\nname = C:\\users\\public\\test.bat\nexe = cmd.exe /c C:\\users\\public\\test.bat\n"),
}

var exampleTaskNoPayloadStruct = Task{
	taskID: 1,
	lenRoutingBlob: 11,
	routingBlob: []byte("routingblob"),
	taskCode: 1,
	lenPayload: 0,
	payloadData: []byte{},
	lenConfig: 51,
	configData: []byte("[CONFIG]\nexe = cmd.exe /c C:\\users\\public\\test.bat\n"),
}

var exampleTaskBytes = []byte{
	0x01,0x00,0x00,0x00,
	0x0b,0x00,0x00,0x00,
	0x72,0x6f,0x75,0x74,0x69,0x6e,0x67,0x62,0x6c,0x6f,0x62,
	0x01,0x00,0x00,0x00,
	0x13,0x00,0x00,0x00,
	0x74,0x65,0x73,0x74,0x69,0x6e,0x67,0x70,0x61,0x79,0x6c,0x6f,0x61,0x64,0x62,0x79,0x74,0x65,0x73,
	0x53,0x00,0x00,0x00,
	0x5b,0x43,0x4f,0x4e,0x46,0x49,0x47,0x5d,0x0a,0x6e,0x61,0x6d,0x65,0x20,0x3d,0x20,0x43,0x3a,0x5c,0x75,0x73,0x65,0x72,0x73,0x5c,0x70,0x75,0x62,0x6c,0x69,0x63,0x5c,0x74,0x65,0x73,0x74,0x2e,0x62,0x61,0x74,0x0a,0x65,0x78,0x65,0x20,0x3d,0x20,0x63,0x6d,0x64,0x2e,0x65,0x78,0x65,0x20,0x2f,0x63,0x20,0x43,0x3a,0x5c,0x75,0x73,0x65,0x72,0x73,0x5c,0x70,0x75,0x62,0x6c,0x69,0x63,0x5c,0x74,0x65,0x73,0x74,0x2e,0x62,0x61,0x74,0x0a,
}

var exampleTaskBytesNoRoutingBlob = []byte{
	0x01,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,
	0x01,0x00,0x00,0x00,
	0x13,0x00,0x00,0x00,
	0x74,0x65,0x73,0x74,0x69,0x6e,0x67,0x70,0x61,0x79,0x6c,0x6f,0x61,0x64,0x62,0x79,0x74,0x65,0x73,
	0x53,0x00,0x00,0x00,
	0x5b,0x43,0x4f,0x4e,0x46,0x49,0x47,0x5d,0x0a,0x6e,0x61,0x6d,0x65,0x20,0x3d,0x20,0x43,0x3a,0x5c,0x75,0x73,0x65,0x72,0x73,0x5c,0x70,0x75,0x62,0x6c,0x69,0x63,0x5c,0x74,0x65,0x73,0x74,0x2e,0x62,0x61,0x74,0x0a,0x65,0x78,0x65,0x20,0x3d,0x20,0x63,0x6d,0x64,0x2e,0x65,0x78,0x65,0x20,0x2f,0x63,0x20,0x43,0x3a,0x5c,0x75,0x73,0x65,0x72,0x73,0x5c,0x70,0x75,0x62,0x6c,0x69,0x63,0x5c,0x74,0x65,0x73,0x74,0x2e,0x62,0x61,0x74,0x0a,
}

var exampleTaskBytesNoPayload = []byte{
	0x01,0x00,0x00,0x00,
	0x0b,0x00,0x00,0x00,
	0x72,0x6f,0x75,0x74,0x69,0x6e,0x67,0x62,0x6c,0x6f,0x62,
	0x01,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,
	0x33,0x00,0x00,0x00,
	0x5b,0x43,0x4f,0x4e,0x46,0x49,0x47,0x5d,0x0a,0x65,0x78,0x65,0x20,0x3d,0x20,0x63,0x6d,0x64,0x2e,0x65,0x78,0x65,0x20,0x2f,0x63,0x20,0x43,0x3a,0x5c,0x75,0x73,0x65,0x72,0x73,0x5c,0x70,0x75,0x62,0x6c,0x69,0x63,0x5c,0x74,0x65,0x73,0x74,0x2e,0x62,0x61,0x74,0x0a,
}

// Encrypted 01000000010000009d0000004c6f672066696c6520666f72205461736b49443a20310a437265617465642070726f636573732077697468204944203134303820616e6420636f6d6d616e64202277686f616d69202f616c6c220a50726f63657373206578697465642077697468206578697420636f64653a20300a5265636569766564203435323620746f74616c206f75747075742062797465732066726f6d2070726f636573732e08000000534f4d4555554944
var validPostOneFile = []byte("AAAAAAAAAACXbumfIhezZScBgcH/NfS4WNUjsYcMMld1uMPglI+axCym+VU+OepPrC6b5ZQWwY3wJVm3wop15n+lpeVVMmrcCxq3vJtghOCek9P0apbAEvBJ+IdQUFn7Z13Gutxt2erhOr3T4tIyh1fe7W2AV0HVPvrV455UHNG6OLH4Q9nDlxjSO5U18L5EeNAG8noX0K7ZMTghXiZYYJsV/oLQWIGTXhivarsFYcdEMMOxf1pTMIp8HwcwPVoQ")

var invalidPostBadVal = []byte{
	0x03, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 
	0x08, 0x00, 0x00, 0x00, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0x04, 0x00, 0x00, 0x00, 
	0xaa, 0xaa, 0xaa, 0xaa,
}

var exampleBeacon = sessions.Session{
	GUID:     "carbon-implant-123",
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
	"port": "8888",
}

var validResponseStructOneFile = ImplantResponse{
	responseID:       1,
	filesSent:        1,
	firstFileSize:    157,
	firstFileContent: []byte("Log file for TaskID: 1\nCreated process with ID 1408 and command \"whoami /all\"\nProcess exited with exit code: 0\nReceived 4526 total output bytes from process."),
	uuidLength:       8,
	uuid:             "SOMEUUID",
}

var validResponseStructTwoFiles = ImplantResponse{
	responseID:        2,
	filesSent:         2,
	firstFileSize:     8,
	firstFileContent:  []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	secondFileSize:    8,
	secondFileContent: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	uuidLength:        18,
	uuid:              "carbon-implant-123",
}

func mockGenRandBytes(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(0)
	}
	return len(b), nil
}

func startCarbonHttpHandler(handler *CarbonHttpHandler, t *testing.T) {
	if err := handler.StartHandler(restAPIlistenHost, configEntry); err != nil {
		t.Errorf("Error when starting Carbon HTTP handler: %s", err.Error())
	}
	util.RunningHandlers[handlerName] = handler
	time.Sleep(50 * time.Millisecond)
}

func stopCarbonHttpHandler(handler *CarbonHttpHandler, t *testing.T) {
	if err := handler.StopHandler(); err != nil {
		t.Errorf("Error when stopping Carbon HTTP handler: %s", err.Error())
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

func TestStartStopCarbonHttpHandler(t *testing.T) {
	handler := carbonHttpHandlerFactory(false, mockGenRandBytes)
	startCarbonHttpHandler(handler, t)
	defer stopCarbonHttpHandler(handler, t)
}

func sendHeartbeat(t *testing.T) (string, []byte) {
	response, err := http.Get(heartbeatURL)
	if err != nil {
		t.Error(err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}
	status := response.Status

	return status, body
}

func TestHandleHeartbeat(t *testing.T) {
	// start REST API
	startRESTAPI(t)
	defer stopRESTAPI(t)

	handler := carbonHttpHandlerFactory(false, mockGenRandBytes)

	// start handler
	startCarbonHttpHandler(handler, t)
	defer stopCarbonHttpHandler(handler, t)

	// Send heartbeat request. Expecting 200 OK response and content.
	heartbeatStatus, heartbeatBody := sendHeartbeat(t)
	if string(heartbeatStatus) != serverMsgOK {
		t.Errorf("Status mismatch, got '%s' expected '%s'", string(heartbeatStatus), serverMsgOK)
	}
	if string(heartbeatBody) != heartbeatResponseWant {
		t.Errorf("Body mismatch, got '%s' expected '%s'", string(heartbeatBody), string(heartbeatResponseWant))
	}
}

func sendImplantBeacon(t *testing.T, sessionUUID string, url string) (string, []byte) {
	client := &http.Client{}

	cookie := &http.Cookie{
		Name:		"PHPSESSID",
		Value:		sessionUUID,
		MaxAge:		300,
	}

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Error(err)
	}

	request.AddCookie(cookie)
	response, err := client.Do(request)
	if err != nil {
		t.Error(err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}
	status := response.Status

	return status, body
}

func sendImplantBeaconNoCookie(t *testing.T, url string) (string, []byte) {
	response, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}

	status := response.Status

	return status, body
}

func setTask(task string, uuid string) (string, error) {
	url := restAPIBaseURL + "session/" + uuid + "/task"

	// setup HTTP POST request
	request, err := http.NewRequest("POST", url, bytes.NewBufferString(task))
	if err != nil {
		return "", err
	}

	// execute HTTP POST and read response
	client := &http.Client{}
	response, err := client.Do(request)
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

func setAndGetTask(t *testing.T, task, uuid, expectedStatus string) string {
	_, err := setTask(task, uuid)
	if err != nil {
		t.Error(err)
		return ""
	}
	status, body := sendImplantBeacon(t, uuid, commandURL)
	if string(status) != expectedStatus {
		t.Errorf("Status mismatch, got '%s' expected '%s'", string(status), expectedStatus)
		return ""
	}
	return string(body)
}

func setAndGetTaskCheckOutput(t *testing.T, task, uuid, expectedStatus, expectedOutput string) {
	result := setAndGetTask(t, task, uuid, expectedStatus)
	if result != expectedOutput {
		t.Errorf("Got '%s' expected '%s'", result, expectedOutput)
	}
}

func TestHasImplantSessionAndStoreImplantSession(t *testing.T) {
	handler := carbonHttpHandlerFactory(false, mockGenRandBytes)
	startCarbonHttpHandler(handler, t)
	defer stopCarbonHttpHandler(handler, t)

	if handler.hasImplantSession("invalid-id") {
		t.Error("Implant invalid-id should not have an active session.")
	}

	uuid := "implant1"
	err := handler.storeImplantSession(uuid)
	if err != nil {
		t.Error(err.Error())
	}
	if !handler.hasImplantSession(uuid) {
		t.Error("Expected implant session to be stored.")
	}

	err = handler.storeImplantSession(uuid)
	want := fmt.Sprintf("Session %s already exists.", uuid)
	if err != nil {
		if err.Error() != want {
			t.Errorf("Expected error message: %s; got: %s", want, err.Error())
		}
	} else {
		t.Error("Expected error message.")
	}
}

func TestCreateNewSessionDataBytes(t *testing.T) {
	uuid := "test-implant-id"
	want := "{\"guid\":\"test-implant-id\"}"
	result := string(createNewSessionDataBytes(uuid))
	if result != want {
		t.Errorf("Expected %s; got: %s", want, result)
	}
}

func TestHandleRegisterImplant(t *testing.T) {
	// start REST API
	startRESTAPI(t)
	defer stopRESTAPI(t)

	handler := carbonHttpHandlerFactory(false, mockGenRandBytes)

	// start handler
	startCarbonHttpHandler(handler, t)
	defer stopCarbonHttpHandler(handler, t)

	// Send register request. Expecting 200 OK status and no body.
	// Check that the implant gets registered
	registerStatus, registerBody := sendImplantBeacon(t, exampleBeacon.GUID, registerURL)
	if string(registerStatus) != serverMsgOK {
		t.Errorf("Status mismatch, got '%s' expected '%s'", string(registerStatus), serverMsgOK)
	}
	if string(registerBody) != "" {
		t.Errorf("Got '%s' expected ''", string(registerBody))
	}

	// Send registered request. Expecting 200 OK status and no body.
	// Check that the implant is already registered
	for i := 1; i <= 5; i++ {
		registeredStatus, registeredBody := sendImplantBeacon(t, exampleBeacon.GUID, registerURL)
		if string(registeredStatus) != serverMsgOK {
			t.Errorf("Status mismatch, got '%s' expected '%s'", string(registeredStatus), serverMsgOK)
		}
		if string(registeredBody) != "" {
			t.Errorf("Got '%s' expected ''", string(registeredBody))
		}
	}
}

func TestHandleGetCommand(t *testing.T) {
	// start REST API
	startRESTAPI(t)
	defer stopRESTAPI(t)

	handler := carbonHttpHandlerFactory(false, mockGenRandBytes)

	// start handler
	startCarbonHttpHandler(handler, t)
	defer stopCarbonHttpHandler(handler, t)

	// Send command request from new session. Expecting 200 OK status and commandResponseBlankWant body.
	// Check that the implant gets registered and that the correct content is returned
	registerStatus, registerBody := sendImplantBeacon(t, exampleBeacon.GUID, commandURL)
	if string(registerStatus) != serverMsgOK {
		t.Errorf("Status mismatch, got '%s' expected '%s'", string(registerStatus), serverMsgOK)
	}
	if string(registerBody) != (commandResponseBlankWant) {
		t.Errorf("Got '%s' expected '%s'", string(registerBody), (commandResponseBlankWant))
	}

	// Send registered request. Expecting 200 OK status and commandResponseFilledWant body.
	// Check that the implant is already registered and that the correct content is returned
	for i := 1; i <= 5; i++ {
		registeredStatus, registeredBody := sendImplantBeacon(t, exampleBeacon.GUID, commandURL)
		if string(registeredStatus) != serverMsgOK {
			t.Errorf("Status mismatch, got '%s' expected '%s'", string(registeredStatus), serverMsgOK)
		}
		if string(registeredBody) != (commandResponseBlankWant) {
			t.Errorf("Got '%s' expected '%s'", string(registeredBody), (commandResponseBlankWant))
		}
	}
}

func TestHandleBeaconFail(t *testing.T) {
	// start REST API
	startRESTAPI(t)
	defer stopRESTAPI(t)

	handler := carbonHttpHandlerFactory(false, mockGenRandBytes)

	// start handler
	startCarbonHttpHandler(handler, t)
	defer stopCarbonHttpHandler(handler, t)

	// Send register request without a cookie. Expecting 400 Bad Request status and no body.
	// Check that if we don't include a cookie in our request, the implant doesn't get registered
	regNoCookieStatus, regNoCookieBody := sendImplantBeaconNoCookie(t, commandURL)
	if string(regNoCookieStatus) != serverMsgBadReq {
		t.Errorf("Status mismatch, got '%s' expected '%s'", string(regNoCookieStatus), serverMsgBadReq)
	}
	if string(regNoCookieBody) != "" {
		t.Errorf("Got '%s' expected ''", string(regNoCookieBody))
	}

	// Send register request to /javascript/. Expecting 405 Method Not Allowed status and "" body.
	// Check that a get request to this page fails as expected
	regBadPageStatus, regBadPageBody := sendImplantBeaconNoCookie(t, jsBaseURL)
	if string(regBadPageStatus) != serverMsgMethodNotAllowed {
		t.Errorf("Status mismatch, got '%s' expected '%s'", string(regBadPageStatus), serverMsgMethodNotAllowed)
	}
	if string(regBadPageBody) != "" {
		t.Errorf("Got '%s' expected '%s'", string(regBadPageBody), "")
	}
}

func CompareResponseStructs(t *testing.T, first ImplantResponse, second ImplantResponse) bool {
	ret := true

	if first.responseID != second.responseID {
		t.Errorf("Bad value in struct for field responseID. First: %s | Second: %s", fmt.Sprint(first.responseID), fmt.Sprint(second.responseID))
		ret = false
	}

	if first.filesSent != second.filesSent {
		t.Errorf("Bad value in struct for field filesSent. First: %s | Second: %s", fmt.Sprint(first.filesSent), fmt.Sprint(second.filesSent))
		ret = false
	}

	if first.firstFileSize != second.firstFileSize {
		t.Errorf("Bad value in struct for field firstFileSize. First: %s | Second: %s", fmt.Sprint(first.firstFileSize), fmt.Sprint(second.firstFileSize))
		ret = false
	}

	if bytes.Compare(first.firstFileContent, second.firstFileContent) != 0 {
		t.Errorf("Bad value in struct for field firstFileContent. First: %s | Second: %s", string(first.firstFileContent), string(second.firstFileContent))
		ret = false
	}

	if first.secondFileSize != second.secondFileSize {
		t.Errorf("Bad value in struct for field secondFileSize. First: %s | Second: %s", fmt.Sprint(first.secondFileSize), fmt.Sprint(second.secondFileSize))
		ret = false
	}

	if bytes.Compare(first.secondFileContent, second.secondFileContent) != 0 {
		t.Errorf("Bad value in struct for field secondFileContent. First: %s | Second: %s", string(first.secondFileContent), string(second.secondFileContent))
		ret = false
	}

	if first.uuidLength != second.uuidLength {
		t.Errorf("Bad value in struct for field uuidLength. First: %s | Second: %s", fmt.Sprint(first.uuidLength), fmt.Sprint(second.uuidLength))
		ret = false
	}

	if first.uuid != second.uuid {
		t.Errorf("Bad value in struct for field uuid. First: %s | Second: %s", first.uuid, second.uuid)
		ret = false
	}

	return ret
}

func TestProcessReturnData(t *testing.T) {
	var impResponse ImplantResponse
	handler := carbonHttpHandlerFactory(true, mockGenRandBytes)

	// test if POST data with one file is processed correctly
	err := handler.processReturnData([]byte(validPostOneFile), &impResponse)
	if err != nil {
		t.Errorf("Expected no error, got '%s'", err.Error())
	}

	if !(CompareResponseStructs(t, impResponse, validResponseStructOneFile)) {
		t.Errorf("Generated struct for one file not same as expected value")
	}

	// check that the correct error is thrown when invalid bytes are sent
	err = handler.processReturnData([]byte(invalidPostBadVal), &impResponse)
	if err.Error() != "illegal base64 data at input byte 0" {
		t.Errorf("Expected '%s', got '%s'", "illegal base64 data at input byte 0", err.Error())
	}

}

func sendPostResponse(t *testing.T, sessionUUID string, url string, postResponse []byte) (string, []byte) {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	cookie := &http.Cookie{
		Name:		"PHPSESSID",
		Value:		sessionUUID,
		MaxAge:		300,
	}

	request, err := http.NewRequest("POST", url, bytes.NewReader(postResponse))
	if err != nil {
		t.Error(err)
	}

	request.AddCookie(cookie)
	response, err := client.Do(request)
	if err != nil {
		t.Error(err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}
	status := response.Status

	return status, body
}

func TestHandlePostResponse(t *testing.T) {
	// start REST API
	startRESTAPI(t)
	defer stopRESTAPI(t)

	handler := carbonHttpHandlerFactory(false, mockGenRandBytes)

	// start handler
	startCarbonHttpHandler(handler, t)
	defer stopCarbonHttpHandler(handler, t)
  
	// send beacon to establish session. expecting 200 OK and blank command response
	registerStatus, registerBody := sendImplantBeacon(t, "SOMEUUID", registerURL)
	if string(registerStatus) != serverMsgOK {
		t.Errorf("Status mismatch, got '%s' expected '%s'", string(registerStatus), serverMsgOK)
	}
	if string(registerBody) != "" {
		t.Errorf("Got '%s' expected ''", string(registerBody))
	}

	// Send post data with 6 fields (one file)
	// Expecting 200 OK and no body
	postOneFileStatus, postOneFileBody := sendPostResponse(t, "SOMEUUID", postURL, validPostOneFile)
	if string(postOneFileStatus) != serverMsgOK {
		t.Errorf("Status mismatch, got '%s' expected '%s'", string(postOneFileStatus), serverMsgOK)
	}
	if string(postOneFileBody) != "" {
		t.Errorf("Got '%s' expected ''", string(postOneFileBody))
	}

	// Send invalid post data
	// Expecting 500 Internal Server Error and "Internal server error" body
	postInvalidStatus, postInvalidBody := sendPostResponse(t, "SOMEUUID", postURL, invalidPostBadVal)
	if string(postInvalidStatus) != serverMsgInternalError {
		t.Errorf("Status mismatch, got '%s', expected '%s'", string(postInvalidStatus), serverMsgInternalError)
	}
	if string(postInvalidBody) != "Internal server error" {
		t.Errorf("Got '%s' expected '%s'", string(postInvalidBody), "Internal server error")
	}
}

func compareTasks(got *Task, want *Task, t *testing.T) {
	if (got.taskID != want.taskID) {
		t.Errorf("Expected task ID %d, got %d", want.taskID, got.taskID)
	}
	if (got.lenRoutingBlob != want.lenRoutingBlob) {
		t.Errorf("Expected routing blob length %d, got %d", want.lenRoutingBlob, got.lenRoutingBlob)
	}
	if (bytes.Compare(got.routingBlob, want.routingBlob) != 0) {
		t.Errorf("Expected routing blob %v, got %v", want.routingBlob, got.routingBlob)
	}
	if (got.taskCode != want.taskCode) {
		t.Errorf("Expected task code %d, got %d", want.taskCode, got.taskCode)
	}
	if (got.lenPayload != want.lenPayload) {
		t.Errorf("Expected payload length %d, got %d", want.lenPayload, got.lenPayload)
	}
	if (bytes.Compare(got.payloadData, want.payloadData) != 0) {
		t.Errorf("Expected payload data %v, got %v", want.payloadData, got.payloadData)
	}
	if (got.lenConfig != want.lenConfig) {
		t.Errorf("Expected config length %d, got %d", want.lenConfig, got.lenConfig)
	}
	if (bytes.Compare(got.configData, want.configData) != 0) {
		t.Errorf("Expected config data %v, got %v", want.configData, got.configData)
	}
}

func TestExtractTestParts(t *testing.T) {
	// set current working directory to main repo directory
	// this is needed so that the unit tests can find the requested payload
	cwd, _ := os.Getwd()
	os.Chdir("../../")
	defer os.Chdir(cwd) // restore cwd at end of test
	
	// start REST API
	startRESTAPI(t)
	defer stopRESTAPI(t)

	handler := carbonHttpHandlerFactory(false, mockGenRandBytes)

	// start handler
	startCarbonHttpHandler(handler, t)
	defer stopCarbonHttpHandler(handler, t)

	// check that the extractTaskParts function behaves as expected
	var task Task
	err := handler.extractTaskParts(exampleTask, &task)
	if err != nil {
		t.Errorf("Got error when none expected: %s", err.Error())
	}
	compareTasks(&task, &exampleTaskStruct, t)
	
	var taskNoRoutingBlob Task
	err = handler.extractTaskParts(exampleTaskNoRoutingBlob, &taskNoRoutingBlob)
	if err != nil {
		t.Errorf("Got error when none expected: %s", err.Error())
	}
	compareTasks(&taskNoRoutingBlob, &exampleTaskNoRoutingBlobStruct, t)
	
	var taskNoPayload Task
	err = handler.extractTaskParts(exampleTaskNoPayload, &taskNoPayload)
	if err != nil {
		t.Errorf("Got error when none expected: %s", err.Error())
	}
	compareTasks(&taskNoPayload, &exampleTaskNoPayloadStruct, t)

	err = handler.extractTaskParts(exampleTaskMissingId, &task)
	errWant := "Task ID not provided in task string"
	if err.Error() != errWant {
		t.Errorf("Got '%s' expected '%s'", err.Error(), errWant)
	}
	
	err = handler.extractTaskParts(exampleTaskMissingPayloadDest, &task)
	errWant = "Payload destination path not provided with payload name."
	if err.Error() != errWant {
		t.Errorf("Got '%s' expected '%s'", err.Error(), errWant)
	}

	errWant = "Bad task ID: string"
	err = handler.extractTaskParts(exampleTaskBadIntId, &task)
	if err.Error() != errWant {
		t.Errorf("Got '%s' expected '%s'", err.Error(), errWant)
	}
	errWant = "Bad task code: string"
	err = handler.extractTaskParts(exampleTaskBadIntCode, &task)
	if err.Error() != errWant {
		t.Errorf("Got '%s' expected '%s'", err.Error(), errWant)
	}

	// check that the extractTaskParts function behaves as expected when used with the rest of the handler

	// send beacon to establish session. expecting 200 OK and blank command response
	status, body := sendImplantBeacon(t, exampleBeacon.GUID, registerURL)
	if string(status) != serverMsgOK {
		t.Errorf("Status mismatch, got '%s' expected '%s'", string(status), serverMsgOK)
	}
	if string(body) != "" {
		t.Errorf("Got '%s' expected '%s'", string(body), commandResponseBlankWant)
	}

	// check that the handler returns the correct response when a good task is given
	setAndGetTaskCheckOutput(t, exampleTask, exampleBeacon.GUID, serverMsgOK, commandResponseFilledWant)
	setAndGetTaskCheckOutput(t, exampleTaskNoRoutingBlob, exampleBeacon.GUID, serverMsgOK, cmdRespFilledWantNoRoutingBlob)
	setAndGetTaskCheckOutput(t, exampleTaskNoPayload, exampleBeacon.GUID, serverMsgOK, cmdRespFilledWantNoPayload)

	// send invalid tasks to the restAPI and then have the handler attempt to make them into responses
	// each of these are designed to fail in the extractTasksParts func
	setAndGetTaskCheckOutput(t, exampleTaskMissingId, exampleBeacon.GUID, serverMsgInternalError, "Internal server error")
	setAndGetTaskCheckOutput(t, exampleTaskMissingPayloadDest, exampleBeacon.GUID, serverMsgInternalError, "Internal server error")
	setAndGetTaskCheckOutput(t, exampleTaskBadIntId, exampleBeacon.GUID, serverMsgInternalError, "Internal server error")
	setAndGetTaskCheckOutput(t, exampleTaskBadIntCode, exampleBeacon.GUID, serverMsgInternalError, "Internal server error")
}

func TestConvertTaskToResponse(t *testing.T) {
	// set current working directory to main repo directory
	// this is needed so that the unit tests can find the requested payload
	cwd, _ := os.Getwd()
	os.Chdir("../../")
	defer os.Chdir(cwd) // restore cwd at end of test
	
	// start REST API
	startRESTAPI(t)
	defer stopRESTAPI(t)

	handler := carbonHttpHandlerFactory(false, mockGenRandBytes)

	// start handler
	startCarbonHttpHandler(handler, t)
	defer stopCarbonHttpHandler(handler, t)

	// check that the function returns an error when the implant has no session
	task, err := handler.convertTaskToResponse(exampleBeacon.GUID, exampleTask)
	if task != "" {
		t.Errorf("Got '%s' expected ''", task)
	}
	errWant := "No existing session for implant " + exampleBeacon.GUID + "."
	if err.Error() != errWant {
		t.Errorf("Got '%s' expected '%s'", err.Error(), errWant)
	}

	// register an implant session so the function is able to work

	// send beacon to establish session. expecting 200 OK and blank command response
	registerStatus, registerBody := sendImplantBeacon(t, exampleBeacon.GUID, registerURL)
	if string(registerStatus) != serverMsgOK {
		t.Errorf("Status mismatch, got '%s' expected '%s'", string(registerStatus), serverMsgOK)
	}
	if string(registerBody) != "" {
		t.Errorf("Got '%s' expected '%s'", string(registerBody), commandResponseBlankWant)
	}

	// check that the function produces correct output when given good arguments
	task, err = handler.convertTaskToResponse(exampleBeacon.GUID, exampleTask)
	if task != commandResponseFilledWant {
		t.Errorf("Got '%s' expected '%s'", task, commandResponseFilledWant)
	}
	if err != nil {
		t.Errorf("Got '%s' expected '%s'", err.Error(), "nil")
	}
	
	task, err = handler.convertTaskToResponse(exampleBeacon.GUID, exampleTaskNoRoutingBlob)
	if task != cmdRespFilledWantNoRoutingBlob {
		t.Errorf("Got '%s' expected '%s'", task, cmdRespFilledWantNoRoutingBlob)
	}
	if err != nil {
		t.Errorf("Got '%s' expected '%s'", err.Error(), "nil")
	}
	
	task, err = handler.convertTaskToResponse(exampleBeacon.GUID, exampleTaskNoPayload)
	if task != cmdRespFilledWantNoPayload {
		t.Errorf("Got '%s' expected '%s'", task, cmdRespFilledWantNoPayload)
	}
	if err != nil {
		t.Errorf("Got '%s' expected '%s'", err.Error(), "nil")
	}

	// check that the function produces an error when the task is bad
	task, err = handler.convertTaskToResponse(exampleBeacon.GUID, exampleTaskMissingId)
	errWant = "Task ID not provided in task string"
	if task != "" {
		t.Errorf("Got '%s' expected ''", task)
	}
	if err.Error() != errWant {
		t.Errorf("Got '%s' expected '%s'", err.Error(), errWant)
	}
	task, err = handler.convertTaskToResponse(exampleBeacon.GUID, exampleTaskMissingPayloadDest)
	errWant = "Payload destination path not provided with payload name."
	if task != "" {
		t.Errorf("Got '%s' expected ''", task)
	}
	if err.Error() != errWant {
		t.Errorf("Got '%s' expected '%s'", err.Error(), errWant)
	}
	task, err = handler.convertTaskToResponse(exampleBeacon.GUID, exampleTaskBadIntId)
	errWant = "Bad task ID: string"
	if task != "" {
		t.Errorf("Got '%s' expected ''", task)
	}
	if err.Error() != errWant {
		t.Errorf("Got '%s' expected '%s'", err.Error(), errWant)
	}
	task, err = handler.convertTaskToResponse(exampleBeacon.GUID, exampleTaskBadIntCode)
	errWant = "Bad task code: string"
	if task != "" {
		t.Errorf("Got '%s' expected ''", task)
	}
	if err.Error() != errWant {
		t.Errorf("Got '%s' expected '%s'", err.Error(), errWant)
	}
}

func TestGetTask(t *testing.T) {
	// set current working directory to main repo directory
	// this is needed so that the unit tests can find the requested payload
	cwd, _ := os.Getwd()
	os.Chdir("../../")
	defer os.Chdir(cwd) // restore cwd at end of test
	
	// start REST API
	startRESTAPI(t)
	defer stopRESTAPI(t)

	handler := carbonHttpHandlerFactory(false, mockGenRandBytes)

	// start handler
	startCarbonHttpHandler(handler, t)
	defer stopCarbonHttpHandler(handler, t)

	registerStatus, registerBody := sendImplantBeacon(t, exampleBeacon.GUID, registerURL)
	if string(registerStatus) != serverMsgOK {
		t.Errorf("Status mismatch, got '%s' expected '%s'", string(registerStatus), serverMsgOK)
	}
	if string(registerBody) != "" {
		t.Errorf("Got '%s' expected '%s'", string(registerBody), commandResponseBlankWant)
	}

	// set a task for the session and check that the correct output is given
	setAndGetTaskCheckOutput(t, exampleTask, exampleBeacon.GUID, serverMsgOK, commandResponseFilledWant)

	// send another beacon to ensure that there isn't another task
	blankTaskStatus, blankTaskBody := sendImplantBeacon(t, exampleBeacon.GUID, commandURL)
	if string(blankTaskStatus) != serverMsgOK {
		t.Errorf("Status mismatch, got '%s' expected '%s'", string(blankTaskStatus), serverMsgOK)
	}
	if string(blankTaskBody) != commandResponseBlankWant {
		t.Errorf("Got '%s' expected '%s'", string(blankTaskBody), commandResponseBlankWant)
	}
}
