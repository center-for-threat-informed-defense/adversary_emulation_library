package emotet_test

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"
	
	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/handlers/emotet"
	"attackevals.mitre-engenuity.org/control_server/logger"
	"attackevals.mitre-engenuity.org/control_server/restapi"
)

var exampleBeacon = "emotetImplantExampleGUID:"

var restAPIlistenHost = "127.0.0.1:9996"

var baseURL string = "http://localhost"

var registerImplantRoute = "/"
var serveModuleRoute = "/modules"
var getTaskRoute = "/getTask"
var getTaskOutputRoute = "/output"

var aeskey = "1234567890123456"

var handler = &emotet.EmotetHandler{}
var configEntry = config.HandlerConfigEntry{
	"host": "127.0.0.1",
	"port": "80",
	
}

func startEmotetHandler(t *testing.T) {
	if err := handler.StartHandler(restAPIlistenHost, configEntry); err != nil {
		t.Errorf("Error when starting emotet handler: %s", err.Error())
	}
	time.Sleep(50 * time.Millisecond)
}

func stopEmotetHandler(t *testing.T) {
	if err := handler.StopHandler(); err != nil {
		t.Errorf("Error when stopping emotet handler: %s", err.Error())
	}
	time.Sleep(50 * time.Millisecond)
}

func startRESTAPI() {
	restapi.Start(restAPIlistenHost, "./test_payloads")
	time.Sleep(50 * time.Millisecond)
}

func stopRESTAPI() {
	restapi.Stop()
	time.Sleep(50 * time.Millisecond)
}

func TestStartStopEmotetHandler(t *testing.T) {
	startEmotetHandler(t)
	stopEmotetHandler(t)
}


func registerImplant(registerURL string) (string, error) {

	encryptedEncodedString := emotet.EncryptEncode(exampleBeacon + "test;;hosttest;;C:\\test;;1;;0")

	// setup HTTP POST request
	req, err := http.NewRequest("POST", registerURL, bytes.NewBuffer([]byte(encryptedEncodedString)))
	if err != nil {
		return "", err
	}

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
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	return string(body), err
}

func TestResgisterImplant(t *testing.T) {

	// start REST API
	startRESTAPI()
	defer stopRESTAPI()

	// start handler
	startEmotetHandler(t)
	defer stopEmotetHandler(t)

	registerImplantURL := fmt.Sprintf("%s%s", baseURL, registerImplantRoute)

	// test implant registration against handler
	encryptedResponse, err := registerImplant(registerImplantURL)
	if err != nil {
		t.Error(err)
	}

	response := emotet.DecodeDecrypt([]byte(encryptedResponse))

	expectedOutput := "successfully added session"
	if string(response) != expectedOutput {
		t.Errorf("Got '%v' expected '%v'", response, expectedOutput)
	}
}

func TestGetTask(t *testing.T) {
	// start REST API
	startRESTAPI()
	defer stopRESTAPI()

	// start handler
	startEmotetHandler(t)
	defer stopEmotetHandler(t)

	// Set dummy task
	guidstripcolon := exampleBeacon[:len(exampleBeacon)-1] 
	registerURL := "http://" + restAPIlistenHost + "/api/v1.0/task/" + guidstripcolon

	task := "testdummytask"

	reqRest, err := http.NewRequest("POST", registerURL, bytes.NewBuffer([]byte(task)))
	if err != nil {
		t.Error(err)
	}

	// execute HTTP POST request and read response
	clientRest := &http.Client{}
	responseRest, err := clientRest.Do(reqRest)
	if err != nil {
		t.Error(err)
	}
	defer responseRest.Body.Close()

	encryptedEncodedGuid := emotet.EncryptEncode(exampleBeacon)
	url := fmt.Sprintf("%s%s", baseURL, getTaskRoute)
	req, err := http.NewRequest("GET", url, bytes.NewBuffer([]byte(encryptedEncodedGuid)))
	if err != nil {
		t.Error(err)
	}
	// execute HTTP POST request and read response
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer response.Body.Close()
	encryptedBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}

	body := emotet.DecodeDecrypt(encryptedBody)

	expectedOutput := "testdummytask"
	if string(body) != expectedOutput {
		t.Errorf("Got '%v' expected '%v'", string(body), expectedOutput)
	}
}

func TestPostTaskOutput(t *testing.T) {

	// start REST API
	startRESTAPI()
	defer stopRESTAPI()

	// start handler
	startEmotetHandler(t)
	defer stopEmotetHandler(t)

	output := exampleBeacon + "this is example task output"

	encryptedEncodedString := emotet.EncryptEncode(output)

	// setup HTTP POST request
	postOutputURL := fmt.Sprintf("%s%s", baseURL, getTaskOutputRoute)
	req, err := http.NewRequest("POST", postOutputURL, bytes.NewBufferString(encryptedEncodedString))
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

	encryptedBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}

	body := emotet.DecodeDecrypt(encryptedBody)

	expectedOutput := "successfully set task output"
	if string(body) != expectedOutput {
		t.Errorf("Expected \"%v\", got \"%v\"", expectedOutput, string(body))
	}
}

func TestForwardGetFileFromServer(t *testing.T) {

	// set current working directory to wizard_spider/Resources/control_server
	// this is needed so that the unit tests can find ./config/config.yml
	cwd, _ := os.Getwd()
	os.Chdir("../../")
	defer os.Chdir(cwd) // restore cwd at end of test

	// start REST API
	startRESTAPI()
	defer stopRESTAPI()

	// start handler
	startEmotetHandler(t)
	defer stopEmotetHandler(t)

	fileData, err := emotet.ForwardGetFileFromServer("OutlookScraper.dll")
	if err != nil {
		t.Error(err)
	}

	goodHash := "7a33eb2f7fcf960244bb9a205114999b"
	h := md5.Sum([]byte(fileData))
	actualHash := hex.EncodeToString(h[:])
	if goodHash != actualHash {
		t.Errorf("Expected %v, got %v", goodHash, actualHash)
	}
}

// checks if 200 OK is returned from serving module
func TestServeModule(t *testing.T) {

	startEmotetHandler(t)
	defer stopEmotetHandler(t)

	ServeModuleURL := fmt.Sprintf("%s%s", baseURL, serveModuleRoute)
	logger.Info(fmt.Sprintf("Sending GET request to URL: %s", serveModuleRoute))

	req, err := http.NewRequest("GET", ServeModuleURL, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(emotet.ServeModule)

	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}
