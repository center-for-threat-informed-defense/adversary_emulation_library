package trickbot_test

import (
	"fmt"
	"time"
	"os"
	"bytes"
	"strings"
	"testing"
	"net/http"
	"io/ioutil"
	"crypto/md5"
	"encoding/hex"
	"net/http/httptest"

	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/handlers/trickbot"
	"attackevals.mitre-engenuity.org/control_server/logger"
	"attackevals.mitre-engenuity.org/control_server/restapi"
)

var baseURL = "http://127.0.0.1:447/"
var restAPIlistenHost = "127.0.0.1:9997"
var campaign_id = "camp1"
var client_id = "DMIN_W617601.HATGSF1265TRQIKSH54367FSGDHUIA11"
var random_string = "HAGSTGST123"

var handler = &trickbot.TrickbotHandler{}
var configEntry = config.HandlerConfigEntry{
	"host": "127.0.0.1",
	"port": "447",
}

func startTrickBotHandler(t *testing.T) {
	if err := handler.StartHandler(restAPIlistenHost, configEntry); err != nil {
		t.Errorf("Error when starting Trickbot handler: %s", err.Error())
	}
	time.Sleep(100 * time.Millisecond)
}

func stopTrickBotHandler(t *testing.T) {
	if err := handler.StopHandler(); err != nil {
		t.Errorf("Error when stopping Trickbot handler: %s", err.Error())
	}
	time.Sleep(200 * time.Millisecond)
}

func startRESTAPI() {
	restapi.Start(restAPIlistenHost, "./test_payloads")
	time.Sleep(100 * time.Millisecond)
}

func stopRESTAPI() {
	restapi.Stop()
	time.Sleep(200 * time.Millisecond)
}

func TestStartStopTrickBotHandler(t *testing.T) {
	startTrickBotHandler(t)
	stopTrickBotHandler(t)
}

func TestStartStopRESTAPI(t *testing.T) {
	startRESTAPI()
	stopRESTAPI()
}

// params format
// campaign id/client_id/command_id/winver/hardcoded_id/external_ip/sha256_adapaters_info/random_string
// checks if 200 OK is returned during registration
func TestRegister(t *testing.T) {
	var command = "0"
	var windows_ver = "Windows%207%20x64"
	var hardcoded_id = "1234"
	var external_ip = "0.0.0.0"
	var adapter_sha256 = "GAVHSGFD12345ATGSHBDSAFSGTAGSBHSGFSDATQ12345AGSFSGBDISHJKAGS2343"
	var cwd = "C:"
	var pid = "1111"
	var ppid = "2222"

	startRESTAPI()
	defer stopRESTAPI()

	startTrickBotHandler(t)
	defer stopTrickBotHandler(t)
	registerURL := fmt.Sprintf("%s%s/%s/%s/%s/%s/%s/%s/%s/%s/%s/%s", baseURL, campaign_id, client_id, command, windows_ver, hardcoded_id, external_ip, adapter_sha256, cwd, pid, ppid, random_string)
	req, err := http.NewRequest("GET", registerURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	logger.Info(response.StatusCode)
	if response.StatusCode != 200 {
		t.Fatal(err)
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}

	expectedOutput := "successfully added session"
	if string(body) != expectedOutput {
		t.Fatalf("Got '%s' expected '%v'", string(body), expectedOutput)
	}
}

func TestGetTask(t *testing.T) {
	var command = "80"

	// start REST API
	startRESTAPI()
	defer stopRESTAPI()

	startTrickBotHandler(t)
	defer stopTrickBotHandler(t)
	getTaskUrl := fmt.Sprintf("%s%s/%s/%s/%s", baseURL, campaign_id, client_id, command, random_string)

	req, err := http.NewRequest("GET", getTaskUrl, nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(trickbot.HandleGetTask)

	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestPostTaskOutput(t *testing.T) {
	var command = "10"
	// start REST API
	startRESTAPI()
	defer stopRESTAPI()

	// start handler
	startTrickBotHandler(t)
	defer stopTrickBotHandler(t)

	getTaskUrl := fmt.Sprintf("%s%s/%s/%s/%s", baseURL, campaign_id, client_id, command, random_string)
	output := "this is example task output"

	// setup HTTP POST request
	req, err := http.NewRequest("POST", getTaskUrl, bytes.NewBufferString(output))
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
	expectedOutput := "successfully set task output"
	if string(body) != expectedOutput {
		t.Errorf("Expected \"%v\", got \"%v\"", expectedOutput, string(body))
	}
}

func TestDownload(t *testing.T) {
	var command = "5"
	var filename = "hello_world.elf"
	
	cwd, _ := os.Getwd()
	os.Chdir("../../")
	defer os.Chdir(cwd)
	
	startRESTAPI()
	defer stopRESTAPI()
	
	startTrickBotHandler(t)
	defer stopTrickBotHandler(t)
	
	downloadFileURL := fmt.Sprintf("%s%s/%s/%s/%s/%s", baseURL, campaign_id, client_id, command, filename, random_string)
	req, err := http.NewRequest("GET", downloadFileURL, nil)
	if err != nil {
		t.Fatal(err)
	}

	// execute HTTP GET and read response
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		t.Fatalf("Expected error code 200, got %v", response.StatusCode)
	}

	fileData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	goodHash := "fe7c47d38224529c7d8f9a11a62cdd7a"
	h := md5.Sum(fileData)
	actualHash := hex.EncodeToString(h[:])
	if goodHash != actualHash {
		t.Errorf("Expected %v, got %v", goodHash, actualHash)
	}
}

func TestPostFileToServer(t *testing.T) {
	// set current working directory to wizard_spider/Resources/control_server
	// this is needed so that the unit tests can find ./config/config.yml
	var command = "6"
	cwd, _ := os.Getwd()
	os.Chdir("../../")
	defer os.Chdir(cwd) // restore cwd at end of test

	// start REST API
	startRESTAPI()
	defer stopRESTAPI()
	
	startTrickBotHandler(t)
	defer stopTrickBotHandler(t)
	// read file to upload
	// pass file data to function
	// validate response

	testFile := "./test_payloads/hello_world.elf"
	// testFileName := "hello_world.elf"
	outputFilename := "hello_world2.elf"
	fileData, err := ioutil.ReadFile(testFile)
	if err != nil {
		t.Error(err)
	}

	getFileUrl := fmt.Sprintf("%s%s/%s/%s/%s/%s", baseURL, campaign_id, client_id, command, outputFilename, random_string)

	response, err := http.Post(getFileUrl, "application/octet-stream", bytes.NewBuffer(fileData))
	if err != nil {
		t.Error(err)
	}
	s, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}
	temp := string(s)
	got := strings.TrimSuffix(temp, "\n")
	want := "Successfully uploaded file to control server at './files/hello_world2.elf'"
	if got != want {
		t.Errorf("Expected: \n%v \ngot: \n%v", want, got)
	}
	// confirm file made it to disk properly
	// read test file bytes
	uploadedFile := "./files/" + outputFilename
	uploadedFileData, err := ioutil.ReadFile(uploadedFile)
	if err != nil {
		t.Error(err)
	}
	// compare file hashes
	goodHash := "fe7c47d38224529c7d8f9a11a62cdd7a"
	h := md5.Sum(uploadedFileData)
	actualHash := hex.EncodeToString(h[:])
	if goodHash != actualHash {
		t.Errorf("Expected %v, got %v", goodHash, actualHash)
	}

	err = os.Remove(uploadedFile)
	if err != nil {
		t.Error(err)
	}
}
