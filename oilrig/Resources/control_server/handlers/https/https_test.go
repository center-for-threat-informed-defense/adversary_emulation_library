package https_test

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/handlers/https"
	"attackevals.mitre-engenuity.org/control_server/restapi"
	"attackevals.mitre-engenuity.org/control_server/sessions"
)

var restAPIlistenHost = "127.0.0.1:9995"
var registerImplantURL = "https://127.0.0.1:8443/register"
var getTaskURL = "https://127.0.0.1:8443/task"
var postOutputURL = "https://127.0.0.1:8443/output"
var getFileURL = "https://127.0.0.1:8443/getFile"
var putFileURL = "https://127.0.0.1:8443/putFile"
var certFile string
var keyFile string

// exampleBeacon shows how to construct a well formed beacon
var exampleBeacon = sessions.Session{
	GUID:     "https-implant",
	IPAddr:   "127.0.0.1",
	HostName: "myHostName",
	User:     "myUserName",
	Dir:      "C:\\MyDir\\",
	PID:      1234,
	PPID:     4,
	Task:     "whoami",
}

var handler = &https.HttpsHandler{}
var configEntry = config.HandlerConfigEntry{
	"host": "127.0.0.1",
	"port": "8443",
	"cert_file": "",
	"key_file": "",
}

func startHTTPSHandler(t *testing.T) {
	if err := handler.StartHandler(restAPIlistenHost, configEntry); err != nil {
		t.Errorf("Error when starting HTTPS handler: %s", err.Error())
	}
	time.Sleep(50 * time.Millisecond)
}

func stopHTTPSHandler(t *testing.T) {
	if err := handler.StopHandler(); err != nil {
		t.Errorf("Error when stopping HTTPS handler: %s", err.Error())
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

func registerImplant(registerURL string) (string, error) {

	// convert exampleBeacon data into JSON
	exampleBeaconJSON, err := json.Marshal(exampleBeacon)
	if err != nil {
		return "", err
	}

	// setup HTTP POST request
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	req, err := http.NewRequest("POST", registerURL, bytes.NewBuffer(exampleBeaconJSON))
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
	startHTTPSHandler(t)
	defer stopHTTPSHandler(t)

	// test implant registration against handler
	response, err := registerImplant(registerImplantURL)
	if err != nil {
		t.Error(err)
	}

	expectedOutput := "successfully added session"
	if string(response) != expectedOutput {
		t.Errorf("Got '%v' expected '%v'", response, expectedOutput)
	}

	// delete implant?

}

func TestGetTask(t *testing.T) {
	// start REST API
	startRESTAPI()
	defer stopRESTAPI()

	// start handler
	startHTTPSHandler(t)
	defer stopHTTPSHandler(t)

	url := getTaskURL + "/" + exampleBeacon.GUID
	response, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}

	expectedOutput := "whoami"
	if string(body) != expectedOutput {
		t.Errorf("Got '%v' expected '%v'", response, expectedOutput)
	}
}

func TestPostTaskOutput(t *testing.T) {

	// start REST API
	startRESTAPI()
	defer stopRESTAPI()

	// start handler
	startHTTPSHandler(t)
	defer stopHTTPSHandler(t)

	url := postOutputURL + "/" + exampleBeacon.GUID
	output := "this is example task output"

	// setup HTTP POST request
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(output))
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
	startHTTPSHandler(t)
	defer stopHTTPSHandler(t)

	resp, err := https.ForwardGetFileFromServer("hello_world.elf")
	if err != nil {
		t.Error(err)
	}
	fileData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}

	goodHash := "fe7c47d38224529c7d8f9a11a62cdd7a"
	h := md5.Sum([]byte(fileData))
	actualHash := hex.EncodeToString(h[:])
	if goodHash != actualHash {
		t.Errorf("Expected %v, got %v", goodHash, actualHash)
	}

	// test non-existent file
	resp2, err := https.ForwardGetFileFromServer("does_not_exist.txt")
	if err != nil {
		t.Error(err)
	}

	expectedErr := "404 Not Found"
	actualErr := resp2.Status
	if expectedErr != actualErr {
		t.Errorf("expected '%v' got '%v'", expectedErr, actualErr)
	}
}

func TestGetFileFromServer(t *testing.T) {
	// set current working directory to wizard_spider/Resources/control_server
	// this is needed so that the unit tests can find ./config/config.yml
	cwd, _ := os.Getwd()
	os.Chdir("../../")
	defer os.Chdir(cwd) // restore cwd at end of test

	// start REST API
	startRESTAPI()
	defer stopRESTAPI()

	// start handler
	startHTTPSHandler(t)
	defer stopHTTPSHandler(t)

	// download the test file
	url := getFileURL + "/hello_world.elf"
	resp, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}

	// Create the file
	filepath := "/tmp/hello_world.elf"
	out, err := os.Create(filepath)
	if err != nil {
		t.Error(err)
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		t.Error(err)
	}

	// compare file hashes
	goodHash := "fe7c47d38224529c7d8f9a11a62cdd7a"
	fileData, err := ioutil.ReadFile(filepath)
	if err != nil {
		t.Error(err)
	}
	h := md5.Sum(fileData)
	actualHash := hex.EncodeToString(h[:])
	if goodHash != actualHash {
		t.Errorf("Expected %v, got %v", goodHash, actualHash)
	}

	// test non-existent file
	url = getFileURL + "/does_not_exist.txt"
	resp2, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}

	expectedErr := "404 Not Found"
	actualErr := resp2.Status
	if expectedErr != actualErr {
		t.Errorf("expected '%v' got '%v'", expectedErr, actualErr)
	}
}

func TestForwardPostFileToServer(t *testing.T) {
	// set current working directory to wizard_spider/Resources/control_server
	// this is needed so that the unit tests can find ./config/config.yml
	cwd, _ := os.Getwd()
	os.Chdir("../../")
	defer os.Chdir(cwd) // restore cwd at end of test

	// start REST API
	startRESTAPI()
	defer stopRESTAPI()

	// start handler
	startHTTPSHandler(t)
	defer stopHTTPSHandler(t)

	testFile := "./test_payloads/hello_world.elf"
	fileNameOnUpload := "test_binary.elf"
	fileData, err := ioutil.ReadFile(testFile)
	if err != nil {
		t.Error(err)
	}

	// invoke file upload
	got, err := https.ForwardPostFileToServer(fileNameOnUpload, fileData)
	if err != nil {
		t.Error(err)
	}
	// validate response
	want := "Successfully uploaded file to control server at './files/test_binary.elf'\n"
	if got != want {
		t.Errorf("Expected '%v' got '%v'", want, got)
	}

	// confirm file made it to disk properly
	// read test file bytes
	uploadedFile := "./files/" + fileNameOnUpload
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

	// clean up test file
	err = os.Remove(uploadedFile)
	if err != nil {
		t.Error(err)
	}
}

func TestPostFileToServer(t *testing.T) {
	// set current working directory to wizard_spider/Resources/control_server
	// this is needed so that the unit tests can find ./config/config.yml
	cwd, _ := os.Getwd()
	os.Chdir("../../")
	defer os.Chdir(cwd) // restore cwd at end of test

	// start REST API
	startRESTAPI()
	defer stopRESTAPI()

	// start handler
	startHTTPSHandler(t)
	defer stopHTTPSHandler(t)
	// read file to upload
	// pass file data to function
	// validate response

	testFile := "./test_payloads/hello_world.elf"
	testFileName := "test_file.elf"
	fileData, err := ioutil.ReadFile(testFile)
	if err != nil {
		t.Error(err)
	}

	url := putFileURL + "/" + testFileName
	response, err := http.Post(url, "application/octet-stream", bytes.NewBuffer(fileData))
	if err != nil {
		t.Error(err)
	}
	s, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}
	temp := string(s)
	got := strings.TrimSuffix(temp, "\n")
	want := "Successfully uploaded file to control server at './files/test_file.elf'"
	if got != want {
		t.Errorf("Expected: \n%v \ngot: \n%v", want, got)
	}
	// confirm file made it to disk properly
	// read test file bytes
	uploadedFile := "./files/" + testFileName
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

	// clean up test file

	err = os.Remove(uploadedFile)
	if err != nil {
		t.Error(err)
	}
}
