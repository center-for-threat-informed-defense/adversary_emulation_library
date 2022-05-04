package restapi_test

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/logger"
	"attackevals.mitre-engenuity.org/control_server/restapi"
	"attackevals.mitre-engenuity.org/control_server/sessions"
)

var baseURL string = "http://127.0.0.1:9999/api/v1.0/"

var testSession1 = sessions.Session{
	GUID:          "abcdef123456",
	IPAddr:        "127.0.0.1",
	HostName:      "myHostName",
	User:          "myUserName",
	Dir:           "C:\\MyDir\\",
	PID:           1234,
	PPID:          4,
	SleepInterval: 60,
	Jitter:        1.5,
}

func startRESTapi() {
	// set current working directory to wizard_spider/Resources/control_server
	// this is needed so that the unit tests can find ./config/config.yml
	cwd, _ := os.Getwd()
	os.Chdir("../")
	defer os.Chdir(cwd) // restore cwd at end of test
	err := config.SetRestAPIConfig("./config/restAPI_config.yml")
	if err != nil {
		logger.Fatal(err)
	}

	restAPIaddress := config.GetRestAPIListenAddress()
	restapi.Start(restAPIaddress)
	time.Sleep(50 * time.Millisecond)
}

func stopRESTapi() {
	time.Sleep(50 * time.Millisecond)
	restapi.Stop()
}
func TestStartStopRESTapi(t *testing.T) {
	startRESTapi()
	stopRESTapi()
}

func TestGetVersion(t *testing.T) {
	startRESTapi()
	defer stopRESTapi()

	getVersionURL := baseURL + "version"
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
	want := "ATT&CK Evaluations Control Server 1.0\n"

	if got != want {
		t.Errorf("Got '%v', expected '%v'", got, want)
	}
}

func TestGetConfig(t *testing.T) {

	startRESTapi()
	defer stopRESTapi()

	getConfigURL := baseURL + "config"
	httpResponse, err := http.Get(getConfigURL)
	if err != nil {
		t.Error(err)
	}
	defer httpResponse.Body.Close()

	httpBody, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		t.Error(err)
	}

	// need additional validation logic here once config files are fully implemented
	configLength := len(httpBody)
	expectedLength := 5
	if configLength < expectedLength {
		t.Errorf("Config file is %v bytes, expected it to be greater than %v bytes", configLength, expectedLength)
	}
}

func TestCreateSession(t *testing.T) {
	// setup test dependencies
	startRESTapi()
	defer stopRESTapi()

	// http://localhost:9999/api/v1.0/session
	createSessionURL := baseURL + "session"

	// convert testSession1 object into JSON
	testSessionJSON, err := json.Marshal(testSession1)
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
	expectedOutput := "successfully added session"
	if string(body) != expectedOutput {
		t.Error(err)
	}
}

func TestGetSessions(t *testing.T) {
	startRESTapi()
	defer stopRESTapi()
	url := baseURL + "sessions"
	resp, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()
	sessionData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	if len(sessionData) < 10 {
		t.Error("Session data is too small to be valid: ", sessionData)
	}
}

func TestGetSessionByName(t *testing.T) {
	startRESTapi()
	defer stopRESTapi()

	// http://localhost:9999/api/v1.0/session/abcdef123456
	url := baseURL + "session/abcdef123456"
	resp, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()
	sessionData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	if len(sessionData) < 10 {
		t.Error("Session data is too small to be valid: ", sessionData)
	}
}

func TestSetSessionTask(t *testing.T) {
	startRESTapi()
	defer stopRESTapi()

	// http://localhost:9999/api/v1.0/task/abcdef123456
	url := baseURL + "task/abcdef123456"
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
	expectedOutput := "successfully set task"
	if string(body) != expectedOutput {
		t.Errorf("Expected \"%v\", got \"%v\"", expectedOutput, string(body))
	}
}

func TestGetSessionTask(t *testing.T) {
	startRESTapi()
	defer stopRESTapi()
	url := baseURL + "task/abcdef123456"
	resp, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()
	sessionData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	expectedTask := "whoami"
	if string(sessionData) != expectedTask {
		t.Errorf("Expected '%v' got '%v'", expectedTask, string(sessionData))
	}

}

func TestSetTaskOutput(t *testing.T) {
	startRESTapi()
	defer stopRESTapi()

	// http://localhost:9999/api/v1.0/task/output/abcdef123456
	url := baseURL + "task/output/abcdef123456"
	output := "username"

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

func TestGetTaskOutput(t *testing.T) {
	startRESTapi()
	defer stopRESTapi()
	// http://localhost:9999/api/v1.0/task/output/abcdef123456
	url := baseURL + "task/output/abcdef123456"
	resp, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()
	sessionData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	expectedOutput := "username"
	if string(sessionData) != expectedOutput {
		t.Errorf("Expected '%v' got '%v'", expectedOutput, string(sessionData))
	}
}

func TestRemoveTaskOutput(t *testing.T) {
	startRESTapi()
	defer stopRESTapi()

	// http://localhost:9999/api/v1.0/task/output/abcdef123456
	url := baseURL + "task/output/abcdef123456"

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
	expectedOutput := "successfully deleted task output for session: abcdef123456"
	if string(body) != expectedOutput {
		t.Error(err)
	}
}

func TestRemoveSession(t *testing.T) {
	startRESTapi()
	defer stopRESTapi()

	// http://localhost:9999/api/v1.0/session/abcdef123456
	url := baseURL + "session/delete/abcdef123456"

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
	expectedOutput := "successfully removed session: abcdef123456"
	if string(body) != expectedOutput {
		t.Error(err)
	}
}

func TestGetFile(t *testing.T) {
	startRESTapi()
	defer stopRESTapi()

	// set current working directory to wizard_spider/Resources/control_server
	// this is needed so that the unit tests can find ./config/config.yml
	cwd, _ := os.Getwd()
	os.Chdir("../")
	defer os.Chdir(cwd) // restore cwd at end of test

	// http://localhost:9999/api/v1.0/files/
	url := baseURL + "files/hello_world.elf"
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
	url = baseURL + "files/does_not_exist.txt"
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
	startRESTapi()
	defer stopRESTapi()

	// set current working directory to wizard_spider/Resources/control_server
	// this is needed so that the unit tests can find ./config/config.yml
	cwd, _ := os.Getwd()
	os.Chdir("../")
	defer os.Chdir(cwd) // restore cwd at end of test

	// read file
	fileData, err := ioutil.ReadFile("files/hello_world.elf")
	if err != nil {
		t.Error(err)
	}

	// upload file via HTTP POST
	url := baseURL + "upload/test_file.elf"
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
	expectedOutput := "Successfully uploaded file to control server at './files/test_file.elf'\n"
	if string(body) != expectedOutput {
		t.Error(err)
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
