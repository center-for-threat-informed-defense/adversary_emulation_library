package exaramel_test

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"attackevals.mitre-engenuity.org/control_server/handlers/exaramel"
	"attackevals.mitre-engenuity.org/control_server/restapi"
	"github.com/google/go-cmp/cmp"
)

const proto = "https://"
const listenHost = "127.0.0.1:8088"
const handlerAPIPathPrefix = "/api/v1"
const restAPIlistenHost = "127.0.0.1:9988"
const restAPIBaseURL = "http://" + restAPIlistenHost + "/api/v1.0/"
const registerImplantURL = proto + listenHost + handlerAPIPathPrefix + "/auth/app"
const getTaskURL = proto + listenHost + handlerAPIPathPrefix + "/tasks.get/"
const postOutputURL = proto + listenHost + handlerAPIPathPrefix + "/tasks.report/"
const getFileURL = proto + listenHost + handlerAPIPathPrefix + "/attachment.get/"

// exampleBeacon shows how to construct a well formed beacon
type AuthStruct struct {
	guid       string
	whoami     string
	platform   string
	version    string
	generation string
	ip         string
	pid        string
	ppid       string
}

var exampleAuth = AuthStruct{
	guid:       "exaramel-implant",
	whoami:     "myUserName",
	platform:   "Linux ubuntu-focal 5.8.0-53-generic #60~20.04.1-Ubuntu Other Garbage",
	version:    "0.1",
	generation: "1",
	ip:         "127.0.0.1",
	pid:        "2222",
	ppid:       "1111",
}

func startExaramelHandler() {
	exaramel.StartHandler(listenHost, restAPIlistenHost, "", "")
	time.Sleep(50 * time.Millisecond)
}

func stopExaramelHandler() {
	exaramel.StopHandler()
	time.Sleep(50 * time.Millisecond)
}

func startRESTAPI() {
	restapi.Start(restAPIlistenHost)
	time.Sleep(50 * time.Millisecond)
}

func stopRESTAPI() {
	restapi.Stop()
	time.Sleep(50 * time.Millisecond)
}

func disableCertCheck() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

func registerImplant(registerURL string) (string, error) {

	data := url.Values{}
	data.Set("guid", exampleAuth.guid)
	data.Set("whoami", exampleAuth.whoami)
	data.Set("platform", exampleAuth.platform)
	data.Set("version", exampleAuth.version)
	data.Set("generation", exampleAuth.generation)
	data.Set("ip", exampleAuth.ip)
	data.Set("pid", exampleAuth.pid)
	data.Set("ppid", exampleAuth.ppid)

	disableCertCheck()
	req, err := http.NewRequest("POST", registerURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

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

func SetTask(task string, guid string) (string, error) {
	url := restAPIBaseURL + "task/" + guid
	command := task

	// setup HTTP POST request
	disableCertCheck()
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(command))
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

func GetTask(guid string) ([]byte, error) {
	url := getTaskURL + guid
	disableCertCheck()
	response, err := http.Get(url)
	if err != nil {
		return []byte(""), err
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return []byte(""), err
	}
	return body, nil
}

func TestStartStopTrickBotHandler(t *testing.T) {
	startExaramelHandler()
	stopExaramelHandler()
}

func TestResgisterImplant(t *testing.T) {

	// start REST API
	startRESTAPI()
	defer stopRESTAPI()

	// start handler
	startExaramelHandler()
	defer stopExaramelHandler()

	// test implant registration against handler
	response, err := registerImplant(registerImplantURL)
	if err != nil {
		t.Error(err)
	}

	var expectedOutput exaramel.RespAuth
	expectedOutput.Auth.GUID = "exaramel-implant"
	expectedOutput.Auth.AuthResult = 1

	var actualOutput exaramel.RespAuth
	json.Unmarshal([]byte(response), &actualOutput)

	if !cmp.Equal(expectedOutput, actualOutput) {
		t.Errorf("Got '%+v' expected '%+v'", actualOutput, expectedOutput)
	}
}

func TestGetTask(t *testing.T) {
	// start REST API
	startRESTAPI()
	defer stopRESTAPI()

	// start handler
	startExaramelHandler()
	defer stopExaramelHandler()

	_, err := registerImplant(registerImplantURL)
	if err != nil {
		t.Error(err)
	}

	_, err = SetTask("exec whoami", exampleAuth.guid)
	if err != nil {
		t.Error(err)
	}

	response, err := GetTask(exampleAuth.guid)
	if err != nil {
		t.Error(err)
	}

	var expectedOutput = exaramel.Tasks{
		Response: []exaramel.TaskResponse{
			{
				ID:                1,
				Method:            exaramel.OSShellExecute.String(),
				Arguments:         "whoami",
				Attachment:        0,
				AnswerWait:        0,
				DoAsync:           0,
				AnswerImmediately: 0,
				WaitOutputTime:    0,
			},
		},
	}

	var actualOutput exaramel.Tasks
	json.Unmarshal([]byte(response), &actualOutput)

	if !cmp.Equal(expectedOutput, actualOutput) {
		t.Errorf("Got '%+v' expected '%+v'", actualOutput, expectedOutput)
	}
}

func TestPostTaskOutput(t *testing.T) {

	// start REST API
	startRESTAPI()
	defer stopRESTAPI()

	// start handler
	startExaramelHandler()
	defer stopExaramelHandler()

	_, err := registerImplant(registerImplantURL)
	if err != nil {
		t.Error(err)
	}

	_, err = SetTask("exec whoami", exampleAuth.guid)
	if err != nil {
		t.Error(err)
	}

	body, err := GetTask(exampleAuth.guid)
	if err != nil {
		t.Error(err)
	}

	var getTaskOutput exaramel.Tasks
	json.Unmarshal([]byte(body), &getTaskOutput)
	taskID := getTaskOutput.Response[0].ID

	// Posting task output
	values := map[string]string{
		"guid":    exampleAuth.guid,
		"task_id": strconv.Itoa(int(taskID)),
		"file":    "this is example task output",
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for key, val := range values {
		var fw io.Writer
		if fw, err = w.CreateFormField(key); err != nil {
			t.Error(err)
		}
		if _, err = io.Copy(fw, strings.NewReader(val)); err != nil {
			t.Error(err)
		}
	}
	w.Close()

	// setup HTTP POST request
	disableCertCheck()
	req, err := http.NewRequest("POST", postOutputURL, &buf)
	if err != nil {
		t.Error(err)
	}

	req.Header.Set("Content-Type", w.FormDataContentType())

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

	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}

	var expectedOutput exaramel.Reports
	expectedOutput.Response.ID = exampleAuth.guid
	expectedOutput.Response.CommandID = taskID
	expectedOutput.Response.Status = 1

	var actualOutput exaramel.Reports
	json.Unmarshal([]byte(body), &actualOutput)

	if !cmp.Equal(expectedOutput, actualOutput) {
		t.Errorf("Got '%+v' expected '%+v'", actualOutput, expectedOutput)
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
	startExaramelHandler()
	defer stopExaramelHandler()

	fileData, err := exaramel.ForwardGetFileFromServer("hello_world.elf")
	if err != nil {
		t.Error(err)
	}

	goodHash := "fe7c47d38224529c7d8f9a11a62cdd7a"
	h := md5.Sum([]byte(fileData))
	actualHash := hex.EncodeToString(h[:])
	if goodHash != actualHash {
		t.Errorf("Expected %v, got %v", goodHash, actualHash)
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
	startExaramelHandler()
	defer stopExaramelHandler()

	_, err := registerImplant(registerImplantURL)
	if err != nil {
		t.Error(err)
	}

	_, err = SetTask("put hello_world.elf /tmp/hello_world.elf", exampleAuth.guid)
	if err != nil {
		t.Error(err)
	}

	body, err := GetTask(exampleAuth.guid)
	if err != nil {
		t.Error(err)
	}

	var getTaskOutput exaramel.Tasks
	json.Unmarshal([]byte(body), &getTaskOutput)
	taskID := getTaskOutput.Response[0].ID

	// download the test file
	disableCertCheck()
	url := getFileURL + exampleAuth.guid + "/" + strconv.Itoa(int(taskID))
	resp, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}
	// read test file bytes
	fileData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	// compare file hashes
	goodHash := "fe7c47d38224529c7d8f9a11a62cdd7a"
	h := md5.Sum(fileData)
	actualHash := hex.EncodeToString(h[:])
	if goodHash != actualHash {
		t.Errorf("Expected %v, got %v", goodHash, actualHash)
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
	startExaramelHandler()
	defer stopExaramelHandler()

	testFile := "./files/hello_world.elf"
	fileNameOnUpload := "test_binary.elf"
	fileData, err := ioutil.ReadFile(testFile)
	if err != nil {
		t.Error(err)
	}

	// invoke file upload
	got, err := exaramel.ForwardPostFileToServer(fileNameOnUpload, fileData)
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
	startExaramelHandler()
	defer stopExaramelHandler()

	_, err := registerImplant(registerImplantURL)
	if err != nil {
		t.Error(err)
	}

	_, err = SetTask("get ./files/hello_world.elf test_file.elf", exampleAuth.guid)
	if err != nil {
		t.Error(err)
	}

	body, err := GetTask(exampleAuth.guid)
	if err != nil {
		t.Error(err)
	}

	var getTaskOutput exaramel.Tasks
	json.Unmarshal([]byte(body), &getTaskOutput)
	taskID := getTaskOutput.Response[0].ID
	uploadFile := getTaskOutput.Response[0].Arguments

	testFileName := "test_file.elf"

	// Posting task output
	values := map[string]string{
		"guid":    exampleAuth.guid,
		"task_id": strconv.Itoa(int(taskID)),
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for key, val := range values {
		var fw io.Writer
		if fw, err = w.CreateFormField(key); err != nil {
			t.Error(err)
		}
		if _, err = io.Copy(fw, strings.NewReader(val)); err != nil {
			t.Error(err)
		}
	}

	fileReader, err := os.Open(uploadFile)
	if err != nil {
		t.Error(err)
	}
	var fw io.Writer
	if fw, err = w.CreateFormFile("file", filepath.Base(uploadFile)); err != nil {
		t.Error(err)
	}
	if _, err = io.Copy(fw, fileReader); err != nil {
		t.Error(err)
	}
	fileReader.Close()

	w.Close()

	// setup HTTP POST request
	disableCertCheck()
	req, err := http.NewRequest("POST", postOutputURL, &buf)
	if err != nil {
		t.Error(err)
	}

	req.Header.Set("Content-Type", w.FormDataContentType())

	// execute HTTP POST and read response
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer response.Body.Close()

	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}

	var expectedOutput exaramel.Reports
	expectedOutput.Response.ID = exampleAuth.guid
	expectedOutput.Response.CommandID = taskID
	expectedOutput.Response.Status = 1

	var actualOutput exaramel.Reports
	json.Unmarshal([]byte(body), &actualOutput)

	if !cmp.Equal(expectedOutput, actualOutput) {
		t.Errorf("Got '%+v' expected '%+v'", actualOutput, expectedOutput)
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
