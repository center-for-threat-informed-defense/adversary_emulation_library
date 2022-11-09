package sessions_test

import (
	"testing"

	"attackevals.mitre-engenuity.org/control_server/sessions"
)

var mySesssion = sessions.Session{
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

func TestAddSession(t *testing.T) {

	err := sessions.AddSession(mySesssion)
	if err != nil {
		t.Error(err)
	}
}

func TestUpdateLastCheckin(t *testing.T) {

	valid, index := sessions.SessionExists(mySesssion.GUID)
	if !valid {
		t.Error("Invalid session: ", mySesssion.GUID)
	}

	sessions.UpdateLastCheckin(mySesssion.GUID)
	got := sessions.SessionList[index].LastCheckIn
	want := sessions.GetCurrentTimeFmt()

	if got != want {
		t.Errorf("Expected return value of %v, got %v\n", want, got)
	}
}

func TestSessionExists(t *testing.T) {
	want := true
	got, _ := sessions.SessionExists(mySesssion.GUID)
	if got != want {
		t.Errorf("Expected return value of %v, got %v\n", want, got)
	}

	// test error condition
	want = false
	got, _ = sessions.SessionExists("this should return false")
	if got != want {
		t.Errorf("Expected return value of %v, got %v\n", want, got)
	}
}

func TestGetSessionList(t *testing.T) {
	sessionList := sessions.GetSessionList()
	want := true
	got, _ := sessions.SessionExists(sessionList[0].GUID)
	if got != want {
		t.Errorf("Expected return value of %v, got %v\n", want, got)
	}
}

func TestGetSessionByName(t *testing.T) {
	theSession, err := sessions.GetSessionByName(mySesssion.GUID)
	if err != nil {
		t.Error(err)
	}
	want := true
	got, _ := sessions.SessionExists(theSession.GUID)
	if got != want {
		t.Errorf("Expected return value of %v, got %v\n", want, got)
	}

	_, err = sessions.GetSessionByName("test nonexistent session id")
	if err == nil {
		t.Errorf("Expected an error for bad session, got %v\n", err)
	}
}

func TestSetSessionTask(t *testing.T) {
	expectedTask := "exec-cmd \"whoami\""
	err := sessions.SetTask(mySesssion.GUID, expectedTask)
	if err != nil {
		t.Error(err)
	}
	valid, index := sessions.SessionExists(mySesssion.GUID)
	if !valid {
		t.Error("Invalid session: ", mySesssion.GUID)
	}
	actualTask := sessions.SessionList[index].Task
	if expectedTask != actualTask {
		t.Errorf("Expected return value of %v, got %v\n: ", expectedTask, actualTask)
	}

	expectedTask = "ipconfig"
	err = sessions.SetTask(mySesssion.GUID, expectedTask)
	if err != nil {
		t.Error(err)
	}
	actualTask = sessions.SessionList[index].Task
	if expectedTask != actualTask {
		t.Errorf("Expected return value of %v, got %v\n: ", expectedTask, actualTask)
	}

}

func TestGetSessionTask(t *testing.T) {
	_, err := sessions.GetTask(mySesssion.GUID)
	if err != nil {
		t.Error(err)
	}
}

func TestRemoveSessionTask(t *testing.T) {
	err := sessions.RemoveTask(mySesssion.GUID)
	if err != nil {
		t.Error(err)
	}
	blankTask, err := sessions.GetTask(mySesssion.GUID)
	if err != nil {
		t.Error(err)
	}
	if blankTask != "" {
		t.Errorf("Expected blank task \"\" got %v", blankTask)
	}
}

func TestBootstrapTask(t *testing.T) {
	expectedTask := "exec-cmd \"whoami\""
	handler := "handler1"
	currBootstrap := sessions.GetBootstrapTask(handler)
	if len(currBootstrap) > 0 {
		t.Errorf("Expected empty bootstrap task for %s, got: %s", handler, currBootstrap)
	}
	
	sessions.SetBootstrapTask(handler, expectedTask)
	currBootstrap = sessions.GetBootstrapTask(handler)
	if currBootstrap != expectedTask {
		t.Errorf("Expected bootstrap task of %s, got %s\n: ", expectedTask, currBootstrap)
	}
	currBootstrap = sessions.GetBootstrapTask("handler2")
	if len(currBootstrap) > 0 {
		t.Errorf("Expected empty bootstrap task for handler2, got: %s", currBootstrap)
	}
	
	sessions.RemoveBootstrapTask(handler)
	currBootstrap = sessions.GetBootstrapTask(handler)
	if len(currBootstrap) > 0 {
		t.Errorf("Expected empty bootstrap task, got: %s", currBootstrap)
	}
}

// this tests SetTaskOutput, GetTaskOutput, and DeleteTaskOutput
// To Do - split these into individual tests
func TestTaskOutput(t *testing.T) {
	valid, _ := sessions.SessionExists(mySesssion.GUID)
	if !valid {
		t.Error("Invalid session: ", mySesssion.GUID)
	}

	// test SetTaskOutput
	expectedOutput := "user"
	err := sessions.SetTaskOutput(mySesssion.GUID, expectedOutput)
	if err != nil {
		t.Error(err)
	}

	// test GetTaskOutput
	actualOutput, err := sessions.GetTaskOutput(mySesssion.GUID)
	if err != nil {
		t.Error(err)
	}

	if expectedOutput != actualOutput {
		t.Errorf("Expected return value of %v, got %v\n: ", expectedOutput, actualOutput)
	}

	// test DeleteTaskOutput
	err = sessions.DeleteTaskOutput(mySesssion.GUID)
	if err != nil {
		t.Error(err)
	}
	want := ""
	got, err := sessions.GetTaskOutput(mySesssion.GUID)
	if err != nil {
		t.Error(err)
	}
	if got != want {
		t.Errorf("Expected %v got %v", want, got)
	}
}

func TestRemoveSession(t *testing.T) {
	sessions.RemoveSession(mySesssion.GUID)
	sessionFound, _ := sessions.SessionExists(mySesssion.GUID)
	if sessionFound == true {
		t.Error("Unable to delete session")
	}
}
