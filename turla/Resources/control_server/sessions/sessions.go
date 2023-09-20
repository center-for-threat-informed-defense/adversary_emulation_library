package sessions

import (
	"errors"
	"fmt"
	"time"

	"attackevals.mitre-engenuity.org/control_server/tasks"
)

// Session describes an agent connection to the C2 server
type Session struct {
	GUID          string  		`json:"guid"`
	IPAddr        string  		`json:"ipAddr,omitempty"`
	HostName      string  		`json:"hostName,omitempty"`
	User          string  		`json:"user,omitempty"`
	Dir           string  		`json:"dir,omitempty"`
	PID           int     		`json:"pid,omitempty"`
	PPID          int     		`json:"ppid,omitempty"`
	Task          *tasks.Task   `json:"task,omitempty"`
	SleepInterval int     		`json:"sleepInterval,omitempty"`
	Jitter        float64 		`json:"jitter,omitempty"`
	FirstCheckIn  string  		`json:"firstCheckIn,omitempty"`
	LastCheckIn   string  		`json:"lastCheckIn,omitempty"`
}

var SessionList []Session

// Will contain the default bootstrap task to send to new sessions for the specified handler
var bootstrapTasks map[string]string

func init() {
	bootstrapTasks = make(map[string]string)
}

// GetCurrentTimeFmt returns the current time in a standard format: MM-DD-YY MM:HH:SS
func GetCurrentTimeFmt() string {
	currentTime := time.Now()
	formattedTime := currentTime.Format("01-02-2006 15:04:05")
	return formattedTime
}

// AddSession adds a new session to the SessionList object
func AddSession(s Session) error {

	// check if session already exists
	valid, _ := SessionExists(s.GUID)
	if valid {
		return errors.New("Session already exists")
	}
	s.FirstCheckIn = GetCurrentTimeFmt()
	SessionList = append(SessionList, s)
	valid, _ = SessionExists(s.GUID)
	if !valid {
		return fmt.Errorf("failed to add session: %v", s.GUID)
	}
	return nil
}

// UpdateLastCheckin sets session.LastCheckIn with the current time
func UpdateLastCheckin(guid string) error {
	valid, index := SessionExists(guid)
	if !valid {
		return fmt.Errorf("unable to update last checkin for session: %v", guid)
	}
	SessionList[index].LastCheckIn = GetCurrentTimeFmt()
	return nil
}

// SessionExists checks if the session specified by guid
// is present in SessionList; if a matching session is found,
// the function returns the index for the session
func SessionExists(guid string) (bool, int) {

	for index, session := range SessionList {
		if guid == session.GUID {
			return true, index
		}
	}
	// session not found
	return false, 0
}

// GetSessionList returns a list of current C2 sessions
func GetSessionList() []Session {
	return SessionList
}

// GetSessionByGuid returns details for a session by name
func GetSessionByGuid(guid string) (Session, error) {
	var session Session
	valid, index := SessionExists(guid)
	if !valid {
		return session, fmt.Errorf("unable to get info for nonexistent session: %v", guid)
	}
	session = SessionList[index]
	return session, nil
}

// SetTask creates a task for the session specified by guid
func SetTask(sessionGuid string, taskGuid string, taskCommand string) (*tasks.Task, error) {
	valid, index := SessionExists(sessionGuid)
	if !valid {
		return nil, fmt.Errorf("unable to set task for nonexistent session: %v", sessionGuid)
	}
	SessionList[index].Task = tasks.TaskFactory(taskCommand, taskGuid, tasks.GenerateUUID)
	return SessionList[index].Task, nil
}

// GetTask returns the task for the session specified by guid
func GetTask(guid string) (*tasks.Task, error) {
	valid, index := SessionExists(guid)
	if !valid {
		return nil, fmt.Errorf("unable to get task for nonexistent session: %v", guid)
	}
	return SessionList[index].Task, nil
}

// RemoveTask clears the currently queued tasking
func RemoveTask(guid string) error {
	valid, index := SessionExists(guid)
	if !valid {
		return fmt.Errorf("unable to remove nonexistent session: %v", guid)
	}
	if SessionList[index].Task != nil {
		SessionList[index].Task.CancelTask()
	}
	SessionList[index].Task = nil
	return nil
}

// SetBootstrapTask sets the default bootstrap task for new sessions for the specified handler
func SetBootstrapTask(handler, task string) {
	bootstrapTasks[handler] = task
}

// GetBootstrapTask gets the default bootstrap task for the specified handler (empty string if no task is set).
func GetBootstrapTask(handler string) string {
	if task, ok := bootstrapTasks[handler]; ok {
		return task
	}
	return ""
}

// RemoveBootstrapTask clears the currently set default bootstrap task for the handler
func RemoveBootstrapTask(handler string) {
	delete(bootstrapTasks, handler)
}

// RemoveSession deletes the session specified by guid
// note that this function only removes the session from the SessionList object
// this function does not actually terminate the beacon process on the endpoint
func RemoveSession(guid string) error {
	var err error
	valid, index := SessionExists(guid)
	if !valid {
		return fmt.Errorf("unable to remove nonexistent session: %v", guid)
	}
	SessionList, err = removeElement(SessionList, index)
	return err
}

// removeElement removes the element from []Session specified by the index i
func removeElement(s []Session, i int) ([]Session, error) {
	if i >= len(s) || i < 0 {
		return nil, fmt.Errorf("index out of range; index is %v and slice length is %v", i, len(s))
	}
	return append(s[:i], s[i+1:]...), nil
}

// SetTaskOutput stores console output for the last executed task and marks the task as completed if specified.
func SetTaskOutput(guid string, output string, markAsComplete bool) error {
	valid, index := SessionExists(guid)
	if !valid {
		return fmt.Errorf("unable to set task output for nonexistent session: %v", guid)
	}
	if SessionList[index].Task == nil {
		return fmt.Errorf("unable to set task output for session %v with nonexistent task", guid)
	}
	SessionList[index].Task.Output = output
	if markAsComplete {
		SessionList[index].Task.FinishTask()
	}
	return nil
}

// GetTaskOutput returns the task for the session specified by guid
func GetTaskOutput(guid string) (string, error) {
	valid, index := SessionExists(guid)
	if !valid {
		return "", fmt.Errorf("unable to get task output for nonexistent session: %v", guid)
	}
	if SessionList[index].Task == nil {
		return "", fmt.Errorf("unable to get task output for session %v with nonexistent task", guid)
	}
	return SessionList[index].Task.Output, nil
}

// DeleteTaskOutput returns the task for the session specified by guid
func DeleteTaskOutput(guid string) error {
	valid, index := SessionExists(guid)
	if !valid {
		return fmt.Errorf("unable to delete task output for nonexistent session: %v", guid)
	}
	if SessionList[index].Task == nil {
		return fmt.Errorf("unable to delete task output for session %v with nonexistent task", guid)
	}
	SessionList[index].Task.Output = ""
	return nil
}
