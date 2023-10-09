package tasks

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

const (
	TASK_STATUS_NEW = 0
	TASK_STATUS_PENDING = 1
	TASK_STATUS_FINISHED = 2
	TASK_STATUS_DISCARDED = 3
)

type generateUUIDWrapper func() string

// Describes a Session task.
type Task struct {
	GUID     string `json:"guid"`
	Command  string `json:"command"`
	Output   string `json:"taskOutput,omitempty"`
	Status   int 	`json:"taskStatus"`
	ExitCode int 	`json:"taskExitCode,omitempty"`
}

// Maps a Task GUID to a pointer of the corresponding object.
var taskMapping map[string](*Task)

func init() {
	taskMapping = make(map[string](*Task))
}

// Creates new task with default values. Generates random UUID if no guid provided.
func TaskFactory(command string, guid string, generateUUIDFn generateUUIDWrapper) (t *Task) {
	if len(guid) == 0 {
		guid = generateUUIDFn()
	}
	newTask := Task{
		GUID: guid,
		Command: command,
		Output: "",
		Status: TASK_STATUS_NEW,
		ExitCode: -1,
	}
	taskMapping[newTask.GUID] = &newTask
	return taskMapping[newTask.GUID]
}

// Returns task from taskMapping based on guid provided
func GetTaskById(guid string) (*Task, error) {
	if task, valueExists := taskMapping[guid]; valueExists {
		return task, nil
	}
	return nil, errors.New(fmt.Sprintf("Task %s not found.", guid))
}

// Gets task output based on string provided
func GetTaskOutputById(guid string) (string, error) {
	task, err := GetTaskById(guid)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Task %s not found.", guid))
	}
	return task.Output, nil
}

// Marks the calling Task as finished
func (t *Task) FinishTask() {
	t.Status = TASK_STATUS_FINISHED
}

// Sets task output based on string provided and marks task as finished if specified
func SetTaskOutputById(guid string, output string, markAsComplete bool) (error) {
	task, err := GetTaskById(guid)
	if err != nil {
		return errors.New(fmt.Sprintf("Task %s not found.", guid))
	}
	task.Output = output
	if markAsComplete {
		task.FinishTask()
	}
	return nil
}

// Discards/Cancels the calling Task.
func (t *Task) CancelTask() {
	t.Status = TASK_STATUS_DISCARDED
}


// Helper method for generating v4 UUID string of format 8-4-4-4-12.
func GenerateUUID() string {
	return uuid.New().String()
}
