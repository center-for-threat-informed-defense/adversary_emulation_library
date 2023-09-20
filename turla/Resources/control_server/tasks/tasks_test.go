package tasks

import (
	"reflect"
	"testing"
)

const (
	testGUID = "123456789"
	testCommand = "pwd"
	mockUuid = "00000000-0000-0000-0000-000000000000"
)

var expectedTask = Task{
	GUID:		testGUID,
	Command:	testCommand,
	Output:		"",
	Status:		TASK_STATUS_NEW,
	ExitCode:	-1,
}

var expectedTaskMockUuid = Task{
	GUID:		mockUuid,
	Command:	testCommand,
	Output:		"",
	Status:		TASK_STATUS_NEW,
	ExitCode:	-1,
}

func mockGenerateUUID() string {
	return mockUuid
}

// TaskFactory
func TestTaskFactoryGUIDProvided(t *testing.T) {
	TaskFactory(testCommand, testGUID, GenerateUUID)
	newTask, valueExists := GetTaskById(testGUID)
	if valueExists != nil {
		t.Errorf("Expected new Task with guid %v, but no Task found\n", testGUID)
	}

	if !reflect.DeepEqual(expectedTask, *newTask) {
		t.Errorf("Expected Task %v, got %v\n", expectedTask, *newTask)
	}
}

// TaskFactory
func TestTaskFactoryNoGUID(t *testing.T) {
	newTask := TaskFactory(testCommand, "", mockGenerateUUID)
	_, valueExists := GetTaskById(newTask.GUID)
	if valueExists != nil {
		t.Errorf("Expected new Task to be created, but no Task found\n")
	}

	// Test expected default values
	if !reflect.DeepEqual(expectedTaskMockUuid, *newTask) {
		t.Errorf("Expected Task %v, got %v\n", expectedTaskMockUuid, *newTask)
	}
}

// GetTaskById
func TestGetNonExistentTaskById(t *testing.T) {
	invalidGUID := "000000000"
	_, result := GetTaskById(invalidGUID)

	if result == nil {
		t.Errorf("Expected error message for missing Task %v, but found Task\n", invalidGUID)
	}
}

// GetTaskOutputById
func TestGetTaskOutputById(t *testing.T) {
	guid := "get-task-output-guid"
	expectedOutput := "username"
	newTask := TaskFactory(testCommand, guid, mockGenerateUUID)
	(*newTask).Output = expectedOutput

	// Test expected default values
	result, err := GetTaskOutputById((*newTask).GUID)
	if err != nil {
		t.Errorf("Task %v not found", (*newTask).GUID)
	}
	if expectedOutput != result {
		t.Errorf("Expected output '%v', got '%v'\n", expectedOutput, (*newTask).Output)
	}
}

// SetTaskOutputById
func TestSetTaskOutputById(t *testing.T) {
	guid := "set-task-output-guid"
	newTask := TaskFactory(testCommand, guid, mockGenerateUUID)
	setOutput := "command output"
	
	if newTask.Status != TASK_STATUS_NEW {
		t.Errorf("Expected new task to have status %v, instead got %v", TASK_STATUS_NEW, newTask.Status)
	}
	
	SetTaskOutputById(guid, setOutput, true)

	// Test expected default values
	if setOutput != (*newTask).Output {
		t.Errorf("Expected output '%v', got '%v'\n", setOutput, (*newTask).Output)
	}
	
	// Make sure task finished
	if newTask.Status != TASK_STATUS_FINISHED {
		t.Errorf("Expected task to have status %v, instead got %v", TASK_STATUS_FINISHED, newTask.Status)
	}
	
	guid2 := "set-task-output-not-complete"
	newTask2 := TaskFactory(testCommand, guid, mockGenerateUUID)
	if newTask2.Status != TASK_STATUS_NEW {
		t.Errorf("Expected new task to have status %v, instead got %v", TASK_STATUS_NEW, newTask.Status)
	}
	SetTaskOutputById(guid2, setOutput, false)
	if newTask2.Status != TASK_STATUS_NEW {
		t.Errorf("Expected task to still have status %v, instead got %v", TASK_STATUS_NEW, newTask.Status)
	}
}

// CancelTask
func TestCancelTask(t *testing.T) {
	var testTask = Task{
		GUID:		"1234-test-uuid",
		Command:	testCommand,
		Output:		"",
		Status:		TASK_STATUS_NEW,
		ExitCode:	-1,
	}
	testTask.CancelTask()

	if testTask.Status != TASK_STATUS_DISCARDED {
		t.Errorf("Expected Task with status %v, got %v\n", TASK_STATUS_DISCARDED, testTask.Status)
	}
}

// GenerateUUID
func TestGenerateUUID(t *testing.T) {
	guid := GenerateUUID()

	if len(guid) != 36 {
		t.Errorf("Expected randomly generated guid, got empty string\n")
	}
}
