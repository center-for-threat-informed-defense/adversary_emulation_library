package logger

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

const TEST_LOG_FILENAME = "logs_test.txt"

func clearLogFile(t *testing.T) {
	if err := os.Remove(TEST_LOG_FILENAME); err != nil {
		t.Error(err)
	}
}

func verifyLogFile(t *testing.T, prefix string, want []string) {
	data, err := ioutil.ReadFile(TEST_LOG_FILENAME)
	if err != nil {
		t.Error(err)
	}
	contents := strings.Split(string(data), "\n")
	if len(contents[len(contents)-1]) == 0 {
		contents = contents[:len(contents)-1]
	}
	
	prefixLen := len(prefix)
	offset := prefixLen + 20 // 20 is the length of the timestamp portion, like "2022/05/17 11:39:22 "
	if len(want) != len(contents) {
		t.Errorf("Expected %d lines, got %d", len(want), len(contents))
	} else {
		for index, line := range(contents) {
			toCheck := line[offset:]
			if toCheck != want[index] {
				t.Errorf("Expected %s, got %s", want[index], toCheck)
			}
			prefixCheck := line[:prefixLen]
			if prefixCheck != prefix {
				t.Errorf("Expected prefix: %s, got: %s", prefix, prefixCheck)
			}
		}
	}
}

// logger.Debug()
func TestDebug(t *testing.T) {
	SetLogs(TEST_LOG_FILENAME)
	defer clearLogFile(t)
	
	Debug("Use logger.Debug() for debug messages while you're troubleshooting issues.")

	Debug("Test with multiple ", "strings", ".")

	msg := "hello world"
	Debug("Test with variable: ", msg)
	
	want := []string{
		"Use logger.Debug() for debug messages while you're troubleshooting issues.",
		"Test with multiple  strings .",
		"Test with variable:  hello world",
	}
	verifyLogFile(t, debugPrefix, want)
}

// logger.Info()
func TestInfo(t *testing.T) {
	SetLogs(TEST_LOG_FILENAME)
	defer clearLogFile(t)
	
	Info("Use logger.Info() for informational messages and prompts, like 'Enter name: '")

	Info("Test with multiple ", "strings", ".")

	msg := "hello world"
	Info("Test with variable: ", msg)
	
	want := []string{
		"Use logger.Info() for informational messages and prompts, like 'Enter name: '",
		"Test with multiple  strings .",
		"Test with variable:  hello world",
	}
	verifyLogFile(t, infoPrefix, want)
}

// logger.Success()
func TestSuccess(t *testing.T) {
	SetLogs(TEST_LOG_FILENAME)
	defer clearLogFile(t)
	
	Success("Use logger.Success() for success messages")

	Success("Test with multiple ", "strings", ".")

	msg := "hello world"
	Success("Test with variable: ", msg)
	
	want := []string{
		"Use logger.Success() for success messages",
		"Test with multiple  strings .",
		"Test with variable:  hello world",
	}
	verifyLogFile(t, successPrefix, want)
}

// logger.Task()
func TestTask(t *testing.T) {
	SetLogs(TEST_LOG_FILENAME)
	defer clearLogFile(t)
	
	Task("Use logger.Task() for task output")

	Task("Test with multiple ", "strings", ".")

	msg := "hello world"
	Task("Test with variable: ", msg)
	
	want := []string{
		"Use logger.Task() for task output",
		"Test with multiple  strings .",
		"Test with variable:  hello world",
	}
	verifyLogFile(t, taskLoggerPrefix, want)
}

// logger.Warning()
func TestWarning(t *testing.T) {
	SetLogs(TEST_LOG_FILENAME)
	defer clearLogFile(t)
	
	Warning("Use logger.Warning() for warning messages, such as 'are you sure you want to ... ?'")

	Warning("Test with multiple ", "strings", ".")

	msg := "hello world"
	Warning("Test with variable: ", msg)
	
	want := []string{
		"Use logger.Warning() for warning messages, such as 'are you sure you want to ... ?'",
		"Test with multiple  strings .",
		"Test with variable:  hello world",
	}
	verifyLogFile(t, warningPrefix, want)
}

// logger.Error()
func TestError(t *testing.T) {
	SetLogs(TEST_LOG_FILENAME)
	defer clearLogFile(t)
	
	Error("Use logger.Error() for error messages")

	Error("Test with multiple ", "strings", ".")

	msg := "hello world"
	Error("Test with variable: ", msg)
	
	want := []string{
		"Use logger.Error() for error messages",
		"Test with multiple  strings .",
		"Test with variable:  hello world",
	}
	verifyLogFile(t, errorPrefix, want)
}
