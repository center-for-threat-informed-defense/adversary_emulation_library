package logger_test

import (
	"testing"

	"attackevals.mitre-engenuity.org/exaramel/logger"
)

// logger.Debug()
func TestDebug(t *testing.T) {

	logger.Debug("Use logger.Debug() for debug messages while you're troubleshooting issues.")

	logger.Debug("Test with multiple ", "strings", ".")

	msg := "hello world"
	logger.Debug("Test with variable: ", msg)
}

// logger.Info()
func TestInfo(t *testing.T) {
	logger.Info("Use logger.Info() for informational messages and prompts, like 'Enter name: '")

	logger.Info("Test with multiple ", "strings", ".")

	msg := "hello world"
	logger.Info("Test with variable: ", msg)
}

// logger.Success()
func TestSuccess(t *testing.T) {
	logger.Success("Use logger.Success() for success messages")

	logger.Success("Test with multiple ", "strings", ".")

	msg := "hello world"
	logger.Success("Test with variable: ", msg)
}

// logger.Warning()
func TestWarning(t *testing.T) {
	logger.Warning("Use logger.Warning() for warning messages, such as 'are you sure you want to ... ?'")

	logger.Warning("Test with multiple ", "strings", ".")

	msg := "hello world"
	logger.Warning("Test with variable: ", msg)
}

// logger.Error()
func TestError(t *testing.T) {
	logger.Error("Use logger.Error() for error messages")

	logger.Error("Test with multiple ", "strings", ".")

	msg := "hello world"
	logger.Error("Test with variable: ", msg)
}

func TestDisable(t *testing.T) {
	logger.DisableLogging()
	logger.Debug("Use logger.Debug() for debug messages while you're troubleshooting issues.")
	logger.Info("Use logger.Info() for informational messages and prompts, like 'Enter name: '")
	logger.Success("Use logger.Success() for success messages")
	logger.Warning("Use logger.Warning() for warning messages, such as 'are you sure you want to ... ?'")
	logger.Error("Use logger.Error() for error messages")
}
