//go:build linux

package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"
)

func main() {
	// This application must be executed with administrator privileges
	// so that it can use systemctl start / stop commands.

	// Assign flags to variables. Syntax is "flag name", "default", "description."
	shellSrc := flag.String("shellSrc", "simpleshell.php", "Location to copy webshell from.")
	shellDest := flag.String("shellDest", "/var/www/html/simpleshell.php", "Webshell will be copied here.")
	port := flag.String("port", "80", "Client will connect to the server on localhost with this port. Do not set this unless your local Apache server uses a non-default port!")
	runTime := flag.Int("runTime", 120, "Time in seconds to run webshell for (0 to run forever).")
	commandTimeDelay := flag.Int("commandTimeDelay", 10, "Time in seconds between running commands.")
	loopTimeDelay := flag.Int("loopTimeDelay", 20, "Time in seconds between looping back through commands.")

	flag.Parse()

	log.Printf(
		"Wrapper will run with these options: -shellSrc: %s, -shellDest: %s, -port: %s, -runTime: %d, -commandTimeDelay: %d, -loopTimeDelay: %d",
		*shellSrc, *shellDest, *port, *runTime, *commandTimeDelay, *loopTimeDelay)

	input, read_err := ioutil.ReadFile(*shellSrc)
	if read_err != nil {
		log.Printf("Error reading %s: %s\n", *shellSrc, read_err)
	}

	if write_err := ioutil.WriteFile(*shellDest, input, 0744); write_err != nil {
		log.Printf("Error writing %s: %s\n", *shellSrc, write_err)
	}

	log.Printf("Copied webshell %s to %s.\n", *shellSrc, *shellDest)

	start_cmd := exec.Command("systemctl", "start", "apache2")
	start_cmd.Stdout = os.Stdout
	start_cmd.Stderr = os.Stderr

	shellDest_tokens := strings.Split(*shellDest, "/")
	shell_name := shellDest_tokens[len(shellDest_tokens)-1]

	if start_err := start_cmd.Run(); start_err != nil {
		log.Fatalf("Error starting server with command \"systemctl start apache2\": %s", start_err.Error())
	} else {
		log.Printf("Server started.")
	}

	if *runTime > 0 {
		log.Printf("Server will run for %d seconds.", *runTime)

		// Put it in a go func() so that killing the main process
		// doesn't kill the client, and it terminates on its own.
		go func() {
			log.Printf("Starting client.")
			client("localhost", *port, shell_name, *commandTimeDelay, *loopTimeDelay, *runTime) //Run the client script for as long as the user specified
		}()

		// Using this timer separately from the client is necessary
		// because the server is killed independently of the client,
		// which continues to run in the background until it sends a
		// command and receives no response.
		time.Sleep(time.Duration(*runTime) * time.Second)

		// Kill web server after sleep.
		stop_cmd := exec.Command("systemctl", "stop", "apache2")
		if stop_err := stop_cmd.Start(); stop_err != nil {
			log.Fatalf("Error starting server with \"systemctl stop apache2\": %s", stop_err.Error())
		} else {
			log.Println("Attempted to stop server with systemctl.")
			log.Println("Finished.")
			os.Exit(0)
		}
	} else if *runTime == 0 {
		log.Println("Server will run until stopped with Ctrl+C.\n")

		srv_channel := make(chan os.Signal)
		signal.Notify(srv_channel, os.Interrupt)

		// Put it in a go func() so that killing the main process
		// doesn't kill the client, and it terminates on its own.
		go func() {
			log.Printf("Starting client.")
			client("localhost", *port, shell_name, *commandTimeDelay, *loopTimeDelay, *runTime) //Run the client script for as long as the user specified
		}()

		// Receive kill signal.
		<-srv_channel

		// Kill web server after signal.
		log.Println("Kill signal received. Attempting to stop web server.")
		stop_cmd := exec.Command("systemctl", "stop", "apache2")
		if stop_err := stop_cmd.Start(); stop_err != nil {
			log.Fatalf("Error stopping server with \"systemctl stop apache2\": %s", stop_err.Error())
		} else {
			log.Println("Attempted to stop server with systemctl.")
			log.Println("Finished.")
			os.Exit(0)
		}

	} else {
		log.Fatalf("Invalid runtime %d not >= 0. Quitting.", *runTime)
	}
}
