package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"time"
)

func main() {
	// Assign flags to variables. Syntax is "flag name", "default", "description."
	shellSrc := flag.String("shellSrc", "shell/windowswebshell.exe", "Location to copy webshell from.")
	shellDest := flag.String("shellDest", "./windowswebshell.exe", "Webshell will be copied here.")
	shellHost := flag.String("shellHost", "localhost", "The hostname or IP you want the shell to run on.")
	shellPort := flag.String("shellPort", "8080", "The port you want the shell to run on.")
	runTime := flag.Int("runTime", 120, "Time in seconds to run webshell for (0 to run forever). Must be longer than total command and loop time.")
	commandTimeDelay := flag.Int("commandTimeDelay", 10, "Time in seconds between running commands.")
	loopTimeDelay := flag.Int("loopTimeDelay", 20, "Time in second between looping back through commands.")
	flag.Parse()

	input, read_err := ioutil.ReadFile(*shellSrc)
	if read_err != nil {
		fmt.Printf("Error reading %s: %s\n", *shellSrc, read_err)
	}

	if write_err := ioutil.WriteFile(*shellDest, input, 0744); write_err != nil {
		fmt.Printf("Error writing %s: %s\n", *shellSrc, write_err)
	}

	shellOptions := "-hostname=" + *shellHost + " -port=" + *shellPort + " -runTime=" + strconv.Itoa(*runTime)
	fmt.Printf("Copied webshell %s to %s.\n", *shellSrc, *shellDest)
	fmt.Printf("Webshell will be started: %s %s\n", *shellDest, shellOptions)

	if *runTime == 0 {
		fmt.Println("runTime is 0 (run forever). The webshell will run until Ctrl+C.")
		cmd := exec.Command(*shellDest, "-hostname="+*shellHost, "-port="+*shellPort, "-runTime="+strconv.Itoa(*runTime))
		go func() {
			if cmd_err := cmd.Start(); cmd_err != nil {
				log.Fatalf("Error starting process: %s\n\t", cmd_err)
			} else {
				log.Printf("Process started.\n")
			}
		}()

		fmt.Println("Started webshell. Waiting for kill signal.")
		cmd_channel := make(chan os.Signal)
		signal.Notify(cmd_channel, os.Interrupt)

		// Put it in a go func() so that killing the main process
		// doesn't kill the client, and it terminates on its own.
		go func() {
			// Send commands to the webshell.
			log.Println("Starting the client.\n")
			client(*shellHost, *shellPort, *commandTimeDelay, *loopTimeDelay, *runTime) //Call the client to run commands
		}()

		<-cmd_channel

		if kill_err := cmd.Process.Kill(); kill_err != nil {
			if kill_err.Error() == "TerminateProcess: Access is denied." {
				fmt.Printf(
					"Attempt to kill webshell returned an expected error: \"%s\". Continuing.",
					kill_err.Error())
			} else {
				log.Fatal("\nFailed to kill webshell's process: ", kill_err)
			}
		} else {
			fmt.Println("Process terminated without errors.")
		}
		fmt.Println("\nFinished.\n")
	} else if *runTime > 0 {
		cmd := exec.Command(*shellDest, "-hostname="+*shellHost, "-port="+*shellPort, "-runTime="+strconv.Itoa(*runTime))
		if cmd_err := cmd.Start(); cmd_err != nil {
			log.Fatalf("Error starting process: %s\n", cmd_err)
		} else {
			log.Printf("Process started.\n")
		}

		fmt.Printf("Started webshell. It will be killed after %d seconds.\n", *runTime)

		// Put it in a go func() so that killing the main process
		// doesn't kill the client, and it terminates on its own.
		go func() {
			// Send commands to the webshell, will end at runTime duration.
			log.Println("Starting the client.\n")
			client(*shellHost, *shellPort, *commandTimeDelay, *loopTimeDelay, *runTime) //Call the client to run commands
		}()

		// Using this timer separately from the client is necessary
		// because the server is killed independently of the client,
		// which continues to run in the background until it sends a
		// command and receives no response.
		time.Sleep(time.Duration(*runTime) * time.Second)

		// Kill webshell after runTime elapses.
		if kill_err := cmd.Process.Kill(); kill_err != nil {
			log.Fatal("Failed to kill webshell's process: ", kill_err)
		} else {
			fmt.Println("Process terminated without errors.")
		}
		fmt.Printf("Finished.")
	} else {
		fmt.Println("Invalid runTime %d not >= 0. Quitting.", *runTime)
		os.Exit(1)
	}
}
