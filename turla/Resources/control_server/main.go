package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"

	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/handlers"
	"attackevals.mitre-engenuity.org/control_server/logger"
	"attackevals.mitre-engenuity.org/control_server/restapi"
	"attackevals.mitre-engenuity.org/control_server/sessions"
)

var testSession1 = sessions.Session{
	GUID:          "abcdef123456",
	IPAddr:        "127.0.0.1",
	HostName:      "myHostName",
	User:          "myUserName",
	Dir:           "C:\\MyDir\\",
	PID:           1234,
	PPID:          4,
	SleepInterval: 60,
	Jitter:        1.5,
}

var (
	defaultHandlerConfigPath = "./config/handler_config.yml"
	defaultRestConfigPath = "./config/restAPI_config.yml"
	restConfigFile string
	handlerConfigFile string
)

func main() {
	flag.StringVar(&restConfigFile, "rest-config", defaultRestConfigPath, "Path to the REST API config file. Default: ./config/restAPI_config.yml")
	flag.StringVar(&restConfigFile, "r", defaultRestConfigPath, "Path to the REST API config file. Default: ./config/restAPI_config.yml")
	flag.StringVar(&handlerConfigFile, "config", defaultHandlerConfigPath, "Path to the handler config file. Default: ./config/handler_config.yml")
	flag.StringVar(&handlerConfigFile, "c", defaultHandlerConfigPath, "Path to the handler config file. Default: ./config/handler_config.yml")
	flag.Parse()

	logger.Info("Initializing REST API from config file: ", restConfigFile)
	err := config.SetRestAPIConfig(restConfigFile)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Success("REST API configuration set")

	logger.Info("Starting REST API server")
	restAPIaddress := config.GetRestAPIListenAddress()
	restapi.Start(restAPIaddress, "../payloads")
	logger.Success("REST API server is listening on: ", restAPIaddress)

	loadHandlerConfig(handlerConfigFile)
	logger.Info("Starting C2 handlers")
	handlers.StartHandlers()

	logger.Info("Waiting for connections")
	
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt)
	s := <-signalChannel
	logger.Info(fmt.Sprintf("Received signal %s: stopping handlers.", s))
	handlers.StopHandlers()
	restapi.Stop()
}

// Load in the handler configuration. Pass in "./config/handler_config.yml" as the file path.
func loadHandlerConfig(configFile string) {
	logger.Info("Setting C2 handler configurations from config file: ", configFile)
	err := config.HandlerConfig.SetHandlerConfig(configFile)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Success("C2 Handler configuration set")
}
