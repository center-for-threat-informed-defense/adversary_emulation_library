package handlers

import (
	"fmt"
	"strings"

	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/handlers/util"
	"attackevals.mitre-engenuity.org/control_server/logger"

	_ "attackevals.mitre-engenuity.org/control_server/handlers/emotet"
	_ "attackevals.mitre-engenuity.org/control_server/handlers/exaramel"
	_ "attackevals.mitre-engenuity.org/control_server/handlers/https"
	_ "attackevals.mitre-engenuity.org/control_server/handlers/simplehttp"
	_ "attackevals.mitre-engenuity.org/control_server/handlers/trickbot"
	_ "attackevals.mitre-engenuity.org/control_server/handlers/sidetwist"
)

// StartHandlers starts the C2 handlers
func StartHandlers() {
	restAPIAddr := config.GetRestAPIListenAddress()
	if len(restAPIAddr) == 0 {
		logger.Fatal("No REST API address provided. Please check your configuration.")
	}
	handlerConfigMap := config.HandlerConfig.GetHandlerConfigMap()
	if len(handlerConfigMap) == 0 {
		logger.Fatal("No handler configuration provided. Please check your configuration.")
	}
	if len(util.AvailableHandlers) == 0 {
		logger.Fatal("No handlers available to start.")
	}
	for handlerName, handler := range util.AvailableHandlers {
		configEntry, ok := handlerConfigMap[handlerName]
		if !ok {
			logger.Fatal(fmt.Sprintf("No configuration entry found for %s. Please check your configuration", handlerName))
		}
		if enabled, ok := configEntry["enabled"]; ok && strings.ToLower(enabled) == "true" {
			if err := handler.StartHandler(restAPIAddr, configEntry); err != nil {
				logger.Error(fmt.Sprintf("Error starting handler %s: %s", handlerName, err.Error()))
			} else {
				logger.Success(fmt.Sprintf("Started handler %s", handlerName))
				util.RunningHandlers[handlerName] = handler
			}
		} else {
			logger.Info(fmt.Sprintf("Handler %s disabled. Skipping.", handlerName))
		}
	}
	if len(util.RunningHandlers) == 0 {
		logger.Fatal("Failed to start any C2 handler. Please make sure at least one handler is enabled in your configuration.")
	}
}

// StopHandlers stops all C2 handlers
func StopHandlers() {
	for handlerName, handler := range util.RunningHandlers {
		if err := handler.StopHandler(); err != nil {
			logger.Error(fmt.Sprintf("Error stopping handler %s: %s", handlerName, err.Error()))
		} else {
			logger.Success(fmt.Sprintf("Terminated handler %s", handlerName))
			delete(util.RunningHandlers, handlerName)
		}
	}
	// To do - each handler should send a signal to indicate it stopped gracefully
}

