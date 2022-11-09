package util

import (
	"attackevals.mitre-engenuity.org/control_server/config"
)

// The Handler interface provides methods that all C2 handlers must implement.
type Handler interface {
	// Starts the handler given the rest API address string and configuration map.
	StartHandler(string, config.HandlerConfigEntry) error

	// Stops the given handler.
	StopHandler() error
}

// Contains the available C2 handler implementations. These will be populated as from the init() functions in each handler subpackage.
var AvailableHandlers map[string]Handler = make(map[string]Handler)

// Contains running handler implementations.
var RunningHandlers map[string]Handler = make(map[string]Handler)
