package handlers_test

import (
	"testing"
	"time"

	"attackevals.mitre-engenuity.org/control_server/handlers"
)

func TestStartHandlers(t *testing.T) {
	handlers.StartHandlers()
	time.Sleep(100 * time.Millisecond)
	handlers.StopHandlers()
}
