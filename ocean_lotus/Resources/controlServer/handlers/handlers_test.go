package handlers

import (
	"os"
	"testing"
	"time"

	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/handlers/util"
)

func mockHandlerConfigFileReaderAllEnabled(path string) ([]byte, error) {
    dataStr := `simplehttp: 
  host: 127.0.0.1
  port: 60001
  enabled: true
oceanlotus:
  host: 127.0.0.1
  port: 443
  encryption: false
  enabled: true`
    return []byte(dataStr), nil
}

func mockHandlerConfigFileReaderSomeEnabled(path string) ([]byte, error) {
    dataStr := `simplehttp: 
  host: 127.0.0.1
  port: 60011
  enabled: true
oceanlotus:
  host: 127.0.0.1
  port: 443
  encryption: false
  enabled: false`
    return []byte(dataStr), nil
}

func TestStartStopHandlers(t *testing.T) {
    // set current working directory to main repo directory
    // this is needed so that the handlers can reference correct file structure
    cwd, _ := os.Getwd()
    os.Chdir("../")
    defer os.Chdir(cwd) // restore cwd at end of test

    wantAvailable := 2
    wantRunning := 2
    config.SetRestAPIConfig("config/restAPI_config.yml")
    config.HandlerConfig = config.HandlerConfigGenerator(mockHandlerConfigFileReaderAllEnabled)
    config.HandlerConfig.SetHandlerConfig("config/handler_config.yml")
    if len(util.AvailableHandlers) != wantAvailable {
        t.Errorf("Expected %d available handlers, got %d", wantAvailable, len(util.AvailableHandlers))
    }
    StartHandlers()
    time.Sleep(100 * time.Millisecond)
    if len(util.RunningHandlers) != wantRunning {
        t.Errorf("Expected %d running handlers, got %d", wantRunning, len(util.RunningHandlers))
    }
    StopHandlers()
    if len(util.RunningHandlers) != 0 {
        t.Errorf("Expected to stop all running handlers, got %d remaining", len(util.RunningHandlers))
    }
}

func TestStartStopHandlersSomeEnabled(t *testing.T) {
    // set current working directory to main repo directory
    // this is needed so that the handlers can reference correct file structure
    cwd, _ := os.Getwd()
    os.Chdir("../")
    defer os.Chdir(cwd) // restore cwd at end of test

    wantAvailable := 2
    wantRunning := 1
    config.SetRestAPIConfig("config/restAPI_config.yml")
    config.HandlerConfig = config.HandlerConfigGenerator(mockHandlerConfigFileReaderSomeEnabled)
    config.HandlerConfig.SetHandlerConfig("config/handler_config.yml")
    if len(util.AvailableHandlers) != wantAvailable {
        t.Errorf("Expected %d available handlers, got %d", wantAvailable, len(util.AvailableHandlers))
    }
    StartHandlers()
    time.Sleep(100 * time.Millisecond)
    if len(util.RunningHandlers) != wantRunning {
        t.Errorf("Expected %d running handlers, got %d", wantRunning, len(util.RunningHandlers))
    }
    if _, ok := util.RunningHandlers["simplehttp"]; !ok {
        t.Error("Expected simplehttp to be enabled and running")
    }
    if _, ok := util.RunningHandlers["oceanlotus"]; ok {
        t.Error("Expected oceanlotus to be disabled")
    }
    StopHandlers()
    if len(util.RunningHandlers) != 0 {
        t.Errorf("Expected to stop all running handlers, got %d remaining", len(util.RunningHandlers))
    }
}
