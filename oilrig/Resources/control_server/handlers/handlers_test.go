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
https: 
  host: 127.0.0.1
  port: 60002
  cert_file: /dummy/https/cert
  key_file: /dummy/https/key
  enabled: true
trickbot: 
  host: 127.0.0.1
  port: 60003
  enabled: true
emotet: 
  host: 127.0.0.1
  port: 60004
  enabled: true
exaramel: 
  host: 127.0.0.1
  port: 60005
  cert_file: /dummy/exaramel/cert
  key_file: /dummy/exaramel/key
  enabled: true
sidetwist:
  host: 127.0.0.1
  port: 60006
  enabled: true`
	return []byte(dataStr), nil
}

func mockHandlerConfigFileReaderSomeEnabled(path string) ([]byte, error) {
	dataStr := `simplehttp: 
  host: 127.0.0.1
  port: 60011
  enabled: true
https: 
  host: 127.0.0.1
  port: 60012
  cert_file: /dummy/https/cert
  key_file: /dummy/https/key
  enabled: true
trickbot: 
  host: 127.0.0.1
  port: 60013
  enabled: false
emotet: 
  host: 127.0.0.1
  port: 60014
  enabled: true
exaramel: 
  host: 127.0.0.1
  port: 60015
  cert_file: /dummy/exaramel/cert
  key_file: /dummy/exaramel/key
  enabled: false
sidetwist:
  host: 127.0.0.1
  port: 60016
  enabled: true`
	return []byte(dataStr), nil
}

func TestStartStopHandlers(t *testing.T) {
	// set current working directory to main repo directory
	// this is needed so that the handlers can reference correct file structure
	cwd, _ := os.Getwd()
	os.Chdir("../")
	defer os.Chdir(cwd) // restore cwd at end of test
	
	wantAvailable := 6
	wantRunning := 6
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
	
	wantAvailable := 6
	wantRunning := 4
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
	if _, ok := util.RunningHandlers["https"]; !ok {
		t.Error("Expected https to be enabled and running")
	}
	if _, ok := util.RunningHandlers["trickbot"]; ok {
		t.Error("Expected trickbot to be disabled")
	}
	if _, ok := util.RunningHandlers["emotet"]; !ok {
		t.Error("Expected emotet to be enabled and running")
	}
	if _, ok := util.RunningHandlers["exaramel"]; ok {
		t.Error("Expected exaramel to be disabled")
	}
	if _, ok := util.RunningHandlers["sidetwist"]; !ok {
		t.Error("Expected sidetwist to be enabled and running")
	}
	StopHandlers()
	if len(util.RunningHandlers) != 0 {
		t.Errorf("Expected to stop all running handlers, got %d remaining", len(util.RunningHandlers))
	}
}
