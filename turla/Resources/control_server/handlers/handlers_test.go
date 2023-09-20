package handlers

import (
	"os"
	"testing"
	"time"

	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/handlers/util"
)

func mockHandlerConfigFileReaderAllEnabled(path string) ([]byte, error) {
	dataStr := `snakehttp:
  host: 127.0.0.1
  port: 60007
  enabled: true
carbonhttp:
  host: 127.0.0.1
  port: 60008
  enabled: true
epic:
  host: 127.0.0.1
  port: 60009
  cert_file: /dummy/epic/cert
  key_file: /dummy/epic/key
  use_https: false
  enabled: true
lightneuron:
  host: 127.0.0.1
  port: 60010
  mailFrom: invalid@mail.local
  username: dummy
  password: dummy
  image_file_path: .lightneuron/snake.jpg
  watch_dir_path: /dummy/lightneuron/attachments
  recipientFilePath: .lightneuron/recipients.txt
  enabled: true`
	return []byte(dataStr), nil
}

func mockHandlerConfigFileReaderSomeEnabled(path string) ([]byte, error) {
	dataStr := `snakehttp:
  host: 127.0.0.1
  port: 60007
  enabled: true
carbonhttp:
  host: 127.0.0.1
  port: 60008
  enabled: false
epic:
  host: 127.0.0.1
  port: 60009
  cert_file: /dummy/epic/cert
  key_file: /dummy/epic/key
  use_https: false
  enabled: false
lightneuron:
  host: 127.0.0.1
  port: 60010
  username: dummy
  password: dummy
  mailFrom: invalid@mail.local
  image_file_path: .lightneuron/snake.jpg
  watch_dir_path: /dummy/lightneuron/attachments
  recipientFilePath: .lightneuron/recipients.txt
  enabled: false`
	return []byte(dataStr), nil
}

func TestStartStopHandlers(t *testing.T) {
	// set current working directory to main repo directory
	// this is needed so that the handlers can reference correct file structure
	cwd, _ := os.Getwd()
	os.Chdir("../")
	defer os.Chdir(cwd) // restore cwd at end of test

	wantAvailable := 4
	wantRunning := 4
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

	wantAvailable := 4
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
	if _, ok := util.RunningHandlers["snakehttp"]; !ok {
		t.Error("Expected snake to be enabled and running")
	}
	if _, ok := util.RunningHandlers["carbonhttp"]; ok {
		t.Error("Expected epic to be disabled")
	}
	if _, ok := util.RunningHandlers["epic"]; ok {
		t.Error("Expected epic to be disabled")
	}
	if _, ok := util.RunningHandlers["lightneuron"]; ok {
		t.Error("Expected lightneuron to be disabled")
	}
	StopHandlers()
	if len(util.RunningHandlers) != 0 {
		t.Errorf("Expected to stop all running handlers, got %d remaining", len(util.RunningHandlers))
	}
}
