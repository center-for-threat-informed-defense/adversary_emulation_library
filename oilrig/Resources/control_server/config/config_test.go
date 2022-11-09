package config

import (
	"reflect"
	"testing"
)

const (
	HANDLER_CONFIG_FILE = "./handler_config.yml"
)

func mockHandlerConfigFileReader(path string) ([]byte, error) {
	dataStr := `simplehttp: 
  host: 192.168.0.4
  port: 8080
  enabled: true
https: 
  host: 192.168.0.4
  port: 443
  cert_file: /dummy/https/cert
  key_file: /dummy/https/key
  enabled: true
trickbot: 
  host: 192.168.0.4
  port: 447
  enabled: false
emotet: 
  host: 192.168.0.4
  port: 80
  enabled: false
exaramel: 
  host: 192.168.0.4
  port: 8443
  cert_file: /dummy/exaramel/cert
  key_file: /dummy/exaramel/key
  enabled: true`
	return []byte(dataStr), nil
}

func TestSetRestAPIConfig(t *testing.T) {
	restAPIConfigFile := "./restAPI_config.yml"
	err := SetRestAPIConfig(restAPIConfigFile)
	if err != nil {
		t.Error(err)
	}
	garbage := "this-is-garbage-input"
	err = SetRestAPIConfig(garbage)
	if err == nil {
		t.Error("expected an error, got nil")
	}
}

func TestGetRestAPIConfig(t *testing.T) {
	conf, err := GetRestAPIConfig()
	if err != nil {
		t.Error(err)
	}
	if len(conf) == 0 {
		t.Errorf("configuration is nil %v", conf)
	}
	badConf := "{\"Address\":\"\"}"
	if string(conf) == badConf {
		t.Errorf("received invalid configuration '%s'", conf)
	}
}

func TestHandlerConfigMockFile(t *testing.T) {
	handler := HandlerConfigGenerator(mockHandlerConfigFileReader)
	err := handler.SetHandlerConfig(HANDLER_CONFIG_FILE)
	if err != nil {
		t.Error(err)
	}
	want := HandlerConfigMap{
		"simplehttp": HandlerConfigEntry{
			"host": "192.168.0.4",
			"port": "8080",
			"enabled": "true",
		},
		"https": HandlerConfigEntry{
			"host": "192.168.0.4",
			"port": "443",
			"cert_file": "/dummy/https/cert",
			"key_file": "/dummy/https/key",
			"enabled": "true",
		},
		"trickbot": HandlerConfigEntry{
			"host": "192.168.0.4",
			"port": "447",
			"enabled": "false",
		},
		"emotet": HandlerConfigEntry{
			"host": "192.168.0.4",
			"port": "80",
			"enabled": "false",
		},
		"exaramel": HandlerConfigEntry{
			"host": "192.168.0.4",
			"port": "8443",
			"cert_file": "/dummy/exaramel/cert",
			"key_file": "/dummy/exaramel/key",
			"enabled": "true",
		},
	}
	confMap := handler.GetHandlerConfigMap()
	if !reflect.DeepEqual(want, confMap) {
		t.Errorf("Expected %v, got %v", want, confMap)
	}
	confJson, err := handler.GetHandlerConfigJSON()
	if err != nil {
		t.Error(err)
	}
	if len(confJson) == 0 {
		t.Errorf("configuration is nil %v", confJson)
	}
}

func TestSetHandlerConfigActualFile(t *testing.T) {
	err := HandlerConfig.SetHandlerConfig(HANDLER_CONFIG_FILE)
	if err != nil {
		t.Error(err)
	}
	garbage := "this-is-garbage-input"
	err = HandlerConfig.SetHandlerConfig(garbage)
	if err == nil {
		t.Error("expected an error, got nil")
	}
}

func TestGetHandlerConfigJSONActualFile(t *testing.T) {
	conf, err := HandlerConfig.GetHandlerConfigJSON()
	if err != nil {
		t.Error(err)
	}
	if len(conf) == 0 {
		t.Errorf("configuration is nil %v", conf)
	}
}

func TestGetHandlerConfigMapActualFile(t *testing.T) {
	conf := HandlerConfig.GetHandlerConfigMap()
	if len(conf) == 0 {
		t.Errorf("configuration is nil %v", conf)
	}
}

func TestGetHostPortString(t *testing.T) {
	configEntry := HandlerConfigEntry{
		"host": "192.168.0.4",
		"port": "8080",
		"enabled": "true",
	}
	want := "192.168.0.4:8080"
	result, err := GetHostPortString(configEntry)
	if err != nil {
		t.Errorf("Obtained error when getting host port string: %s", err.Error())
	}
	if result != want {
		t.Errorf("Expected %s, got %s", want, result)
	}
}

func TestGetHostPortStringMissingHost(t *testing.T) {
	configEntry := HandlerConfigEntry{
		"port": "8080",
	}
	want := "Config entry did not contain a host value. Expected key: host"
	result, err := GetHostPortString(configEntry)
	if err == nil {
		t.Error("Expected error but did not get one.")
	}
	if len(result) != 0 {
		t.Errorf("Expected empty string, got: %s", result)
	}
	if err.Error() != want {
		t.Errorf("Expected error message: %s; got: %s", want, err.Error())
	}
}

func TestGetHostPortStringMissingPort(t *testing.T) {
	configEntry := HandlerConfigEntry{
		"host": "192.168.0.4",
	}
	want := "Config entry did not contain a port value. Expected key: port"
	result, err := GetHostPortString(configEntry)
	if err == nil {
		t.Error("Expected error but did not get one.")
	}
	if len(result) != 0 {
		t.Errorf("Expected empty string, got: %s", result)
	}
	if err.Error() != want {
		t.Errorf("Expected error message: %s; got: %s", want, err.Error())
	}
}

func TestGetHostPortStringEmptyHost(t *testing.T) {
	configEntry := HandlerConfigEntry{
		"host": "",
		"port": "8080",
	}
	want := "Please provide a non-empty host value."
	result, err := GetHostPortString(configEntry)
	if err == nil {
		t.Error("Expected error but did not get one.")
	}
	if len(result) != 0 {
		t.Errorf("Expected empty string, got: %s", result)
	}
	if err.Error() != want {
		t.Errorf("Expected error message: %s; got: %s", want, err.Error())
	}
}

func TestGetHostPortStringEmptyPort(t *testing.T) {
	configEntry := HandlerConfigEntry{
		"host": "192.168.0.4",
		"port": "",
	}
	want := "Please provide a non-empty port value."
	result, err := GetHostPortString(configEntry)
	if err == nil {
		t.Error("Expected error but did not get one.")
	}
	if len(result) != 0 {
		t.Errorf("Expected empty string, got: %s", result)
	}
	if err.Error() != want {
		t.Errorf("Expected error message: %s; got: %s", want, err.Error())
	}
}
