package config_test

import (
	"testing"

	"attackevals.mitre-engenuity.org/control_server/config"
)

func TestSetRestAPIConfig(t *testing.T) {
	restAPIConfigFile := "./restAPI_config.yml"
	err := config.SetRestAPIConfig(restAPIConfigFile)
	if err != nil {
		t.Error(err)
	}
	garbage := "this-is-garbage-input"
	err = config.SetRestAPIConfig(garbage)
	if err == nil {
		t.Error("expected an error, got nil")
	}
}

func TestGetRestAPIConfig(t *testing.T) {
	conf, err := config.GetRestAPIConfig()
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
