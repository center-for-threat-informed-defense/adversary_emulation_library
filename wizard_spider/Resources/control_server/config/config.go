package config

import (
	"encoding/json"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

// RestAPIConfigStruct is used to convert configuration data from YAML to JSON
type RestAPIConfigStruct struct {
	Address string
}

// RestAPIConfig holds configuration data so it can be converted to JSON
var RestAPIConfig RestAPIConfigStruct

// SetRestAPIConfig assigns the values in "configFile" to the 'RestAPIConfig' struct.
// You should pass "restAPI_config.yml" to this function
func SetRestAPIConfig(configFile string) error {

	yamlData, err := ioutil.ReadFile(configFile)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(yamlData, &RestAPIConfig)
	if err != nil {
		return err
	}
	return err
}

// GetRestAPIConfig returns the current REST API configuration in JSON format.
// This function is usually invoked by the 'restapi' package.
func GetRestAPIConfig() ([]byte, error) {
	configJSON, err := json.Marshal(RestAPIConfig)
	if err != nil {
		return nil, err
	}
	return configJSON, err
}

func GetRestAPIListenAddress() string {
	return RestAPIConfig.Address
}
