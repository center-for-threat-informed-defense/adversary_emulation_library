package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

const (
	HostKey = "host"
	PortKey = "port"
)

// Wrapper for the ioutil.ReadFile function. This allows us to set dummy file reader functions when testing.
type FileReaderWrapper func(string) ([]byte, error) 

// RestAPIConfigStruct is used to convert configuration data from YAML to JSON
type RestAPIConfigStruct struct {
	Address string
}

// Type wrapper for a single handler config entry dictionary, which maps setting name to value.
type HandlerConfigEntry map[string]string

// Type wrapper that represents the handler configuration mapping. Maps handler name to HandlerConfigEntry
type HandlerConfigMap map[string]HandlerConfigEntry

// RestAPIConfig holds configuration data so it can be converted to JSON
var RestAPIConfig RestAPIConfigStruct

// HandlerConfigStruct is used to convert configuration data from YAML to JSON/mapping
type HandlerConfigStruct struct {
	configMap HandlerConfigMap `yaml:"omitempty"`
	fileReaderFunc FileReaderWrapper
}

// HandlerConfig holds handler configuration information to convert to JSON and to store as internal reference map.
var HandlerConfig *HandlerConfigStruct

// HandlerConfigGenerator is a generator function that creates a HandlerConfig struct.
func HandlerConfigGenerator(fileReader FileReaderWrapper) *HandlerConfigStruct {
	return &HandlerConfigStruct{
		configMap: HandlerConfigMap{},
		fileReaderFunc: fileReader,
	}
}

func init() {
	HandlerConfig = HandlerConfigGenerator(ioutil.ReadFile)
}

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

// SetHandlerConfig assigns the values in "configFile" to the HandlerConfig struct.
// You should pass "handler_config.yml" to this function
func (h *HandlerConfigStruct) SetHandlerConfig(configFile string) error {
	yamlData, err := h.fileReaderFunc(configFile)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(yamlData, &h.configMap)
}

func (h *HandlerConfigStruct) GetHandlerConfigJSON() ([]byte, error) {
	configJSON, err := json.Marshal(h.configMap)
	if err != nil {
		return nil, err
	}
	return configJSON, err
}

func (h *HandlerConfigStruct) GetHandlerConfigMap() HandlerConfigMap {
	return h.configMap
}

// Given a handler config entry, return a string of the format "host:port" (e.g. "10.1.2.3.4:8080") for the corresponding config values.
func GetHostPortString(configEntry HandlerConfigEntry) (string, error) {
	host, ok := configEntry[HostKey]
	if !ok {
		return "", errors.New(fmt.Sprintf("Config entry did not contain a host value. Expected key: %s", HostKey))
	}
	if len(host) == 0 {
		return "", errors.New("Please provide a non-empty host value.")
	}
	port, ok := configEntry[PortKey]
	if !ok {
		return "", errors.New(fmt.Sprintf("Config entry did not contain a port value. Expected key: %s", PortKey))
	}
	if len(port) == 0 {
		return "", errors.New("Please provide a non-empty port value.")
	}
	return fmt.Sprintf("%s:%s", host, port), nil
}

