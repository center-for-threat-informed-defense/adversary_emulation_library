package util

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"attackevals.mitre-engenuity.org/control_server/config"
	restapi_util "attackevals.mitre-engenuity.org/control_server/restapi/util"
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

func ForwardTaskOutput(restAPIaddress string, uuid string, data []byte) (string, error) {
    url := "http://" + restAPIaddress + "/api/v1.0/session/" + uuid + "/task/output"

    // initialize HTTP request
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
    if err != nil {
        return "", err
    }
    req.Header.Set("Content-Type", "application/json")

    // execute HTTP POST request and read response
    client := &http.Client{}
    response, err := client.Do(req)
    if err != nil {
        return "", err
    }
    defer response.Body.Close()
    if response.StatusCode != 200 {
        return "", errors.New(fmt.Sprintf("Expected 200 HTTP response code, received %d", response.StatusCode))
    }
    return ExtractRestApiStringResponsedData(response)
}

// Forwards Implant Beacon to RESTAPI, which will forward session struct to CALDERA
func ForwardImplantBeacon(uuid string, restAPIaddress string) (string, error) {
	url := "http://" + restAPIaddress + "/api/v1.0/forwarder/session/" + uuid

	// initialize HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(""))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	// execute HTTP POST request and read response
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", errors.New(fmt.Sprintf("Received non-200 HTTP status code when forwarding implant beacon with ID %s: %d", uuid, response.StatusCode))
	}
	return ExtractRestApiStringResponsedData(response)
}

// Extracts string response data from REST API string response. Assumes caller will close response body
func ExtractRestApiStringResponsedData(resp *http.Response) (string, error) {
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return "", err
    }
    // parse out message from REST API
    var apiResponse restapi_util.ApiStringResponse
    err = json.Unmarshal(body, &apiResponse)
    if err != nil {
        return "", err
    }
    return apiResponse.Data, nil
}
