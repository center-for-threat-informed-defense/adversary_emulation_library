package test_utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
	"strings"

	"attackevals.mitre-engenuity.org/control_server/logger"
	"attackevals.mitre-engenuity.org/control_server/sessions"
	"github.com/gorilla/mux"
)

var MockCalderaServer *http.Server

func HandleEmuBeacon(w http.ResponseWriter, r *http.Request) {
	req, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Fprintf(w, "%v", err)
		return
	}

	// convert JSON data into a session struct
	var session sessions.Session
	err = json.Unmarshal(req, &session)
	if err != nil {
		fmt.Fprintf(w, "%v", err)
		return
	}
	fmt.Fprintf(w, "%v%v", "CALDERA server successfully received session: ", session.GUID)
}

func StartMockCalderaServer() {
	r := mux.NewRouter()
	r.HandleFunc("/plugins/emu/beacons", HandleEmuBeacon).Methods("POST")
	calderaAddress := "127.0.0.1:8888"
	MockCalderaServer = &http.Server{
		Addr:         calderaAddress,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r,
	}
	// start rest api in goroutine so it doesn't block
	go func() {
		err := MockCalderaServer.ListenAndServe()
		if err != nil && err.Error() != "http: Mock CALDERA Server closed" {

			if strings.Contains(err.Error(), fmt.Sprintf("Mock CALDERA listen tcp %s: bind: address already in use", calderaAddress)) {
				logger.Warning(err)
				return
			} else {
				logger.Error(err)
			}
		}
	}()
	time.Sleep(50 * time.Millisecond)
}

func StopMockCalderaServer() {
	time.Sleep(50 * time.Millisecond)
	emptyContext := context.Background()
	err := MockCalderaServer.Shutdown(emptyContext)
	if err != nil {
		logger.Error(fmt.Sprintf("Mock CALDERA server failed to shut down: %s", err.Error()))
	}
}