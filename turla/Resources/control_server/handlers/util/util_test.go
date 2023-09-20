package util_test

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "testing"
    "time"

    "attackevals.mitre-engenuity.org/control_server/logger"
    "attackevals.mitre-engenuity.org/control_server/restapi"
    "attackevals.mitre-engenuity.org/control_server/sessions"
    "attackevals.mitre-engenuity.org/control_server/test_utils"
    "attackevals.mitre-engenuity.org/control_server/handlers/util" // avoid import loop
)

const (
    REST_API_LISTEN_HOST   = "127.0.0.1:9990" // need to check on port
    REST_API_BASE_URL      = "http://" + REST_API_LISTEN_HOST + "/api/v1.0/"
    TEST_SESSION_GUID      = "new-implant-beacon"
)

func startRESTAPI(t *testing.T) {
    restapi.Start(REST_API_LISTEN_HOST, "./test_payloads")
    time.Sleep(50 * time.Millisecond)
    t.Log("Started REST API server")
}

func stopRESTAPI(t *testing.T) {
    restapi.Stop()
    time.Sleep(50 * time.Millisecond)
    t.Log("Stopped REST API server")
}

func createTestSession(uuid string) {
    // http://127.0.0.1:9999/api/v1.0/session
    createSessionURL := REST_API_BASE_URL + "session"

    // convert testSession object into JSON
    testSession := sessions.Session{
        GUID: TEST_SESSION_GUID,
    }

    testSessionJSON, err := json.Marshal(testSession)
    if err != nil {
        logger.Fatal(err)
    }

    // setup HTTP POST request
    req, err := http.NewRequest("POST", createSessionURL, bytes.NewBuffer(testSessionJSON))
    if err != nil {
        logger.Fatal(err)
    }
    req.Header.Set("Content-Type", "application/json")

    // execute HTTP POST request and read response
    client := &http.Client{}
    response, err := client.Do(req)
    if err != nil {
        logger.Fatal(err)
    }
    defer response.Body.Close()
    if response.StatusCode != 200 {
        logger.Fatal(fmt.Sprintf("Expected error code 200, got %v", response.StatusCode))
    }
}

func TestForwardImplantBeacon(t *testing.T) {
    startRESTAPI(t)
    test_utils.StartMockCalderaServer()
    restapi.CalderaForwardingEndpoint = "http://127.0.0.1:8888/plugins/emu/beacons"

    defer stopRESTAPI(t)
    defer test_utils.StopMockCalderaServer()
    createTestSession(TEST_SESSION_GUID)

    response, err := util.ForwardImplantBeacon(TEST_SESSION_GUID, REST_API_LISTEN_HOST)
    if err != nil {
        t.Error(err)
    }
    expectedOutput := fmt.Sprintf("Forwarded beacon for session: %s, received response: CALDERA server successfully received session: %s", TEST_SESSION_GUID, TEST_SESSION_GUID)
    if response != expectedOutput {
        t.Errorf("Expected message %s; got %s", expectedOutput, response)
    }
}
