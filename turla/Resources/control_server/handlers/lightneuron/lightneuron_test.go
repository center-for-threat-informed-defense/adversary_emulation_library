package lightneuron

import (
	"bufio"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/handlers/util"
	smtpmock "github.com/mocktools/go-smtp-mock/v2"
)

const (
	handlerName          = "lightneuron"
	restAPIlistenHost    = "127.0.0.1:9994"
	sourceImagePath      = ""
	destinationImagePath = "" //For the image with embedded commands
	command_id           = ""
	command_string       = ""
)

var configEntry = config.HandlerConfigEntry{
	"host":            "127.0.0.1",
	"port":            "25",
	"username":        "",
	"password":        "",
	"image_file_path": "snake.jpg",
	"watch_dir_path":  "extract/",
}

func startLightNeuronHandler(handler *LightNeuronHandler, t *testing.T) {
	if err := handler.StartHandler(restAPIlistenHost, configEntry); err != nil {
		t.Errorf("Error when starting LightNeuron handler: %s", err.Error())
	}
	util.RunningHandlers[handlerName] = handler
	time.Sleep(50 * time.Millisecond)
}

func stopLightNeuronHandler(handler *LightNeuronHandler, t *testing.T) {
	if err := handler.StopHandler(); err != nil {
		t.Errorf("Error when stopping LightNeuron handler: %s", err.Error())
	}
	delete(util.RunningHandlers, handlerName)
	time.Sleep(50 * time.Millisecond)
}

func TestStartStopLightNeuronHandler(t *testing.T) {
	handler := lightNeuronHandlerFactory()
	startLightNeuronHandler(handler, t)
	defer stopLightNeuronHandler(handler, t)

	// Write test code to check default values
}

func TestEmbedData(t *testing.T) {
	handler := lightNeuronHandlerFactory()
	startLightNeuronHandler(handler, t)
	defer stopLightNeuronHandler(handler, t)

	recipient := "test@gmail.com"
	cmdID := 1
	command := "C:\\Windows\\system32\\calc.exe"
	outputFilePath := Embed(configEntry["image_file_path"], cmdID, recipient, command, false)
	_, err := os.Stat(outputFilePath)
	if os.IsNotExist(err) {
		t.Errorf("Output file was not created.")
	}

	containerBytesString := "AAAAOgAAAAEAAAAOdGVzdEBnbWFpbC5jb20AAAAcQzpcV2luZG93c1xzeXN0ZW0zMlxjYWxjLmV4ZQ=="
	containerBytes, err := base64.StdEncoding.DecodeString(containerBytesString)
	if err != nil {
		t.Errorf("Could not decode byte string")
	}

	inFile, err := os.Open(outputFilePath)
	if err != nil {
		t.Errorf("Could not open modified image: %s", err.Error())
	}
	defer inFile.Close()

	// Set up reader
	reader := bufio.NewReader(inFile)

	// Skip to the data we want to check
	reader.Discard(2616)
	// Buffer to hold the data we want to read
	containerBuff := make([]byte, int(len(containerBytes)))

	_, err = reader.Read(containerBuff)
	if err != nil {
		t.Errorf("Could not read bytes from file into buffer. Error: %s", err.Error())
	}

	//Check that the read bytes are what's expected.
	for i := 0; i < len(containerBuff); i++ {
		if containerBuff[i] != containerBytes[i] {
			t.Errorf("Did not find expected bytes in image file.")
		}
	}

}

func TestEncryptDecrypt(t *testing.T) {
	handler := lightNeuronHandlerFactory()
	startLightNeuronHandler(handler, t)
	defer stopLightNeuronHandler(handler, t)

	testPlaintextData := "This is the test encrypted data!"
	key := "thisis32bit1234passph1234imusing"
	cipherText, err := encrypt([]byte(key), []byte(testPlaintextData))
	if err != nil {
		t.Errorf("Encryption process failed.")
	}

	decryptedText, err := decrypt([]byte(key), cipherText)
	if err != nil {
		t.Errorf("Decryption process failed.")
	}

	//Check that the read bytes are what's expected.
	for i := 0; i < len(testPlaintextData); i++ {
		if testPlaintextData[i] != decryptedText[i] {
			t.Errorf("Data encryption/decryption failed. Got '%s', expected '%s'", string(decryptedText[i]), string(testPlaintextData[i]))
		}
	}
}

func TestExtractData(t *testing.T) {
	handler := lightNeuronHandlerFactory()
	handler.encryptionEnabled = true
	startLightNeuronHandler(handler, t)
	defer stopLightNeuronHandler(handler, t)

	data := handler.ExtractData("snake_extract.jpg", true)

	if data == "this is test data\n" {

	} else if data == "Output is to large for the console." {

	} else {
		t.Errorf("Data extraction failed. Got '%s', expected '%s'", data, "this is test data")
	}
}

func TestSendEmail(t *testing.T) {
	server := smtpmock.New(smtpmock.ConfigurationAttr{})

	// Start SMTP server
	if err := server.Start(); err != nil {
		t.Errorf("Failed to start mock SMTP server")
	}
	hostAddress, portNumber := "127.0.0.1", server.PortNumber()

	SendEmail("TestReciever@bounce.local", "snake_modified.jpg", "TestSender@Bounce.local", hostAddress, portNumber, "", "")

	// Store emails in messages variable
	messages := server.Messages()

	// Check for server HELO
	if messages[0].HeloRequest() != "EHLO localhost" {
		t.Error("Invalid HELO request:", messages[0].HeloRequest())
	}

	// Check for proper mail from
	if messages[0].MailfromRequest() != "MAIL FROM:<TestSender@Bounce.local>" {
		t.Error("mail from mismatch:", messages[0].MailfromRequest())
	}

	// Check DATA request in is message
	if messages[0].DataRequest() != "DATA" {
		t.Error("Missing Data request:", messages[0].DataRequest())
	}

	// Stop mock SMTP server
	if err := server.Stop(); err != nil {
		t.Errorf("Failed to stop mock SMTP server")
	}

}
