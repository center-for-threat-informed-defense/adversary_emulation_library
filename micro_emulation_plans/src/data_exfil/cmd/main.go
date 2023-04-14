package main

import (
	"archive/zip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/XANi/loremipsum"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"

	"data_exfil/pkg/microemuserver"
)

// Command-Line Params
var encrypt *bool
var base64encryptKey *string
var ip *string
var port *int
var serveronly *bool
var clientonly *bool
var exfilmethod *string
var verboseLogging *bool
var servercert *string
var serverkey *string

var exfilProtocols = [...]string{"tcp", "tls", "quic"}

const loremipsumMaxParagraphs = 64 // error thrown with >

func main() {
	// Parsing command-line args
	encrypt = flag.Bool("encrypt", false, "encrypt payload before sending")
	base64encryptKey = flag.String("encryptKey", "", "base64 key to encrypt with. must be 16, 24, or 32 bytes for AES 128,192,256 respectively. (default = random generated - 32 bytes for 128bit AES)")
	ip = flag.String("serverip", "localhost", "server exfil ip")
	port = flag.Int("serverport", -1, "server exfil port (default: random ephemeral 20000-65535)")
	serveronly = flag.Bool("serveronly", false, "only run server (exfil receiver)")
	clientonly = flag.Bool("clientonly", false, "only run client (exfil stager + sender)")
	exfilmethod = flag.String("exfilmethod", "tls", "exfil protocol to use: tcp, tls, quic")
	verboseLogging = flag.Bool("verbose", false, "enable verbose logging")
	servercert = flag.String("servercert", "cert-server.pem", "location of the server certificate (pem)")
	serverkey = flag.String("serverkey", "key-server.pem", "location of the server unencrypted key")

	flag.Parse()

	err := validateExfilProtocol()

	if err != nil {
		log.Fatal(err)
	}

	// Updating since this suppresses log.Fatal() errors which should be reported to user
	// verboseLogging will now only stop the log.Println() statements
	/*if !*verboseLogging {
		log.SetOutput(ioutil.Discard)
	}*/

	microemuserver.VerboseLogging = verboseLogging

	// Update port if set to default random
	if *port == -1 {
		// Pick random ephemeral port 20000-65535
		*port = rand.Intn(45536) + 20000
	}

	if *verboseLogging {
		destStr := fmt.Sprintf("exfil Destination: %s:%d", *ip, *port)
		log.Println(destStr)
	}

	microemuserver.CertFileLoc = *servercert
	microemuserver.KeyFileLoc = *serverkey
	var wg sync.WaitGroup

	if *serveronly && *clientonly {
		log.Fatal(errors.New("to run both client and server, omit serveronly and clientonly options"))
	}

	if *serveronly {
		microemuserver.StartServer(*exfilmethod, *port, nil)
		return
	}

	if !*clientonly {
		wg.Add(1)
		go microemuserver.StartServer(*exfilmethod, *port, &wg)

	}

	// Give time for server to turn on
	time.Sleep(3 * time.Second)

	err = createDummyFiles(32, 128)

	if err != nil {
		log.Fatal(err)
	}

	filePaths, err := fileDiscovery()

	if err != nil {
		cleanFiles()
		log.Fatal(err)
	}

	data, err := stageFiles(filePaths)

	if err != nil {
		cleanFiles()
		log.Fatal(err)
	}

	err = exfilData(data)

	if err != nil {
		cleanFiles()
		log.Fatal(err)
	}

	err = cleanFiles()

	if err != nil {
		log.Fatal(err)
	}

	wg.Wait() // wait for server to terminate

}

// Returns error on unrecognized protocol
func validateExfilProtocol() error {
	for _, protocol := range exfilProtocols {
		if protocol == *exfilmethod {
			return nil
		}
	}

	return errors.New("unrecognized exfilmethod. options include: tcp, tls, quic")
}

func exfilData(data []byte) error {
	switch *exfilmethod {
	case "tcp":
		return tcpExfil(data)
	case "tls":
		return tlsExfil(data)
	case "quic":
		return quicExfil(data)
	default:
		// Unknown exfilmethod should be caught in earlier flag parsing in main
		// but just in case
		return errors.New("unrecognized exfilmethod. options include: tcp, tls, quic")
	}
}

func tcpExfil(data []byte) error {
	conn, err := net.Dial("tcp", *ip+":"+strconv.Itoa(*port))

	if err != nil {
		return err
	}

	n, err := conn.Write(data)

	logSend(n)

	if err != nil {
		return err
	}

	conn.Close()

	return nil
}

func quicExfil(data []byte) error {
	conn, err := quic.DialAddr(*ip+":"+strconv.Itoa(*port), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}}, nil)

	if err != nil {
		return err
	}

	stream, err := conn.OpenUniStreamSync(context.Background())

	if err != nil {
		return err
	}

	n, err := stream.Write(data)

	logSend(n)

	if err != nil {
		return err
	}

	stream.Close()

	return nil
}

func tlsExfil(data []byte) error {
	conn, err := tls.Dial("tcp", *ip+":"+strconv.Itoa(*port), &tls.Config{InsecureSkipVerify: true})

	if err != nil {
		return err
	}

	n, err := conn.Write(data)

	logSend(n)

	if err != nil {
		return err
	}

	conn.Close()

	return nil
}

func createDummyFiles(numDirs uint, numFiles uint) error {
	// Create dummy directories
	err := os.Mkdir("searchFiles", os.ModePerm)

	if err != nil {
		return err
	}

	var dirs []string
	dirs = make([]string, 0, numDirs)
	for i := uint(0); i < numDirs; i++ {
		dir, err := os.MkdirTemp("searchFiles/", "")

		if err != nil {
			return err
		}

		dirs = append(dirs, dir)
	}

	// Create dummy files
	var randomDir string
	for i := uint(0); i < numFiles; i++ {
		randomDir = dirs[rand.Intn(len(dirs))]

		file, err := os.CreateTemp(randomDir, "exfilFile_*.txt")

		if err != nil {
			return err
		}

		file.WriteString(loremipsum.New().Paragraphs(rand.Intn(loremipsumMaxParagraphs-32) + 32))
		file.Close()
	}

	return nil
}

// Returns string of filePaths to exfil
func fileDiscovery() ([]string, error) {
	filePaths := make([]string, 0)

	err := filepath.Walk(".", func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.Contains(info.Name(), "exfilFile") {
			filePaths = append(filePaths, path)
			if *verboseLogging {
				log.Println("client: discovered " + info.Name())
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return filePaths, nil
}

func cleanFiles() error {
	err := os.RemoveAll("searchFiles")

	if err != nil {
		return err
	}

	err = os.Remove("exfil.zip")

	if err != nil {
		return err
	}

	return nil
}

// Returns data to exfil
func stageFiles(filePaths []string) ([]byte, error) {
	// Create zip
	zipFile, err := os.Create("exfil.zip")
	defer zipFile.Close()

	if err != nil {
		return nil, err
	}

	zipWriter := zip.NewWriter(zipFile)

	for _, filePath := range filePaths {

		fileInfo, err := os.Lstat(filePath)

		if err != nil {
			return nil, err
		}

		header, err := zip.FileInfoHeader(fileInfo)

		if err != nil {
			return nil, err
		}

		header.Method = zip.Deflate

		writer, err := zipWriter.CreateHeader(header)

		if err != nil {
			return nil, err
		}

		file, err := os.Open(filePath)
		defer file.Close()

		if err != nil {
			return nil, err
		}

		_, err = io.Copy(writer, file)

		if err != nil {
			return nil, err
		}
	}

	zipWriter.Close()

	fileInfo, err := zipFile.Stat()

	if err != nil {
		return nil, err
	}

	zippedData := make([]byte, fileInfo.Size())

	// Gotta use ReadAt to reset our pointer to start of file after writing
	_, err = zipFile.ReadAt(zippedData, 0)

	if err != nil {
		return nil, err
	}

	zipFile.Close()

	if *encrypt {
		// No parameter provided, generate random AES-256 key
		if *base64encryptKey == "" {
			var err error
			microemuserver.EncryptKey, err = generateRandomKey()

			if err != nil {
				return nil, err
			}
		} else {
			// Verify parameter is correct
			keyBytes, err := base64.StdEncoding.DecodeString(*base64encryptKey)

			if err != nil {
				return nil, err
			}

			keyLen := len(keyBytes)

			if keyLen != 16 && keyLen != 24 && keyLen != 32 {
				return nil, errors.New("invalid keylength, should be 16, 24, or 32 bytes (AES-128, AES-192, AES-256)")
			}

			microemuserver.EncryptKey = keyBytes
		}

		if !*verboseLogging {
			log.Println("Using encryption key: " + base64.StdEncoding.EncodeToString(microemuserver.EncryptKey))
		}

		cipherText, err := encryptBytes(zippedData, microemuserver.EncryptKey)

		if err != nil {
			return nil, err
		}

		return cipherText, nil
	} else {
		return zippedData, nil
	}

}

// Returns random 32-byte (256-bit) key
func generateRandomKey() ([]byte, error) {
	key := make([]byte, 32)

	_, err := rand.Read(key)

	if err != nil {
		return nil, err
	}

	return key, nil
}

// Performs AES-GCM
func encryptBytes(plainText []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)

	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())

	cipherText := aesGCM.Seal(nonce, nonce, plainText, nil)

	// https://www.melvinvivas.com/how-to-encrypt-and-decrypt-data-using-aes

	return cipherText, nil
}

func logSend(numBytes int) {
	if !*verboseLogging {
		return
	}
	sendDebugMsg := fmt.Sprintf("client: sending %d bytes", numBytes)
	log.Println(sendDebugMsg)
}
