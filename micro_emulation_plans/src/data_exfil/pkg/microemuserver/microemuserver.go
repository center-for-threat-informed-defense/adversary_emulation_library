package microemuserver

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
)

var bytesReceived int = 0

func StartServer(exfilMethod string, port int, wg *sync.WaitGroup) {
	serverStartupStr := fmt.Sprintf("starting %s server", exfilMethod)
	if *VerboseLogging {
		log.Println(serverStartupStr)
	}

	switch exfilMethod {
	case "tcp":
		tcpServer(port)
	case "tls":
		tlsServer(port)
	case "quic":
		quicServer(port)
	default:
		// Unknown exfilmethod should be caught in earlier flag parsing in main
		// but just in case
		log.Fatal("unrecognized exfilmethod. options include: tls, quic")
	}

	// Server funcs returns after reciving all data (when client closes the connection)
	serverShutdownStr := fmt.Sprintf("shutting down %s server", exfilMethod)
	if *VerboseLogging {
		log.Println(serverShutdownStr)
	}

	if wg != nil {
		wg.Done()
	}

}

func tcpServer(port int) {
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(port))

	if err != nil {
		log.Fatal(err)
	}

	conn, err := listener.Accept()

	if err != nil {
		log.Fatal(err)
	}

	//reader := bufio.NewReader(conn)
	buf := make([]byte, 1024) // read one kb at a time
	for {
		n, err := conn.Read(buf)

		if err != nil {
			if err == io.EOF {
				logReceive(bytesReceived)
				conn.Close()
				listener.Close()
				return
			} else {
				conn.Close()
				listener.Close()
				log.Fatal(err)
			}
		}

		bytesReceived += n
	}
}

func quicServer(port int) {
	cert, err := tls.LoadX509KeyPair(CertFileLoc, KeyFileLoc)
	//cert, err := tls.X509KeyPair([]byte(serverCert), []byte(serverKey))

	if err != nil {
		log.Fatal(err)
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{http3.NextProtoH3}}

	listener, err := quic.ListenAddr(":"+strconv.Itoa(port), tlsConfig, nil)

	if err != nil {
		log.Fatal(err)
	}

	conn, err := listener.Accept(context.Background())

	if err != nil {
		log.Fatal(err)
	}

	// Use streams over datagrams, delivery per message needs to be guaranteed
	stream, err := conn.AcceptUniStream(context.Background())

	if err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, 1024) // read one kb at a time
	for {
		n, err := stream.Read(buf)

		if err != nil {
			if err == io.EOF {
				logReceive(bytesReceived)
				listener.Close()
				return
			} else {
				listener.Close()
				log.Fatal(err)
			}
		}

		bytesReceived += n
	}
}

func tlsServer(port int) {
	cert, err := tls.LoadX509KeyPair("cert-server.pem", "key-server.pem")
	//cert, err := tls.X509KeyPair([]byte(serverCert), []byte(serverKey))

	if err != nil {
		log.Fatal(err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	listener, err := tls.Listen("tcp", ":"+strconv.Itoa(port), tlsConfig)

	if err != nil {
		log.Fatal(err)
	}

	conn, err := listener.Accept()

	if err != nil {
		log.Fatal(err)
	}

	//reader := bufio.NewReader(conn)
	buf := make([]byte, 1024) // read one kb at a time
	for {
		n, err := conn.Read(buf)

		if err != nil {
			if err == io.EOF {
				logReceive(bytesReceived)
				conn.Close()
				listener.Close()
				return
			} else {
				conn.Close()
				listener.Close()
				log.Fatal(err)
			}
		}

		bytesReceived += n
	}
}

func logReceive(numBytes int) {
	if !*VerboseLogging {
		return
	}
	recvDebugMsg := fmt.Sprintf("server: received %d bytes", numBytes)
	log.Println(recvDebugMsg)
}

// Needs testing
// https://www.melvinvivas.com/how-to-encrypt-and-decrypt-data-using-aes
func decryptBytes(cipherText []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(EncryptKey)

	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)

	if err != nil {
		return nil, err
	}

	nonceLen := aesGCM.NonceSize()

	nonce, cipherText := cipherText[:nonceLen], cipherText[nonceLen:]

	return aesGCM.Open(nil, nonce, cipherText, nil)
}
