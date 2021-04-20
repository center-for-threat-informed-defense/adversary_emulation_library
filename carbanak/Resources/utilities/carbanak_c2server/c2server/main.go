package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/fatih/color"
	"gitlab.mitre.org/mlong/carbon-ack/cli"
	"gitlab.mitre.org/mlong/carbon-ack/httpserver"
)

func main() {

	flag.Usage = func() {
		usageText := `
	Description
	----------------------------------------------------------------------------------------
	This program is a simple HTTP/S C2 server used for ATT&CK Evaluations.

	Usage
	----------------------------------------------------------------------------------------
	./c2server [Options]

	Available Options:
	----------------------------------------------------------------------------------------
	-lhost		The listening IP address used for C2
	-ssl		Enable TLS encryption
	-cert		Path to SSL certificate; generated automatically if this option is left blank
	-key		Path to SSL private key; generated automatically if this option is left blank
	-ver		Get program version information

	Examples
	----------------------------------------------------------------------------------------
	1. Start C2 server, listening on 10.10.10.10 at TCP 80 (HTTP)
	 ./c2server -lhost 10.10.10.10:8080
	
	2. Enable SSL; generate SSL cert and key automatically
	 ./c2server -lhost 10.10.10.10:443 -ssl

	3. Enable SSL with specified cert and key files
	 ./c2server -lhost 10.10.10.10:443 -ssl -cert cert.pem -key cert.pem

	`
		fmt.Fprintf(os.Stderr, "%s\n", usageText)
	}
	lhost := flag.String("lhost", "127.0.0.1:443", "the listening IP address used for C2")
	enableSSL := flag.Bool("ssl", false, "Enable TLS encryption")
	certFile := flag.String("cert", "", "Path to SSL certificate")
	keyFile := flag.String("key", "", "Path to SSL private key")
	//logFile := flag.String("logFile", "log.txt", "")
	ver := flag.Bool("ver", false, "Get program version information")
	flag.Parse()

	// display version info
	if *ver {
		printVersion()
		return
	}

	// display banner
	printBanner()

	// start C2 web server
	go httpserver.Start(*enableSSL, *lhost, *certFile, *keyFile)

	// start CLI
	time.Sleep(3 * time.Second)
	cli.Start()
}

func printBanner() {
	banner, err := ioutil.ReadFile("banner.txt")
	if err != nil {
		log.Println(err)
	}
	s := string(banner)
	fmt.Println(color.CyanString(s))
}

func printVersion() {
	ver := `
	Name: 		ATT&CK Evals Simple C2 Server
	Author: 	The MITRE Corporation
	Version: 	1.0
	Website:	https://attackevals.mitre.org/
	`
	fmt.Println(ver)
}
