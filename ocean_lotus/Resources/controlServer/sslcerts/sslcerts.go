package sslcerts

import (
	"fmt"
	"log"
	"os/exec"
)

func GenerateSSLcert(rootName string) (string, string) {
	if rootName == "" {
		rootName = "cert"
	}
	certFile := rootName + ".pem"
	keyFile := rootName + ".key"
	cmd := exec.Command("sh", "-c", fmt.Sprintf("openssl req -new -x509 -keyout ./%v -out ./%v -days 365 -nodes -subj \"/C=US\"", keyFile, certFile))
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	return certFile, keyFile
}

func CheckCert(certFile, keyFile string) bool {
	if (certFile == "") && (keyFile == "") {
		return true
	}
	return false
}
