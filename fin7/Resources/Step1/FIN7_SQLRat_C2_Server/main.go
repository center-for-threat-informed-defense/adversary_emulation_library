package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"dbcli"
)

func main() {

	flag.Usage = func() {
		usageText := `
	Description
	----------------------------------------------------------------------------------------
	This program is a simple MS SQL based C2 server used for ATT&CK Evaluations.

	Usage
	----------------------------------------------------------------------------------------
	./c2server [Options]

	Available Options:
	----------------------------------------------------------------------------------------
	-password	The user's password to the database
	-server		IP address of the server
	-user		Username for the database
	-database	Name of the database
	-ver		Get program version information

	Examples
	----------------------------------------------------------------------------------------
	1. Start C2 server, connecting to an MS SQL server hosted at IP 10.0.2.6
	 ./c2server -server 10.0.2.6
	
	2. Start C2 server, connecting to a particular database other than the evals_test default
	 ./c2server -server 10.0.2.6 -database random_db_name

	`
		fmt.Fprintf(os.Stderr, "%s\n", usageText)
	}
	password := flag.String("password", "Password1234", "the database password")
	server := flag.String("server", "10.0.2.5", "the database server's ip")
	user := flag.String("user", "evals_user", "the database user")
	database := flag.String("database", "tempdb", "the database name")
	ver := flag.Bool("ver", false, "Get program version information")
	flag.Parse()

	// display version info
	if *ver {
		printVersion()
		return
	}

	// display banner
	printBanner()

	dbcli.Start(*password, *server, *user, *database)
}

func printBanner() {
	banner, err := ioutil.ReadFile("banner.txt")
	if err != nil {
		log.Println("ATT&CK Evals Fin7 C2 Starting...")
	}
	fmt.Println(string(banner))
}

func printVersion() {
	ver := `
	Name: 		ATT&CK Evals Simple C2 MS SQL Server
	Author: 	The MITRE Corporation
	Version: 	1.0
	Website:	https://attackevals.mitre.org/
	`
	fmt.Println(ver)
}