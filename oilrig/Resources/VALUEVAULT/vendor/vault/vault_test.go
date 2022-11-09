package vault_test

import (
	"db"
	"vault"
	"testing"
)

var database = db.InitializeDB()

func TestIsWindows8(t *testing.T) {
	if !(vault.IsWindows8orGreater()) {
		t.Fatal("False positive if testing from Windows 7 or before")
	}
}

func TestDumpVaultWin8(t *testing.T) {
	if vault.IsWindows8orGreater() {
		err := database.CreateLoginsTable()
		if err != nil {
			t.Fatal("Unable to create logins table")
		}

		if !(vault.DumpVaultWin8(database)) {
			t.Fatal("Unable to dump vault from Windows 8 or greater")
		}
	}
}

func TestDumpVaultWin7(t *testing.T) {
	if !(vault.IsWindows8orGreater()) {
		err := database.CreateLoginsTable()
		if err != nil {
			t.Fatal("Unable to create logins table")
		}

		if !(vault.DumpVaultWin7(database)) {
			t.Fatal("Unable to dump vault from Windows 7")
		}
	}
}
