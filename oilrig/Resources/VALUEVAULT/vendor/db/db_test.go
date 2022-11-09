package db_test

import (
	"db"
	"strings"
	"testing"
)

var database = db.InitializeDB()

func TestCreateLoginsTable(t *testing.T) {
	err := database.CreateLoginsTable()
	if err != nil {
		t.Fatal("Unable to create table")
	}
}

func TestInsertLogin(t *testing.T) {
	err := database.InsertLogin("http://random.com", "user", "password")
	if err != nil {
		t.Fatal("Unable to insert login")
	}
}

func TestGetDBNameFilePath(t *testing.T) {
	var path string = db.GetDBNameFilePath()
	if !(strings.Contains(path, "AppData")) {
		t.Fatal("DB path does not contain AppData")
	}
}
