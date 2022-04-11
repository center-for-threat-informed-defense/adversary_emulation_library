package encrypt_test

import (
	"testing"

	"attackevals.mitre-engenuity.org/exaramel-windows/encrypt"
)

func TestListFilesRecursive(t *testing.T) {
	key := []byte("password")
	data := []byte("secret message")
	encrypted, err := encrypt.CryptRC4(key, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := encrypt.CryptRC4(key, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != string(data) {
		t.Fatalf("expected %v got %v", data, decrypted)
	}
}
