package discovery_test

import (
	"testing"

	"attackevals.mitre-engenuity.org/exaramel-windows/discovery"
)

func TestGetCurrentserName(t *testing.T) {

	currentUser, err := discovery.GetCurrentUserName()

	if currentUser == "" {
		t.Fatal("expected a populated username, got \"\"")
	}

	if err != nil {
		t.Fatalf("unexpected error from discovery.GetCurrentUserName: %v", err)
	}
}

func TestGetOSInfo(t *testing.T) {
	want := "OS Info: Windows 10 Pro 10 0 19042"
	got, err := discovery.GetOSInfo()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("expected '%v' got '%v'", want, got)
	}
}
