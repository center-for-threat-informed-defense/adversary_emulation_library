package files_test

import (
	"testing"

	"attackevals.mitre-engenuity.org/exaramel-windows/files"
)

func TestListFilesRecursive(t *testing.T) {
	dir := "C:\\Users\\Public"
	_, err := files.ListFilesRecursive(dir)
	if err != nil {
		t.Fatal(err)
	}
}

func TestWriteToFile(t *testing.T) {

	file := "./testFile.txt"
	testData := "testing"

	err := files.WriteToFile(file, []byte(testData))
	if err != nil {
		t.Fatal(err)
	}
	defer files.DeleteFile(file)

	got, err := files.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(testData)
	if string(got) != string(want) {
		t.Fatalf("expected %v got %v", want, got)
	}
}
