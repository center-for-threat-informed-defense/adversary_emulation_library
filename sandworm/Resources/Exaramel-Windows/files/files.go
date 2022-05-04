package files

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// ListFilesRecursive will perform a recursive file listing starting at the passed directory
func ListFilesRecursive(directory string) (string, error) {

	// check if directory is valid
	_, err := os.Open(directory)
	if err != nil {
		return "", err
	}

	fileInfo := make([]string, 1)

	filepath.Walk(directory,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				fileInfo = append(fileInfo, err.Error())
			}
			file := fmt.Sprintf("%v %v %v %v", path, info.Size(), info.ModTime(), info.Mode())
			fileInfo = append(fileInfo, file)
			return nil
		})

	outputToString := strings.Join(fileInfo, " ")

	return outputToString, nil
}

// WriteToFile will write data to the specified file
func WriteToFile(destFile string, destData []byte) error {
	err := ioutil.WriteFile(destFile, destData, 0744)
	if err != nil {
		return err
	}
	return err
}

// ReadFile returns data from the file specified by 'fileToRead'
func ReadFile(fileToRead string) ([]byte, error) {
	data, err := ioutil.ReadFile(fileToRead)
	if err != nil {
		return nil, err
	}
	return data, err
}

// DeleteFile removes a file from the filesystem
func DeleteFile(fileToDelete string) error {
	err := os.Remove(fileToDelete)
	if err != nil {
		return err
	}
	return err
}

func GetFileFromServer(url string, dstFile string) (string, error) {

	// download the test file
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}

	fileToWrite, err := os.Create(dstFile)
	if err != nil {
		return "", err
	}
	defer fileToWrite.Close()

	// Write the downloaded file data to the temp file
	bytesWritten, err := io.Copy(fileToWrite, resp.Body)
	if err != nil {
		return "", err
	}
	if bytesWritten == 0 {
		return "", errors.New("unexpected error - wrote 0 bytes data when downloading file")
	}
	result := fmt.Sprintf("Downloaded file of size %v to %v", bytesWritten, dstFile)
	return result, err
}

func PostFileToServer(url string, fileData []byte) (string, error) {
	response, err := http.Post(url, "application/octet-stream", bytes.NewBuffer(fileData))
	if err != nil {
		return "", err
	}
	s, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	return string(s), err
}
