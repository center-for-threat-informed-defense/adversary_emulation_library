package epic

import (
	"testing"
)

const (
    testingDataEncoded = "dGVzdGluZyBkYXRh"
)

var testingDataCompressed = []byte{0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x0e, 0xe6, 0xf5, 0xc1, 0x00, 0x00, 0x05, 0x11, 0x80, 0x40, 0x00, 0x26, 0xa1, 0x0c, 0x00, 0x20, 0x00, 0x22, 0x29, 0xfa, 0xa7, 0xe5, 0x47, 0xfa, 0x08, 0x06, 0x08, 0xeb, 0x42, 0x03, 0xae, 0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 0x0e, 0xe6, 0xf5, 0xc1}

func areSlicesEqual(x []byte, y []byte) bool {
    if len(x) != len(y) {
        return false
    }
    for i := 0; i < len(x); i++ {
        if x[i] != y[i] {
            return false
        }
    }
    return true
}

func TestBase64Encode(test *testing.T) {
    responseWant := testingDataEncoded
    responseActual := Base64Encode([]byte(testingData))
    if responseActual != responseWant {
        test.Errorf("Status mismatch, got '%s' expected '%s'", responseActual, responseWant)
    }
}

func TestBase64DecodeValid(test *testing.T) {
    responseWant := testingData
    responseActual, err := Base64Decode(testingDataEncoded)
    if err != nil {
        test.Error(err.Error())
    } else if string(responseActual) != responseWant {
        test.Errorf("Status mismatch, got '%s' expected '%s'", responseActual, responseWant)
    }
}

func TestBase64DecodeInvalid(test *testing.T) {
    responseWant := "illegal base64 data at input byte 7"
    _, err := Base64Decode(invalidTest)
    if err != nil {
        if err.Error() != responseWant {
            test.Errorf("Expected error message: '%s'; got: '%s'", responseWant, err.Error())
        }
    } else {
        test.Error("Expected error message.")
    }
}

func TestBzip2Compress(test *testing.T) {
    responseWant := testingDataCompressed
    responseActual, err := Bzip2Compress([]byte(testingData))
    if err != nil {
        test.Error(err.Error())
    } else if !areSlicesEqual(responseActual, responseWant) {
        test.Errorf("Status mismatch, got '%x' expected '%x'", responseActual, responseWant)
    }
}

func TestBzip2DecompressValid(test *testing.T) {
    responseWant := testingData
    responseActual, err := Bzip2Decompress(testingDataCompressed)
    if err != nil {
        test.Error(err.Error())
    } else if string(responseActual) != responseWant {
        test.Errorf("Status mismatch, got '%x' expected '%x'", string(responseActual), responseWant)
    }
}

func TestBzip2DecompressInvalid(test *testing.T) {
    responseWant := "bzip2 data invalid: bad magic value"
    _, err := Bzip2Decompress([]byte(invalidTest))
    if err != nil {
        if err.Error() != responseWant {
            test.Errorf("Expected error message: '%s'; got: '%s'", responseWant, err.Error())
        }
    } else {
        test.Error("Expected error message.")
    }
}
