package epic

import (
	"encoding/base64"
	"strings"
	"testing"
)

var (
    allEmpty = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    allPopulated = []byte{2, 0, 0, 0, 8, 0, 0, 0, 66, 83, 69, 113, 87, 81, 107, 61, 24, 0, 0, 0, 72, 101, 108, 108, 111, 32, 61, 32, 87, 111, 114, 108, 100, 10, 84, 101, 115, 116, 32, 61, 32, 49, 50, 51}
    escapeCharacters = []byte{8, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 65, 65, 65, 92, 110, 92, 61, 65, 65, 65, 32, 61, 32, 61, 61, 92, 110, 92, 110, 9}
)

func makeCommandBuffer() CommandBuffer {
    commandBuffer := CommandBuffer {
        commandId: 0,
        payload: []byte{},
        config: make(map[string]string),
    }
    return commandBuffer
}

func checkOutput(test *testing.T, actual []byte, expected []byte) {
    if string(actual) != string(expected) {
        test.Errorf("Output mismatch, got '%d' expected '%d'", actual, expected)
    }
}

// command ID is 0, no payload, no config file
func TestAllEmpty(test *testing.T) {
    commandBuffer := makeCommandBuffer()
    checkOutput(test, commandBuffer.buildImplantCommand(), allEmpty)
}

// command ID is 2, and payload/config file exists
func TestAllPopulated(test *testing.T) {
    commandBuffer := makeCommandBuffer()
    commandBuffer.commandId = 2
    commandBuffer.payload = append(commandBuffer.payload, 5, 33, 42, 89, 9)

    // order should be reversed in output since H comes before T in alphabet
    commandBuffer.addToConfig("Test", "123")
    commandBuffer.addToConfig("Hello", "World")
    
    checkOutput(test, commandBuffer.buildImplantCommand(), allPopulated)
}

// config file uses escape characters for = and \n
func TestEscapeCharacters(test *testing.T) {
    commandBuffer := makeCommandBuffer()
    commandBuffer.commandId = 8
    commandBuffer.addToConfig("AAA\n=AAA", "==\n\n\t")
    
    checkOutput(test, commandBuffer.buildImplantCommand(), escapeCharacters)
}

func generateLargeSlice() []byte {
    output := []byte{}
    for i:=0; i<256; i++ {
        b := byte(i)
        output = append(output, b, b, b, b, b, b, b, b)
    }
    return output
}

func TestLargeCommand(test *testing.T) {
    commandBuffer := makeCommandBuffer()
    commandBuffer.commandId = 10000
    commandBuffer.payload = generateLargeSlice()

    // output will be in order of C E I P
    commandBuffer.addToConfig("E", strings.Repeat("E", 995))
    commandBuffer.addToConfig("P", strings.Repeat("P", 995))
    commandBuffer.addToConfig("I", strings.Repeat("I", 995))
    commandBuffer.addToConfig("C", strings.Repeat("C", 995))

    // construct expected answer
    expected := []byte{16, 39, 0, 0, 172, 10, 0, 0} // command ID and payload len
    expected = append(expected, []byte(base64.StdEncoding.EncodeToString(generateLargeSlice()))...) // payload
    expected = append(expected, 159, 15, 0, 0) // config size
    expected = append(expected, 67, 32, 61, 32) // "C = "
    expected = append(expected, []byte(strings.Repeat("C", 995))...) // value for C
    expected = append(expected, 10, 69, 32, 61, 32) // "\nE = "
    expected = append(expected, []byte(strings.Repeat("E", 995))...) // value for E
    expected = append(expected, 10, 73, 32, 61, 32) // "\nI = "
    expected = append(expected, []byte(strings.Repeat("I", 995))...) // value for I
    expected = append(expected, 10, 80, 32, 61, 32) // "\nP = "
    expected = append(expected, []byte(strings.Repeat("P", 995))...) // value for P

    checkOutput(test, commandBuffer.buildImplantCommand(), expected)
}
