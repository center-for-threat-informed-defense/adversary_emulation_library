package pkt

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
)

// Represents oceanlotus handler. Will impliment util.Handler interface
type oceanlotusHandler struct {
	restAPIaddress       string
	serverAddress        string
	l                    net.Listener //need to refernce for closing the connection cleanly
	commandNumbers       map[string]int
	pendingCommandOutput map[string]map[int]bool
	encryptionEnabled    bool
}

type ImplantPacket struct {
	//header data
	magicByte   []byte
	messageCode []byte
	keyLen      []byte
	payloadLen  []byte // either 0 or count after 82 bytes
	//implant information
	UUID        string `json:",omitempty"`
	DateExec    string `json:",omitempty"`
	socket      string `json:",omitempty"` //reporting based
	flags       string `json:",omitempty"` //reporting based
	family      string `json:",omitempty"` //reporting based - operating system platform
	Data        string `json:",omitempty"` //task output - used to send to another function
	DataLength  int32  `json:",omitempty"` //length of task out put
	firstPacket bool   `default:"false"`
	protocal    string `json:",omitempty"` //reporting based HTTP or TCP
}

type Task struct {
	cmdCode     string
	args        string
	payloadData []byte
	payloadLen  int32
}

func convertByte2Int(lenBytes []byte, size int) int {
	//lenBytes = []byte{0x04, 0x04, 0x04, 0x04}
	lenBytesInt := int(big.NewInt(0).SetBytes(lenBytes).Uint64())
	return (lenBytesInt)
}

func convertInt2Byte(value int, size int) []byte {
	//var value int = 1234;          // int
	var int64Val = big.NewInt(int64(value)) // int to big Int
	byteSlice := make([]byte, size)
	byteSlice = int64Val.Bytes()
	return (byteSlice)
}

/*
createLotusHeader() returns []byte array
* initializies a  struct with default values
* initializies a byte array of 82 bytes
* adds the struct values to the byte array
* adds several constant values at a specified index in the byte array (bytes resemble unicode characters)
*/
func CreateLotusHeader() []byte {
	//magic byte secquence
	//黑客 = hacker = e9 bb 91 e5 ae a2 = 233 187 145 229 174 162

	payloadLenBytes := convertInt2Byte(1024, 4)
	keyLenBytes := convertInt2Byte(8, 2)
	fmt.Println("payload as bytes: ", payloadLenBytes, " keylen as bytes: ", keyLenBytes)

	lotus := ImplantPacket{
		magicByte:   []byte{0x3B, 0x91, 0x01, 0x10},
		payloadLen:  payloadLenBytes,
		keyLen:      keyLenBytes,
		messageCode: []byte{0x21, 0x70, 0x27, 0x2},
	}

	//allocate header
	header := make([]byte, 82)
	index := 0
	copy(header[index:], lotus.magicByte) //magic key
	index += len(lotus.magicByte)
	index += 8
	copy(header[index:(index+4)], lotus.payloadLen) //payload length
	index += 4
	copy(header[index:(index+2)], lotus.keyLen) //key length
	index += 2
	copy(header[index:(index+4)], lotus.messageCode) //key length

	copy(header[19:], []byte{0xC2}) //marker 1
	copy(header[24:], []byte{0xE2}) //marker 2
	copy(header[29:], []byte{0xC2}) //marker 3
	copy(header[75:], []byte{0xFF}) //marker 4
	fmt.Println("Header byte sequence being sent across the wire:\n", hex.EncodeToString(header))
	return header
}

// return an implant data struct
func (o *oceanlotusHandler) parseDataStream(dataStream []byte, length int) (*ImplantPacket, error) {
	//fmt.Println("#### Data stream sent from the client:\n", dataStream, "####")
	//save data steram to new ImplantPacket struct
	lotus := new(ImplantPacket)
	index := 0
	lotus.magicByte = dataStream[index : index+4] //magic key
	index += 8                                    // magic code = 4 and junk data = 4

	lotus.payloadLen = dataStream[index:(index + 4)] //payload length
	index += 4
	lotus.keyLen = dataStream[index:(index + 2)] //key length
	index += 2
	lotus.messageCode = dataStream[index : index+4] //initial, beacon, or response
	index += 4
	//if first packet will also set the protocal, UUID, and firstpacket bool. Calls setUUID()
	firstPacketCheck(lotus)
	//fmt.Println(lotus)
	return lotus, nil
}

func firstPacketCheck(p *ImplantPacket) {
	magic := []byte{0x3B, 0x91, 0x01, 0x10}
	firstPacketCmd := []byte{0x21, 0x70, 0x27, 0x2}
	//Set the value for first packet, true or false
	p.firstPacket = false
	if bytes.Equal(p.magicByte, magic) &&
		bytes.Equal(p.messageCode, firstPacketCmd) &&
		p.UUID == "" {
		p.firstPacket = true
		//fmt.Println("hit first packet")
		p.UUID = "tmpID"
		//setUUID(p)
	} else {
		p.firstPacket = false
	}
}

func VerifyItsALotus(header []byte) bool {
	marker1 := []byte{0xC2}
	marker2 := []byte{0xE2}
	marker3 := []byte{0xC2}
	marker4 := []byte{0xFF}
	//fmt.Println(header[19:20], header[24:25], header[29:30], header[75:76])
	if !bytes.Equal(marker1, header[19:20]) {
		fmt.Println("First part of rota is not-valid")
	}
	if !bytes.Equal(marker2, header[24:25]) {
		fmt.Println("Second part of rota is not-valid")
	}
	if !bytes.Equal(marker3, header[29:30]) {
		fmt.Println("Third part of rota is not-valid")
	}
	if !bytes.Equal(marker4, header[75:76]) {
		fmt.Println("Forth part of rota is not-valid")
	}

	if bytes.Equal(marker1, header[19:20]) &&
		bytes.Equal(marker2, header[24:25]) &&
		bytes.Equal(marker3, header[29:30]) &&
		bytes.Equal(marker4, header[75:76]) {
		return true
	}
	return false
}
