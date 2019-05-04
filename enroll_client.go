package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"runtime"
)

type message struct {
	size          []byte
	enrollType    []byte
	challenge     []byte
	teamNumber    []byte
	projectChoice []byte
	nonce         []byte
	email         []byte
	firstname     []byte
	lastname      []byte
}

var (
	initMessage   message
	packedMessage []byte
)

const (
	remoteURL  string = "fulcrum.net.in.tum.de"
	remotePort int    = 34151

	enrollInit     uint16 = 680
	enrollRegister uint16 = 681
	enrollSuccess  uint16 = 682
	enrollFailure  uint16 = 683
)

// Network functions ---------------------------------------
func buildTCP() *net.Conn {
	log.Printf("Dialing to: %s:%d...\n", remoteURL, remotePort)
	con, err := net.Dial("tcp", fmt.Sprintf("%s:%d", remoteURL, remotePort))

	if err != nil {
		log.Fatalf("Connection went wrong!")
	} else {
		log.Printf("Connected.\n")
	}

	return &con
}

// Receive Messages ------------------------
func receiveHandler(con *net.Conn) {
	// Receive the size of the message
	buffer := bytes.NewBuffer(make([]byte, 0, 512))
	_, errSize := io.CopyN(buffer, *con, 2)

	log.Printf("Receiving HeaderSize...")

	if errSize != nil {
		log.Fatalf("Receiving the HeaderSize failed.")
	}

	msgSize := binary.BigEndian.Uint16(buffer.Next(2))
	log.Printf("Length of the response is: %dBytes\n", msgSize)

	// Receive the rest of the message
	_, errBody := io.CopyN(buffer, *con, int64(msgSize-2))

	log.Printf("Receiving Message Body...")

	if errBody != nil {
		log.Fatalf("Receiving the Message Body failed.")
	}

	// Evaluate Type of the received Message
	switch binary.BigEndian.Uint16(buffer.Next(2)) {
	case enrollInit:
		initMessage.challenge = buffer.Next(8)
		log.Printf("Enroll Init: %x", initMessage.challenge)
	case enrollSuccess:
		buffer.Next(2)
		log.Printf("Enroll Success!!!\nteam number: %d", binary.BigEndian.Uint16(buffer.Next(2)))
	case enrollFailure:
		buffer.Next(2)
		log.Printf("Enroll Failure!!!\nerror number: %d, error message: %s", buffer.Next(2), string(buffer.Bytes()))
	}
}

// Send Messages ---------------------------
func sendFinalMessage(con *net.Conn) {
	// merge the Header and the hashed message together
	buf := bytes.NewBuffer(make([]byte, 0, 512))

	// calculate size of the message: Message Size (unknown) + Header Size (4)
	binary.BigEndian.PutUint16(initMessage.size, uint16(binary.Size(packedMessage)+4))
	binary.Write(buf, binary.BigEndian, initMessage.size)

	// Add Enroll Type
	binary.Write(buf, binary.BigEndian, initMessage.enrollType)

	// Add the packed message
	binary.Write(buf, binary.BigEndian, packedMessage)

	// Send the result
	log.Printf("Uploading message: %x\n", buf.Bytes())

	_, err := io.Copy(*con, buf)

	if err != nil {
		log.Fatalf("Upload failed.")
	} else {
		log.Printf("Upload successful \n")
	}

}

// Utility functions ---------------------------------------
func messageInit() {
	// Set up Size -
	initMessage.size = make([]byte, 2)
	binary.BigEndian.PutUint16(initMessage.size, 0)

	// Set up enroll register
	initMessage.enrollType = make([]byte, 2)
	binary.BigEndian.PutUint16(initMessage.enrollType, enrollRegister)

	// Set up Challenge
	initMessage.challenge = make([]byte, 8)
	binary.BigEndian.PutUint64(initMessage.challenge, 0)

	// Set up team number
	initMessage.teamNumber = make([]byte, 2)
	binary.BigEndian.PutUint16(initMessage.teamNumber, 0)

	// Set up project choice
	initMessage.projectChoice = make([]byte, 2)
	binary.BigEndian.PutUint16(initMessage.projectChoice, 39943)

	// Set up nonce
	initMessage.nonce = make([]byte, 8)
	binary.BigEndian.PutUint64(initMessage.nonce, 0)

	// Set up email
	initMessage.email = []byte("ga94kow@mytum.de\r\n")
	// Set up first name
	initMessage.firstname = []byte("Maximilian-Dominik\r\n")
	// Set up last name
	initMessage.lastname = []byte("Robl")
}

// This function implements the RFC 6234 padding standard - since sha256 is already using padding this is not used
func padding(message []byte, identifier string) []byte {
	// create padding for the strings email, firstname, lastname - RFC6234 multiple of 512

	// calculate length
	messageSize := binary.Size(message) * 8
	log.Printf("%s size: %dBit\n", identifier, messageSize)
	// ( L + 1 + K ) mod 512 = 448 -> calculate k
	messageL := (messageSize % 512) + 1

	messageK := messageL
	if messageL > 448 {
		messageK = 448 + (512 - messageL)
	} else {
		messageK = 448 - messageL
	}

	// create buffer to add bytewise
	messageBuffer := bytes.NewBuffer(make([]byte, 0, 512))
	binary.Write(messageBuffer, binary.BigEndian, message)

	// add 1 - add k - Work with bytes 8bit - add: 1000 0000 | k-7 * 0 - all Strings: string % 8 = 0
	binary.Write(messageBuffer, binary.BigEndian, uint8(0x80))

	// itearate through the String length K and fill the buffer with 0s
	messageK -= 7

	// error Handling - if the padding failed
	if messageK < 0 || messageK%8 != 0 {
		log.Fatalf("%s Length of Bits is to long: %d", identifier, messageK)
	}

	// iteration
	for i := 0; i < messageK/8; i++ {
		binary.Write(messageBuffer, binary.BigEndian, uint8(0x00))
	}

	// 64-bit/8Byte block that is L in binary -> L original length
	binary.Write(messageBuffer, binary.BigEndian, uint64(messageSize))

	log.Printf("Padding for %s: %x(%dBytes|%dBits)\n", identifier, messageBuffer.Bytes(), binary.Size(messageBuffer.Bytes()), binary.Size(messageBuffer.Bytes())*8)
	return messageBuffer.Bytes()
}

func checkHash(data []byte) bool {
	// creating the hashfunction
	SHA256 := sha256.New()

	// add the string to the SHA256 function and execute - and clear the hashfunction
	SHA256.Write(data)

	hashValue := SHA256.Sum(nil)
	SHA256.Reset()

	// checking the hash - last 30bits = 0 ? ...
	// hash.Sum(): *[Size]byte* -> 30bits - 4 Byte - first 6Bit - BigEndian - 1111 1000 0xF8
	if hashValue[0] == 0 && hashValue[1] == 0 && hashValue[2] == 0 && hashValue[3]&0xF8 == 0 {
		log.Printf("Hash was found:\nHash: %x(%dBytes)\n", hashValue, binary.Size(hashValue))
		return true
	}

	return false
}

func findHash() {
	// create the data packet which needs hashing
	// creating a buffer to get all []byte
	buffer := bytes.NewBuffer(make([]byte, 0, 512))

	// write all Entries into this buffer
	binary.Write(buffer, binary.BigEndian, initMessage.challenge)
	binary.Write(buffer, binary.BigEndian, initMessage.teamNumber)
	binary.Write(buffer, binary.BigEndian, initMessage.projectChoice)

	binary.Write(buffer, binary.BigEndian, initMessage.nonce)

	binary.Write(buffer, binary.BigEndian, initMessage.email)
	binary.Write(buffer, binary.BigEndian, initMessage.firstname)
	binary.Write(buffer, binary.BigEndian, initMessage.lastname)

	// create 2 channels - 1 for receiving the nonce - 1 for
	resChan := make(chan []byte, 1)
	defer close(resChan)
	stopChan := make(chan struct{})

	// Use Threading to distribute the hashing Task - generate a random nonce
	for index := 0; index < runtime.NumCPU(); index++ {
		// every Nonce should be random - create random int - cvt to []byte
		rand.Seed(int64(index))
		nonceNumber := rand.Uint64()

		nonce := make([]byte, 8)
		binary.BigEndian.PutUint64(nonce, nonceNumber)

		// Print current message for debugging
		log.Printf("The current message is: %x\n", buffer.Bytes())

		// This function will be executed by every thread
		go func(index int, data []byte, nonce []byte, resultChannel chan []byte, stopChannel chan struct{}) {
			log.Printf("Thread %d: Calculating the right Nonce starting with %x \n", index, nonce)
			// Test all hashes
			for {
				// Check the channel for stopping
				select {
				//close routines bc other routine already found a result
				case <-stopChan:
					log.Printf("Thread %d: closed\n", index)
					runtime.Goexit()
				default:
					// Check the hash
					// start with merging the data and the hash
					// create new buffer and get all the values of hashlist and the nonce
					buf := bytes.NewBuffer(make([]byte, 0, 512))
					binary.Write(buf, binary.BigEndian, data[:12])
					binary.Write(buf, binary.BigEndian, nonce)
					binary.Write(buf, binary.BigEndian, data[20:])

					if checkHash(buf.Bytes()) {
						log.Printf("The final Nonce is: %x\nWith the message %x\n", nonce, buf.Bytes)

						// if the nonce is found - msg all threads - stop all threads and continue working
						resChan <- buf.Bytes()
						log.Printf("Thread %d: closed\n", index)
						runtime.Goexit()
					} else {
						// randomize nonce
						rand.Read(nonce)
					}
				}
			}
		}(index+1, buffer.Bytes(), nonce, resChan, stopChan)
	}

	// wait for a successful thread - Channel 1
	packedMessage = <-resChan

	// send close message - Channel 2
	close(stopChan)
}

// Main function -------------------------------------------

func main() {
	// start setting up the initMessage
	messageInit()

	// start a tcp connection
	con := buildTCP()

	// get Enroll init - refresh global var initMessage
	receiveHandler(con)

	// find the right hash
	findHash()

	// send a message to the Server and retrieve a message afterwards
	sendFinalMessage(con)
	receiveHandler(con)
}
