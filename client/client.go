package main

import (
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"net"
	"time"
	"tugas1/utils"

	"github.com/gansidui/gotcp/examples/echo"
)

func main() {
	// Resolve TCP address
	tcpAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:8989")
	utils.CheckError(err)

	// Dial TCP connection
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	utils.CheckError(err)

	// Create an instance of the EchoProtocol
	echoProtocol := &echo.EchoProtocol{}

	// Load and parse public key
	_, pub_key := utils.LoadAndParse()

	// Define session key and message
	sessionkey := []byte{9, 10, 11, 12, 13, 14, 15, 16}
	message := []byte{1}

	// Encrypt the session key using RSA
	encryptedSessionKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		pub_key,
		sessionkey,
		[]byte(""),
	)
	utils.CheckError(err)

	// Append encrypted session key to the message
	message = append(message, encryptedSessionKey...)

	// Send the message to the server
	conn.Write(echo.NewEchoPacket([]byte(message), false).Serialize())

	// Read the server's response
	p, err := echoProtocol.ReadPacket(conn)
	if err == nil {
		echoPacket := p.(*echo.EchoPacket)
		fmt.Printf("Server reply:[%v] [%v]\n", echoPacket.GetLength(), string(echoPacket.GetBody()))
	}

	// Prepare a secret message and encrypt it using DES
	secretmessage := []byte("KELOMPOK 3 KI B!")
	message = []byte{2}
	ciphertext := make([]byte, 16)

	block, err := des.NewCipher(sessionkey)
	utils.CheckError(err)
	block.Encrypt(ciphertext[0:8], secretmessage[0:8])
	block.Encrypt(ciphertext[8:16], secretmessage[8:16])
	message = append(message, ciphertext...)

	// Send the encrypted message to the server
	conn.Write(echo.NewEchoPacket([]byte(message), false).Serialize())

	// Read the server's response
	p, err = echoProtocol.ReadPacket(conn)
	if err == nil {
		echoPacket := p.(*echo.EchoPacket)
		fmt.Printf("Server reply:[%v] [%v]\n", echoPacket.GetLength(), string(echoPacket.GetBody()))
	}

	if false {
		// Ping <--> Pong
		for i := 0; i < 3; i++ {
			// Write a ping message
			conn.Write(echo.NewEchoPacket([]byte("hello"), false).Serialize())

			// Read the server's response
			p, err := echoProtocol.ReadPacket(conn)
			if err == nil {
				echoPacket := p.(*echo.EchoPacket)
				fmt.Printf("Server reply:[%v] [%v]\n", echoPacket.GetLength(), string(echoPacket.GetBody()))
			}

			time.Sleep(2 * time.Second)
		}
	}

	// Close the connection
	conn.Close()
}
