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
	tcpAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:8989")
	utils.CheckError(err)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	utils.CheckError(err)

	echoProtocol := &echo.EchoProtocol{}

	_, pub_key := utils.LoadAndParse()
	sessionkey := []byte{9, 10, 11, 12, 13, 14, 15, 16}
	message := []byte{1}

	// encrypt sessionkey
	encryptedSessionKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		pub_key,
		sessionkey,
		[]byte(""),
	)
	utils.CheckError(err)

	message = append(message, encryptedSessionKey...)

	conn.Write(echo.NewEchoPacket([]byte(message), false).Serialize())
	p, err := echoProtocol.ReadPacket(conn)
	if err == nil {
		echoPacket := p.(*echo.EchoPacket)
		fmt.Printf("Server reply:[%v] [%v]\n", echoPacket.GetLength(), string(echoPacket.GetBody()))
	}

	secretmessage := []byte("KELOMPOK 3 KI B!")
	message = []byte{2}
	ciphertext := make([]byte, 16)

	block, err := des.NewCipher(sessionkey)
	utils.CheckError(err)
	block.Encrypt(ciphertext[0:8], secretmessage[0:8])
	block.Encrypt(ciphertext[8:16], secretmessage[8:16])
	message = append(message, ciphertext...)

	conn.Write(echo.NewEchoPacket([]byte(message), false).Serialize())

	p, err = echoProtocol.ReadPacket(conn)
	if err == nil {
		echoPacket := p.(*echo.EchoPacket)
		fmt.Printf("Server reply:[%v] [%v]\n", echoPacket.GetLength(), string(echoPacket.GetBody()))
	}

	if false {
		// ping <--> pong
		for i := 0; i < 3; i++ {
			// write
			conn.Write(echo.NewEchoPacket([]byte("hello"), false).Serialize())

			// read
			p, err := echoProtocol.ReadPacket(conn)
			if err == nil {
				echoPacket := p.(*echo.EchoPacket)
				fmt.Printf("Server reply:[%v] [%v]\n", echoPacket.GetLength(), string(echoPacket.GetBody()))
			}

			time.Sleep(2 * time.Second)
		}
	}

	conn.Close()
}
