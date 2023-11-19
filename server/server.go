package main

import (
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
	"tugas1/utils"

	"github.com/gansidui/gotcp"
	"github.com/gansidui/gotcp/examples/echo"
)

// Session key used for encryption/decryption
var sessionkey = []byte{0, 0, 0, 0, 0, 0, 0, 0}

// Callback struct for handling connection events
type Callback struct{}

// OnConnect is called when a new connection is established
func (*Callback) OnConnect(c *gotcp.Conn) bool {
	addr := c.GetRawConn().RemoteAddr()
	c.PutExtraData(addr)
	fmt.Println("OnConnect:", addr)
	return true
}

// OnMessage is called when a message is received from the client
func (*Callback) OnMessage(c *gotcp.Conn, p gotcp.Packet) bool {
	echoPacket := p.(*echo.EchoPacket)
	body := echoPacket.GetBody()

	if body[0] == 1 {
		// Handle message type 1
		priv_key, _ := utils.LoadAndParse()
		paket := echo.NewEchoPacket([]byte("OK1"), false)

		pak := echoPacket.GetBody()[1:]
		// Decrypt the received message using RSA
		decriptedMessage, err := rsa.DecryptOAEP(
			sha256.New(),
			rand.Reader,
			priv_key,
			pak,
			[]byte(""),
		)
		utils.CheckError(err)

		// Copy the decrypted session key
		copy(sessionkey, decriptedMessage[0:8])
		fmt.Println("SESSION KEY:", sessionkey)
		c.AsyncWritePacket(paket, time.Second)
		fmt.Println("OK1")

	} else if body[0] == 2 {
		// Handle message type 2
		pak := echoPacket.GetBody()[1:]
		plaintext := make([]byte, 16)

		// Decrypt the secret message using DES
		block, err := des.NewCipher(sessionkey)
		utils.Check(err)

		block.Decrypt(plaintext[0:8], pak[0:8])
		block.Decrypt(plaintext[8:16], pak[8:16])
		fmt.Println("SECRET MESSAGE: " + string(plaintext))

		paket := echo.NewEchoPacket([]byte("OK2"), false)
		c.AsyncWritePacket(paket, time.Second)
		fmt.Println("OK2")
	}

	return true
}

// OnClose is called when a connection is closed
func (*Callback) OnClose(c *gotcp.Conn) {
	fmt.Println("OnClose:", c.GetExtraData())
}

func main() {
	// Set the maximum number of CPUs that can be executing simultaneously
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Create a TCP listener
	tcpAddr, err := net.ResolveTCPAddr("tcp4", ":8989")
	utils.CheckError(err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	utils.CheckError(err)

	// Generate private and public key
	utils.GenerateAndSave()
	fmt.Println("Berhasil membuat private key dan public key")

	// Create a server configuration
	config := &gotcp.Config{
		PacketSendChanLimit:    20,
		PacketReceiveChanLimit: 20,
	}
	srv := gotcp.NewServer(config, &Callback{}, &echo.EchoProtocol{})

	// Start the server
	go srv.Start(listener, time.Second)
	fmt.Println("listening:", listener.Addr())

	// Catch system signals
	chSig := make(chan os.Signal)
	signal.Notify(chSig, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Signal: ", <-chSig)

	// Stop the server
	srv.Stop()
}
