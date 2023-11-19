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

var sessionkey = []byte{0, 0, 0, 0, 0, 0, 0, 0}

type Callback struct{}

func (*Callback) OnConnect(c *gotcp.Conn) bool {
	addr := c.GetRawConn().RemoteAddr()
	c.PutExtraData(addr)
	fmt.Println("OnConnect:", addr)
	return true
}

func (*Callback) OnMessage(c *gotcp.Conn, p gotcp.Packet) bool {
	echoPacket := p.(*echo.EchoPacket)
	body := echoPacket.GetBody()
	if body[0] == 1 {
		priv_key, _ := utils.LoadAndParse()
		paket := echo.NewEchoPacket([]byte("OK1"), false)

		pak := echoPacket.GetBody()[1:]
		decriptedMessage, err := rsa.DecryptOAEP(
			sha256.New(),
			rand.Reader,
			priv_key,
			pak,
			[]byte(""),
		)
		utils.CheckError(err)

		copy(sessionkey, decriptedMessage[0:8])
		fmt.Println("SESSION KEY:", sessionkey)
		c.AsyncWritePacket(paket, time.Second)
		fmt.Println("OK1")

	} else if body[0] == 2 {
		pak := echoPacket.GetBody()[1:]
		plaintext := make([]byte, 16)

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

func (*Callback) OnClose(c *gotcp.Conn) {
	fmt.Println("OnClose:", c.GetExtraData())
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// creates a tcp listener
	tcpAddr, err := net.ResolveTCPAddr("tcp4", ":8989")
	utils.CheckError(err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	utils.CheckError(err)

	// generate private and public key
	utils.GenerateAndSave()
	fmt.Println("Berhasil membuat private key dan public key")

	// creates a server
	config := &gotcp.Config{
		PacketSendChanLimit:    20,
		PacketReceiveChanLimit: 20,
	}
	srv := gotcp.NewServer(config, &Callback{}, &echo.EchoProtocol{})

	// starts service
	go srv.Start(listener, time.Second)
	fmt.Println("listening:", listener.Addr())

	// catchs system signal
	chSig := make(chan os.Signal)
	signal.Notify(chSig, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Signal: ", <-chSig)

	// stops service
	srv.Stop()
}
