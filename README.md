# KI-B-KEL3-Tugas1

## Anggota Kelompok

1. 5025201145 - MOCHAMAD REVANZA KURNIAWAN
2. 5025201152 - HELMI TAQIYUDIN
3. 5025201199 - ALFIN INDRAWAN
4. 5025201102 - ARYA NUR RAZZAQ
5. 5025201232 - AHMAD IBNU MALIK RAHMAN
6. 5025201041 - KHAIRUDDIN NASTY
7. 5025201208 - BAGUS FEBRIAN DALI HIDAYAT

## Deskripsi Aplikasi

Aplikasi ini adalah sistem komunikasi **client-server** yang berjalan pada protokol TCP, aplikasi ini menggunakan enkripsi RSA dalam pertukaran session key, dan enkripsi DES untuk bagian pesan. Server akan menunggu koneksi TCP, menangani koneksi yang masuk, dan memproses pesan yang diterima. Klien akan melakukan kontak koneksi ke server, mengirim session key yang terenkripsi RSA, dan bertukar pesan rahasia yang dienkripsi DES. Aplikasi ini juga terdapat utils.go untuk pembuatan RSA key, ekspor/import kunci, dan penanganan kesalahan.

## Cara Kerja Aplikasi

### Server

1. Konfigurasi server

```go
var sessionkey = []byte{0, 0, 0, 0, 0, 0, 0, 0}
type Callback struct{}
func main() {
    runtime.GOMAXPROCS(runtime.NumCPU())
    ...
    utils.GenerateAndSave()
}
```

Menyiapkan session key dan konfigurasi server

2. Menerima koneksi

```go
func (*Callback) OnConnect(c *gotcp.Conn) bool {
    addr := c.GetRawConn().RemoteAddr()
    c.PutExtraData(addr)
    fmt.Println("OnConnect:", addr)
    return true
}
```

Menerima koneksi dari client

3. Memproses pesan

```go
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
```

Pada fungsi ini, server akan memproses pesan yang diterima dari client. Pertama, server akan mengecek apakah pesan yang diterima adalah pesan pertama atau pesan kedua. Jika pesan pertama, maka server akan mengambil session key yang telah dienkripsi oleh client menggunakan RSA. Lalu, server akan mendekripsi session key tersebut menggunakan RSA private key yang telah diimport. Setelah itu, server akan mengirimkan pesan OK1 ke client. Jika pesan yang diterima adalah pesan kedua, maka server akan mendekripsi pesan tersebut menggunakan session key yang telah didapatkan sebelumnya. Setelah itu, server akan mengirimkan pesan OK2 ke client.

4. Menangani penutupan koneksi

```go
func (*Callback) OnClose(c *gotcp.Conn) {
    fmt.Println("OnClose:", c.GetExtraData())
}
```

Menangani penutupan koneksi dari client

### Client

1. Menghubungi server

```go
func main() {
    tcpAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:8989")
    conn, err := net.DialTCP("tcp", nil, tcpAddr)
    ...
}
```

Menghubungi server dan memulai koneksi TCP

2. Mengirimkan pesan pertama

```go
_, pub_key := utils.LoadAndParse()
encryptedSessionKey, err := rsa.EncryptOAEP(...)
message = append(message, encryptedSessionKey...)
conn.Write(echo.NewEchoPacket([]byte(message), false).Serialize())
```

Mengirimkan pesan pertama ke server. Pesan pertama berisi session key yang telah dienkripsi menggunakan RSA public key yang telah diimport dari file utils.go

3. Mengirimkan pesan kedua

```go
secretmessage := []byte("KELOMPOK 3 KI B!")
message = []byte{2}
ciphertext := make([]byte, 16)

block, err := des.NewCipher(sessionkey)
utils.CheckError(err)
block.Encrypt(ciphertext[0:8], secretmessage[0:8])
block.Encrypt(ciphertext[8:16], secretmessage[8:16])
message = append(message, ciphertext...)

conn.Write(echo.NewEchoPacket([]byte(message), false).Serialize())

```

Pada bagian ini client.go adan mengirimkan pesan kedua ke server. Pesan kedua ini berisi pesan rahasia yang akan di enkripsi menggunakan DES dan akan dikirimkan ke server.

### Utils

Berisi fungsi-fungsi untuk keperluan enkripsi, pembuatan kunci, dan melakukan handling error.

fungsi yang ada di utils.go:

- Error Checking
- Generates and saves RSA key
- Loads and parses RSA key
- Exports RSA key
- Imports RSA key
