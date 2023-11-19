package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"path/filepath"
)

func Check(e error) {
	if e != nil {
		panic(e)
	}
}

func CheckError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return privkey, &privkey.PublicKey
}

func ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
	privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkey_bytes,
		},
	)
	return string(privkey_pem)
}

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)

	return string(pubkey_pem), nil
}

func GenerateAndSave() (priv_pem string, pub_pem string) {
	// Create the keys
	priv, pub := GenerateRsaKeyPair()

	// Export the keys to pem string
	priv_pem = ExportRsaPrivateKeyAsPemStr(priv)
	pub_pem, _ = ExportRsaPublicKeyAsPemStr(pub)

	f, err := os.Create(filepath.Join("..", "server", "server_private.key"))
	Check(err)
	_, err = f.WriteString(priv_pem)
	Check(err)

	f, err = os.Create(filepath.Join("..", "server", "server_public.key"))
	Check(err)
	_, err = f.WriteString(pub_pem)
	Check(err)

	return
}

func LoadAndParse() (priv_key *rsa.PrivateKey, pub_key *rsa.PublicKey) {
	privIn := make([]byte, 5000)
	pubIn := make([]byte, 5000)

	//open server_private.key on server folder
	f, err := os.Open(filepath.Join("..", "server", "server_private.key"))
	Check(err)
	_, err = f.Read(privIn)
	Check(err)

	f, err = os.Open(filepath.Join("..", "server", "server_public.key"))
	Check(err)
	_, err = f.Read(pubIn)
	Check(err)

	// Import the keys from pem string
	priv_key, _ = ParseRsaPrivateKeyFromPemStr(string(privIn))
	pub_key, _ = ParseRsaPublicKeyFromPemStr(string(pubIn))

	return
}

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("key type is not RSA")
}
