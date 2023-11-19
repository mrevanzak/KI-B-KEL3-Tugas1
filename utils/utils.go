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

// Check panics if an error is not nil
func Check(e error) {
	if e != nil {
		panic(e)
	}
}

// CheckError logs and fatal if an error is not nil
func CheckError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// GenerateRsaKeyPair generates an RSA key pair (private and public keys)
func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return privkey, &privkey.PublicKey
}

// ExportRsaPrivateKeyAsPemStr exports an RSA private key as a PEM-encoded string
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

// ExportRsaPublicKeyAsPemStr exports an RSA public key as a PEM-encoded string
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

// GenerateAndSave generates and saves RSA keys to files
func GenerateAndSave() (priv_pem string, pub_pem string) {
	// Create the keys
	priv, pub := GenerateRsaKeyPair()

	// Export the keys to PEM strings
	priv_pem = ExportRsaPrivateKeyAsPemStr(priv)
	pub_pem, _ = ExportRsaPublicKeyAsPemStr(pub)

	// Save private key to file
	f, err := os.Create(filepath.Join("..", "server", "server_private.key"))
	Check(err)
	_, err = f.WriteString(priv_pem)
	Check(err)

	// Save public key to file
	f, err = os.Create(filepath.Join("..", "server", "server_public.key"))
	Check(err)
	_, err = f.WriteString(pub_pem)
	Check(err)

	return
}

// LoadAndParse loads and parses RSA keys from files
func LoadAndParse() (priv_key *rsa.PrivateKey, pub_key *rsa.PublicKey) {
	privIn := make([]byte, 5000)
	pubIn := make([]byte, 5000)

	// Open and read the private key file
	f, err := os.Open(filepath.Join("..", "server", "server_private.key"))
	Check(err)
	_, err = f.Read(privIn)
	Check(err)

	// Open and read the public key file
	f, err = os.Open(filepath.Join("..", "server", "server_public.key"))
	Check(err)
	_, err = f.Read(pubIn)
	Check(err)

	// Import the keys from PEM strings
	priv_key, _ = ParseRsaPrivateKeyFromPemStr(string(privIn))
	pub_key, _ = ParseRsaPublicKeyFromPemStr(string(pubIn))

	return
}

// ParseRsaPrivateKeyFromPemStr parses an RSA private key from a PEM-encoded string
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

// ParseRsaPublicKeyFromPemStr parses an RSA public key from a PEM-encoded string
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
