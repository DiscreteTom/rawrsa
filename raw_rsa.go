package rawrsa

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"os"
)

// RawRsa inherit rsa.PrivateKey and provide RawEncrypt, RawDecrypt, Save and Load methods.
type RawRsa struct {
	rsa.PrivateKey
}

// NewRawRsa will generate a key pair.
// If you don't know which random to use, use rand.Reader.
func NewRawRsa(random io.Reader, bits int) (*RawRsa, error) {
	sk, err := rsa.GenerateKey(random, bits)
	if err != nil {
		return nil, err
	}
	return &RawRsa{*sk}, nil
}

// RawEncrypt will encrypt the given secretMsg.
func (rr *RawRsa) RawEncrypt(secretMsg *big.Int) (ciphertext *big.Int) {
	ciphertext = &big.Int{}
	// c = m**E % N
	ciphertext.Exp(secretMsg, new(big.Int).SetInt64(int64(rr.E)), rr.N)
	return
}

// RawDecrypt will decrypt the given ciphertext.
func (rr *RawRsa) RawDecrypt(ciphertext *big.Int) (secretMsg *big.Int) {
	secretMsg = &big.Int{}
	// m = c**D % N
	secretMsg.Exp(ciphertext, rr.D, rr.N)
	return
}

// Save will save the rsa key pair to the given file.
func (rr *RawRsa) Save(fileName string) error {
	// ref: https://medium.com/@Raulgzm/export-import-pem-files-in-go-67614624adc7

	// create private key file
	pemPrivateFile, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer pemPrivateFile.Close()
	pemPrivateFile.Truncate(0) // clear file before write

	// encode & save
	var pemPrivateBlock = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(&rr.PrivateKey),
	}
	return pem.Encode(pemPrivateFile, pemPrivateBlock)
}

// Load will load the rsa key pair from the given file.
func Load(fileName string) (*RawRsa, error) {
	// ref: https://medium.com/@Raulgzm/export-import-pem-files-in-go-67614624adc7

	// open the file
	privateKeyFile, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer privateKeyFile.Close()

	// load file
	pemfileinfo, err := privateKeyFile.Stat()
	if err != nil {
		return nil, err
	}
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	if err != nil {
		return nil, err
	}

	// decode
	data, _ := pem.Decode([]byte(pembytes))
	privateKeyImported, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	if err != nil {
		return nil, err
	}

	// assign private key
	return &RawRsa{*privateKeyImported}, nil
}
