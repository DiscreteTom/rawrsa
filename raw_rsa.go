package rawrsa

import (
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
func NewRawRsa(random io.Reader, bits int) (rr *RawRsa, err error) {
	var sk *rsa.PrivateKey
	sk, err = rsa.GenerateKey(random, bits)
	if err != nil {
		return nil, err
	}
	rr = &RawRsa{*sk}
	return
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

// Save will save the rsa key pair to files.
func (rr *RawRsa) Save(fileName string) (err error) {
	// create private key file
	var pemPrivateFile *os.File
	pemPrivateFile, err = os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer pemPrivateFile.Close()

	var pemPrivateBlock = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(&rr.PrivateKey),
	}

	err = pem.Encode(pemPrivateFile, pemPrivateBlock)
	if err != nil {
		return err
	}
	return nil
}
