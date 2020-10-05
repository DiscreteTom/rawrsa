package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/DiscreteTom/rawrsa"
)

func main() {
	// Init a 2048 bit rsa key pair.
	rr, err := rawrsa.NewRawRsa(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Encrypt "hello world" and decrypt it.
	ciphertext := rr.RawEncrypt(new(big.Int).SetBytes([]byte("hello world")))
	decrypted := rr.RawDecrypt(ciphertext)
	fmt.Println(string(decrypted.Bytes())) // => "hello world"

	// Save key pair to a file.
	if err = rr.Save("my-key.pem"); err != nil {
		panic(err)
	}

	// Load key pair back.
	rr2, err := rawrsa.Load("my-key.pem")
	if err != nil {
		panic(err)
	}

	// Compare new key pair with old key pair.
	fmt.Println(rr.E == rr2.E)
	fmt.Println(rr.D.Cmp(rr2.D))
	fmt.Println(rr.N.Cmp(rr2.N))
}
