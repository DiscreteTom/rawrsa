# rawrsa

This repository is a golang implementation of the textbook RSA encryption.

**DO NOT USE THIS REPO IN PRODUCTION ENVIRONMENTS!**

## Installation

```
go get github.com/DiscreteTom/rawrsa
```

## Usage

See the [example code](https://github.com/DiscreteTom/rawrsa/blob/master/examples/helloworld.go).

Structures:

```go
type RawRsa struct {
	rsa.PrivateKey
}
```

APIs:

```go
func NewRawRsa(random io.Reader, bits int) (*RawRsa, error)
func (rr *RawRsa) RawEncrypt(secretMsg *big.Int) (ciphertext *big.Int)
func (rr *RawRsa) RawDecrypt(ciphertext *big.Int) (secretMsg *big.Int)
func (rr *RawRsa) Save(fileName string) error
func Load(fileName string) (*RawRsa, error)
```