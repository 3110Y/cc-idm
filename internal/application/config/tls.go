package config

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

type TLS struct {
	Key *ecdsa.PrivateKey
}

var privateKey *ecdsa.PrivateKey

func NewTLS() (*TLS, error) {
	if privateKey == nil {
		envKey := os.Getenv("TLS_KEY")
		envKey = strings.Replace(envKey, "\\n", "\n", -1)
		envKeyByte := []byte(envKey)
		block, _ := pem.Decode(envKeyByte)
		if block == nil {
			return nil, errors.New("error decoding PEM block")
		}
		pk, err := x509.ParseECPrivateKey(block.Bytes)
		privateKey = pk
		if err != nil {
			return nil, errors.New(fmt.Sprintf("error when retrieving the private key: %s", err))
		}
	}
	return &TLS{
		Key: privateKey,
	}, nil
}
