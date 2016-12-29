package shadysocks

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"strings"

	"github.com/uber-go/zap"
)

type crypto struct {
	keySize   int
	key       []byte
	blockSize int
	block     cipher.Block

	newEncrypter func(cipher.Block, []byte) cipher.Stream
	newDecrypter func(cipher.Block, []byte) cipher.Stream
	encrypter    cipher.Stream
	decrypter    cipher.Stream
}

func newCrypto(method, password string) (*crypto, error) {
	var err error
	c := new(crypto)
	c.blockSize = aes.BlockSize

	fields := strings.Split(strings.ToLower(method), "-")
	if fields[0] != "aes" {
		logger.Panic("Unknown encryption", zap.String("method", method))
	}

	switch fields[1] {
	case "128":
		c.keySize = 16
	case "192":
		c.keySize = 24
	case "256":
		c.keySize = 32
	default:
		logger.Panic("Unknown key size", zap.String("method", method))
	}

	switch fields[2] {
	case "cfb":
		c.newEncrypter = cipher.NewCFBEncrypter
		c.newDecrypter = cipher.NewCFBDecrypter
	case "ctr":
		c.newEncrypter = cipher.NewCTR
		c.newDecrypter = cipher.NewCTR
	case "ofb":
		c.newEncrypter = cipher.NewOFB
		c.newDecrypter = cipher.NewOFB
	default:
		logger.Panic("Unknown cipher mode", zap.String("method", method))
	}

	pb := []byte(password)
	m := make([][]byte, 0)
	i := 0
	for len(bytes.Join(m, []byte{})) < c.keySize+c.blockSize {
		data := pb
		if i > 0 {
			data = append(m[i-1], pb...)
		}
		digest := md5.Sum(data)
		m = append(m, digest[:])
		i++
	}
	ms := bytes.Join(m, []byte{})
	c.key = ms[:c.keySize]
	c.block, err = aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	return c, nil
}
