package carbon

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	
	"golang.org/x/crypto/cast5"
	
	"attackevals.mitre-engenuity.org/control_server/logger"
)

const (
	rsaPublicKeyDerB64 = "MIIBCAKCAQEAxcvv98NsuX1Fuff9LDyV5fpp/MAbPvIYiMyoups9uhJz7v0E4MRCZQoM6w49rjmMTgsps3TJe8IR/6waEOTzevVBmma2LFd6Q+wlOnfdHFLa2YjCUyY1fvBP+7poc9U/hjf4mLs9hGih8wBUEPZtNYerA/aZM2bwpH7JjTXdQmCZ0Y7WalNn3me+Y9mEXQS16+uxXX3uEjB0zg9J+18H5dDRe40O91pLToAGKw/+s3bs9wuvLw0sArUQusC0T/msUOAawPgUDDv008w1PJblHRnDq6u1R1WD73VjDo1cGd/OfZH166JkVLiOXsrcgYL820cr1BuQuBoMthER5QUs7wIBEQ=="
)

var (
	mainCast128Key = []byte{0xf2, 0xd4, 0x56, 0x08, 0x91, 0xbd, 0x94, 0x86, 0x92, 0xc2, 0x8d, 0x2a, 0x93, 0x91, 0xe7, 0xd9}
)

func importRsaPubKey() (*rsa.PublicKey, error) {
	keyData, err := base64.StdEncoding.DecodeString(rsaPublicKeyDerB64)
        if err != nil {
                return nil, err
        }
        return x509.ParsePKCS1PublicKey(keyData)
}

func pkcs5Padding(blob []byte, blockSize int) []byte {
	paddingSize := blockSize - (len(blob) % blockSize)
	padded := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize) // padded bytes contain padding size
	return append(blob, padded...)
}

func pkcs5RemovePadding(blob []byte) []byte {
	paddingSize := int(blob[len(blob) - 1]) // padded bytes contain the padding size
	return blob[:len(blob) - paddingSize]
}

func cbcEncrypt(castCipher *cast5.Cipher, plaintext, iv []byte) ([]byte, error) {
	if len(iv) != cast5.BlockSize {
		return nil, errors.New("Invalid IV length. Must be CAST128 block length")
	}
	ivPlaintext := append(iv, plaintext...)
	ivPlaintextPadded := pkcs5Padding(ivPlaintext, cast5.BlockSize)
	ciphertext := make([]byte, 0)
	ciphertext = append(ciphertext, ivPlaintextPadded[:cast5.BlockSize]...) // prepend IV to ciphertext
	dstBlock := make([]byte, cast5.BlockSize)
	numIterations := (len(ivPlaintextPadded) / cast5.BlockSize) - 1
	
	// Ci = Enc(Pi XOR Ci-1), where C0 = IV
	for i := 1; i <= numIterations; i++ {
		toXOR := ciphertext[(i-1)*cast5.BlockSize:i*cast5.BlockSize]
		currBlock := ivPlaintextPadded[i*cast5.BlockSize: (i+1)*cast5.BlockSize]
		for j, b := range toXOR {
			currBlock[j] ^= b
		}
		castCipher.Encrypt(dstBlock, currBlock)
		ciphertext = append(ciphertext, dstBlock...)
	}
	return ciphertext, nil
}

// ivCiphertext must be IV + ciphertext
func cbcDecrypt(castCipher *cast5.Cipher, ivCiphertext []byte) ([]byte, error) {
	if len(ivCiphertext) % cast5.BlockSize != 0 {
		return nil, errors.New("Ciphertext length not a multiple of cast128 block length.")
	}
	
	plaintext := make([]byte, 0)
	dstBlock := make([]byte, cast5.BlockSize)
	numIterations := (len(ivCiphertext) / cast5.BlockSize) - 1 // N ciphertext blocks + 1 IV block = N plaintext blocks
	
	// Pi = Dec(Ci) XOR Ci-1 where C0 = IV
	for i := 1; i <= numIterations; i++ {
		toXOR := ivCiphertext[(i-1)*cast5.BlockSize:i*cast5.BlockSize]
		currBlock := ivCiphertext[i*cast5.BlockSize: (i+1)*cast5.BlockSize]
		castCipher.Decrypt(dstBlock, currBlock)
		for j, b := range toXOR {
			dstBlock[j] ^= b
		}
		plaintext = append(plaintext, dstBlock...)
	}
	return pkcs5RemovePadding(plaintext), nil
}

// Returns IV + ciphertext
func (c *CarbonHttpHandler) cast5CbcEncrypt(key, plaintext []byte) ([]byte, error) {
	// generate IV
	iv := make([]byte, cast5.BlockSize)
	_, err := c.genRandBytesFn(iv)
	if err != nil {
		return nil, err
	}
	
	// Encrypt task bytes using CAST128
	castCipher, err := cast5.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cbcEncrypt(castCipher, plaintext, iv)
}

// assumes ciphertext includes prepended IV
func (c *CarbonHttpHandler) cast5CbcDecrypt(key, ciphertext []byte) ([]byte, error) {
	castCipher, err := cast5.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cbcDecrypt(castCipher, ciphertext)
}


func (c *CarbonHttpHandler) encodeTaskResponse(taskBytes []byte) (string, error) {
	if !c.useEncryption {
		return base64.StdEncoding.EncodeToString(taskBytes), nil
	}
	
	// generate random CAST128 key
	castKey := make([]byte, cast5.KeySize)
	_, err := c.genRandBytesFn(castKey)
	if err != nil {
		return "", err
	}
	logger.Debug(fmt.Sprintf("Generated random CAST128 key: %s", hex.EncodeToString(castKey)))
	
	taskCiphertext, err := c.cast5CbcEncrypt(castKey, taskBytes)
	if err != nil {
		return "", err
	}
	
	// base64-encode and encrypt cast128 key using RSA and prepend to ciphertext
	encodedKeyBytes := []byte(base64.StdEncoding.EncodeToString(castKey))
	rng := rand.Reader
	keyCiphertext, err := rsa.EncryptOAEP(sha1.New(), rng, c.rsaPublicKey, encodedKeyBytes, nil)
	if err != nil {
		return "", err
	}
	combined := append(keyCiphertext, taskCiphertext...)
	
	// return base64-encoded blob of whole thing
	return base64.StdEncoding.EncodeToString(combined), nil
}

func (c *CarbonHttpHandler) decodePostResponse(data []byte) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(string(data))

	if err != nil {
		return []byte{}, err
	}

	decrypted, err := c.cast5CbcDecrypt(mainCast128Key, decoded)
	if err != nil {
		return []byte{}, err
	}

	return decrypted, nil
}
