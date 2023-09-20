package epic

import (
	"bytes"
	bzip2std "compress/bzip2"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/dsnet/compress/bzip2"
)

// Note: we use two bzip2 libraries.
// The std library compress/bzip2 has decompression implemented but not compression.
// Dsnet's bzip2 library has both compression and decompression implemented, but only compression
// worked when tested.

// This file provides the helper functions needed to do encoding, compression, and encryption.

const (
    aesKeyLen    = 32
    aesNonceSize = 12
)

// Base64Encode encodes an input byte array into a base64 string.
// Args:
//
//	input: the input buffer to encode
//
// Returns base64 encoded string
func Base64Encode(input []byte) string {
    return base64.StdEncoding.EncodeToString(input)
}

// Base64Decode decodes a base64 string.
// Args:
//
//	input: the input string to decode
//
// Returns the decoded input and any errors received
func Base64Decode(input string) ([]byte, error) {
    return base64.StdEncoding.DecodeString(input)
}

// Bzip2Compress compresses an input with bzip2.
// Args:
//
//	input: the input that should be compressed
//
// Returns the compressed input and any errors received
func Bzip2Compress(input []byte) ([]byte, error) {
    var bzip2Output bytes.Buffer
    var bzipConfig = bzip2.WriterConfig{ Level: 9 }
    bzip2Writer, err := bzip2.NewWriter(&bzip2Output, &bzipConfig)
    if err != nil {
        return []byte{}, errors.New(fmt.Sprintf("Failed to create bzip2 writer: %s", err.Error()))
    }
    _, err = bzip2Writer.Write(input)
    if err != nil {
        return []byte{}, errors.New(fmt.Sprintf("Cannot compress with bzip2: %s", err.Error()))
    }
    err = bzip2Writer.Close()
    if err != nil {
        return []byte{}, errors.New(fmt.Sprintf("Error closing bzip2 writer: %s", err.Error()))
    }
    return bzip2Output.Bytes(), nil
}

// Bzip2Decompress decompresses an input with bzip2.
// Args:
//
//	input: the input that should be decompressed
//
// Returns the decompressed input and any errors received
func Bzip2Decompress(input []byte) ([]byte, error) {
    byteReader := bytes.NewReader(input)
    outputBuffer := new(bytes.Buffer)
    _, err := outputBuffer.ReadFrom(bzip2std.NewReader(byteReader))
    if err != nil {
        return []byte{}, err
    }
    return outputBuffer.Bytes(), nil
}

// AesEncrypt encrypts an input with AES256-CBC and a generated key. https://pkg.go.dev/crypto/cipher#NewCBCEncrypter
// Args:
//
//	input: the input that should be encrypted
//
// Returns the encrypted input prepended with the 16 byte iv, encryption key, and any errors received
func AesEncrypt(input []byte) ([]byte, []byte, error) {
    // pad plaintext
    plaintext := PKCS5Padding(input, aes.BlockSize, len(input))

    // generate AES-256 key (32 bytes)
    key := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, key); err != nil {
        return []byte{}, []byte{}, err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return []byte{}, []byte{}, err
    }

    // generate iv and prepend to ciphertext
    ivCiphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ivCiphertext[:aes.BlockSize] // prepend iv to ciphertext
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return []byte{}, []byte{}, err
    }
    copy(ivCiphertext[:aes.BlockSize], iv)

    // encrypt plaintext
    mode := cipher.NewCBCEncrypter(block, iv)
    mode.CryptBlocks(ivCiphertext[aes.BlockSize:], plaintext) // start after the iv

    return ivCiphertext, key, nil
}

// AesDecrypt decrypts an input with AES256-CBC. https://pkg.go.dev/crypto/cipher#NewCBCDecrypter
// Args:
//
//	key: the key that should be used for decryption
//	input: the iv prepended to ciphertext that should be decrypted
//
// Returns the decrypted ciphertext and any errors received
func AesDecrypt(key []byte, input []byte) ([]byte, error) {
    iv := input[:aes.BlockSize]
    ciphertext := input[aes.BlockSize:]

    block, err := aes.NewCipher(key)
    if err != nil {
        return []byte{}, err
    }

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(ciphertext, ciphertext)
    return PKCS5Unpadding(ciphertext), nil

}

// PKCS5Padding adds padding to ensure the plaintext lengths are a multiple of the block size
// https://gist.github.com/awadhwana/9c95377beba61293390c5fd23a3bb1df?permalink_comment_id=4230709#gistcomment-4230709
func PKCS5Padding(ciphertext []byte, blockSize int, after int) []byte {
    padding := (blockSize - len(ciphertext)%blockSize)
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(ciphertext, padtext...)
}

// PKCS5Unpadding removes padding that was added to ensure the plaintext lengths were a multiple of the block size
// https://gist.github.com/awadhwana/9c95377beba61293390c5fd23a3bb1df?permalink_comment_id=4230709#gistcomment-4230709
func PKCS5Unpadding(src []byte) []byte {
    length := len(src)
    unpadding := int(src[length-1])
    return src[:(length - unpadding)]
}

// ImportRsaPubKey imports the base64 encoded implant's RSA public key for encrypting communications
// Returns the RSA public key
func ImportRsaPubKey(publicKeyString string) (*rsa.PublicKey, error) {
    var keyData []byte
    var err error
    if publicKeyString == "" {
        keyData, err = base64.StdEncoding.DecodeString(implantPublicKey)
        if err != nil {
            return nil, err
        }
    } else {
        keyData, err = base64.StdEncoding.DecodeString(publicKeyString)
        if err != nil {
            return nil, err
        }
    }
    
    publicKey, err := x509.ParsePKCS1PublicKey(keyData)
    if err != nil {
        return nil, err
    }
    return publicKey, nil
}

// ImportRsaPrivKey imports the base64 encoded server's RSA private key for decrypting communications
func ImportRsaPrivKey(privateKeyString string) (*rsa.PrivateKey, error) {
    var keyData []byte
    var err error
    if privateKeyString == "" {
        keyData, err = base64.StdEncoding.DecodeString(serverPrivateKey)
        if err != nil {
            return nil, err
        }
    } else {
        keyData, err = base64.StdEncoding.DecodeString(privateKeyString)
        if err != nil {
            return nil, err
        }
    }
    privateKey, err := x509.ParsePKCS1PrivateKey(keyData)
    if err != nil {
        return nil, err
    }
    return privateKey, nil
}

// RsaEncrypt encrypts an input with RSA (sha256 hash function, OAEP padding, and currently 2048-bit key). https://golangdocs.com/rsa-encryption-decryption-in-golang
// Parsing keys: https://pkg.go.dev/encoding/pem#Decode, https://pkg.go.dev/crypto/x509
// Args:
//
//	input: the message to encrypt
//	key: the implant RSA public key to encrypt the message
//
// Returns the encrypted message and any errors recieved
func RsaEncrypt(input []byte, publicKey *rsa.PublicKey) ([]byte, error) {
    rng := rand.Reader

    return rsa.EncryptOAEP(sha1.New(), rng, publicKey, input, nil)
}

// RsaDecrypt decrypts an input with RSA (sha256 hash function, OAEP padding, and currently 2048-bit key). https://golangdocs.com/rsa-encryption-decryption-in-golang
// Parsing keys: https://pkg.go.dev/encoding/pem#Decode, https://pkg.go.dev/crypto/x509
// Args:
//
//	input: the ciphertext that should be decrypted
//	privateKey: the server RSA private key used to decrypt
//
// Returns the decrypted ciphertext and any errors received
func RsaDecrypt(input []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
    rng := rand.Reader

    return rsa.DecryptOAEP(sha1.New(), rng, privateKey, input, nil)
}

// Encrypt combines the calls to AES encryption and RSA encryption.
// An AES key and IV are generated for the session. The input data is encrypted
// with the AES session key and the IV is prepended to the AES encrypted data.
// The AES key is then base64 encoded and RSA encrypted using the implant's
// public key. The RSA encrypted AES key is then prepended to the encrypted
// input data.
// Args:
//
//  input: the data that should be encrypted
//  publicKey: the implant RSA public key used to encrypt
//
// Returns the RSA encrypted AES key, AES IV, and AES encrypted input data
func Encrypt(input []byte, publicKey *rsa.PublicKey) ([]byte, error) {
    // AES-encrypt body
    ivCiphertext, aesKey, err := AesEncrypt(input)
    if err != nil {
        return nil, err
    }

    // base64 encode the AES key
    b64AesKey := Base64Encode(aesKey)
    b64AesKeyBytes := []byte(b64AesKey)

    // RSA-encrypt AES key
    rsaAesKey, err := RsaEncrypt(b64AesKeyBytes, publicKey)
    if err != nil {
        return nil, err
    }

    // Prepend RSA-encrypted AES key to AES-encrypted body
    ret := append(rsaAesKey, ivCiphertext...)

    return ret, err

}

// Decrypt combines the calls toe AES decryption and RSA decryption.
// Args:
//
//  input: the data that should be decrypted
//  privateKey: the server RSA private key used to derypt
//
// Returns the decrypted data
func Decrypt(input []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
    // Pull out RSA-encrypted(AES key)
    rsaAesKey := make([]byte, 256)
    if len(input) < 256 {
        return nil, errors.New("Provided input is not minimum 256 bytes for extracting RSA-encrypted AES key")
    }
    copy(rsaAesKey, input[0:256])

    // RSA-decrypt(AES key)
    b64AesKey, err := RsaDecrypt(rsaAesKey, privateKey)
    if err != nil {
        return nil, err
    }

    // base64 decode the AES key
    b64AesKeyStr := string(b64AesKey)
    aesKey, err := Base64Decode(b64AesKeyStr)
    if err != nil {
        return nil, err
    }

    // AES-decrypt(body)
    ret, err := AesDecrypt(aesKey, input[256:])
    if err != nil {
        return nil, err
    }

    return ret, nil
}
