package encrypt

import "crypto/rc4"

// CryptRC4 XOR encrypts/decrypts data using a symmetric key
func CryptRC4(key []byte, srcData []byte) ([]byte, error) {

	rc4Cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dstData := make([]byte, len(srcData))
	rc4Cipher.XORKeyStream(dstData, srcData)
	return dstData, err
}
