package jsoncrypto

import (
	"crypto/sha256"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	b64 "encoding/base64"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"fmt"
)

// GenerateDerivedKey creates a derived key from the given key and salt
func GenerateDerivedKey(key []byte, salt []byte) []byte {
	return pbkdf2.Key(key, salt, 1000, 32, sha256.New)
}

// AesEncrypt encrypts the plaintext using AES-GCM
func AesEncrypt(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return b64.StdEncoding.EncodeToString(ciphertext), nil
}

// AesDecrypt decrypts AES-GCM encrypted data
func AesDecrypt(ciphertext string, key []byte) (string, error) {
	base64DecodedCipher, err := b64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(base64DecodedCipher) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, cipherBytes := base64DecodedCipher[:nonceSize], base64DecodedCipher[nonceSize:]
	plaintextBytes, err := aesGCM.Open(nil, nonce, cipherBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintextBytes), nil
}

// ConvertToAES encrypts JSON and returns AES string
func ConvertToAES(inputJSON map[string]interface{}, key []byte, salt []byte) ([]byte, []byte, string, []byte, error) {
	JSONbytes, err := json.Marshal(inputJSON)
	if err != nil {
		return nil, nil, "", nil, err
	}

	base64Encoded := b64.StdEncoding.EncodeToString(JSONbytes)
	derivedKey := GenerateDerivedKey(key, salt)

	aesString, err := AesEncrypt(base64Encoded, derivedKey)
	if err != nil {
		return nil, nil, "", nil, err
	}

	sha256Key := sha256.Sum256(key)
	return derivedKey, salt, aesString, sha256Key[:], nil
}

// ConvertFromAES decrypts an AES string back into JSON
func ConvertFromAES(aesString string, key []byte, salt []byte) (map[string]interface{}, error) {
	derivedKey := GenerateDerivedKey(key, salt)
	decryptedBase64, err := AesDecrypt(aesString, derivedKey)
	if err != nil {
		return nil, err
	}

	decodedBytes, err := b64.StdEncoding.DecodeString(decryptedBase64)
	if err != nil {
		return nil, err
	}

	var vault map[string]interface{}
	err = json.Unmarshal(decodedBytes, &vault)
	if err != nil {
		return nil, err
	}

	return vault, nil
}
