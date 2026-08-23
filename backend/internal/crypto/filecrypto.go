package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

// derivePerFileKey derives a 32-byte AES key for a specific file using
// HMAC-SHA256 over the master key and a random per-file nonce.
func derivePerFileKey(masterKey, fileNonce []byte) []byte {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write(fileNonce)
	mac.Write([]byte("burnerbox-file-key"))
	return mac.Sum(nil)[:32]
}

// EncryptFile encrypts plaintext using AES-256-GCM with a per-file key
// derived from masterKey + a random nonce.
//
// Returns (fileNonce, ciphertext, error) where:
//   - fileNonce is base64-encoded and should be stored in the DB
//   - ciphertext is nonce || encrypted bytes, written to disk
//
// This protects raw disk compromise but is NOT a substitute for real
// client-side E2EE, since the server holds masterKey and can decrypt.
func EncryptFile(masterKey, plaintext []byte) (fileNonce string, ciphertext []byte, err error) {
	// Generate random 32-byte nonce for key derivation
	nonceBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return "", nil, err
	}

	perFileKey := derivePerFileKey(masterKey, nonceBytes)

	block, err := aes.NewCipher(perFileKey)
	if err != nil {
		return "", nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, err
	}

	// Random 12-byte nonce for AES-GCM
	gcmNonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, gcmNonce); err != nil {
		return "", nil, err
	}

	encrypted := aesGCM.Seal(gcmNonce, gcmNonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(nonceBytes), encrypted, nil
}

// DecryptFile decrypts AES-256-GCM encrypted data using the per-file key
// derived from masterKey and fileNonce (base64-encoded, from the DB).
func DecryptFile(masterKey []byte, fileNonce string, ciphertext []byte) ([]byte, error) {
	nonceBytes, err := base64.StdEncoding.DecodeString(fileNonce)
	if err != nil {
		return nil, err
	}

	perFileKey := derivePerFileKey(masterKey, nonceBytes)

	block, err := aes.NewCipher(perFileKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	gcmNonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, gcmNonce, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
