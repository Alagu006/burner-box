package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"image/png"
	"io"

	"github.com/pquerna/otp/totp"
)

// GenerateTOTPSecret creates a new TOTP secret for an organization
func GenerateTOTPSecret(orgName, email string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "BurnerBox",
		AccountName: email,
		SecretSize:  20,
	})
	if err != nil {
		return "", "", err
	}

	// Generate QR code as PNG image
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return "", "", err
	}

	png.Encode(&buf, img)
	qrBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	return key.Secret(), "data:image/png;base64," + qrBase64, nil
}

// ValidateTOTPCode checks if a TOTP code is valid
func ValidateTOTPCode(secret, code string) bool {
	valid := totp.Validate(code, secret)
	return valid
}

// EncryptTOTPSecret encrypts the TOTP secret using AES-256-GCM.
// Output format: base64(nonce || ciphertext)
func EncryptTOTPSecret(secret string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes.NewCipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("cipher.NewGCM: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("reading nonce: %w", err)
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(secret), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptTOTPSecret decrypts an AES-256-GCM encrypted TOTP secret.
// Input format: base64(nonce || ciphertext)
func DecryptTOTPSecret(encrypted string, key []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes.NewCipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("cipher.NewGCM: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(raw) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("AES-GCM decrypt: %w", err)
	}

	return string(plaintext), nil
}