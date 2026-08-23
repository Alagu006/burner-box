package handlers

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
)

const proofKeyFile = "data/proof_key.json"

type persistedProofKey struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

var (
	proofPublicKey  ed25519.PublicKey
	proofPrivateKey ed25519.PrivateKey
	proofKeyLoaded  bool
)

// LoadOrGenerateProofKey loads or generates the Ed25519 key for proof-of-submission.
func LoadOrGenerateProofKey() {
	// Try loading from file
	if data, err := os.ReadFile(proofKeyFile); err == nil {
		var pk persistedProofKey
		if json.Unmarshal(data, &pk) == nil {
			privBytes, err1 := base64.StdEncoding.DecodeString(pk.PrivateKey)
			pubBytes, err2 := base64.StdEncoding.DecodeString(pk.PublicKey)
			if err1 == nil && err2 == nil {
				proofPrivateKey = ed25519.PrivateKey(privBytes)
				proofPublicKey = ed25519.PublicKey(pubBytes)
				proofKeyLoaded = true
				log.Println("PROOF_KEY: Loaded existing Ed25519 key")
				return
			}
		}
	}

	// Generate new keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Printf("PROOF_KEY: Failed to generate Ed25519 key: %v — proof of submission disabled", err)
		return
	}

	proofPublicKey = pub
	proofPrivateKey = priv
	proofKeyLoaded = true

	// Persist to file
	os.MkdirAll("data", 0700)
	pk := persistedProofKey{
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
	}
	if data, err := json.Marshal(pk); err == nil {
		os.WriteFile(proofKeyFile, data, 0600)
	}

	log.Println("PROOF_KEY: Generated and persisted new Ed25519 key")
}

type ProofOfSubmission struct {
	SubmissionID string `json:"submission_id"`
	Hash         string `json:"hash"`
	Signature    string `json:"signature"`
	Timestamp    string `json:"timestamp"`
	KeyFingerprint string `json:"key_fingerprint"`
}

// GenerateProofOfSubmission signs the SHA-256 hash of the encrypted payload.
// Returns a signed receipt the submitter can download.
func GenerateProofOfSubmission(submissionID, encryptedPayload string) *ProofOfSubmission {
	if !proofKeyLoaded || proofPrivateKey == nil {
		return nil
	}

	hash := sha256.Sum256([]byte(encryptedPayload))
	hashHex := fmt.Sprintf("%x", hash)

	signature := ed25519.Sign(proofPrivateKey, hash[:])
	sigBase64 := base64.StdEncoding.EncodeToString(signature)

	// Fingerprint: first 8 bytes of SHA-256 of the public key
	fingerprintHash := sha256.Sum256(proofPublicKey)
	fingerprint := fmt.Sprintf("%x", fingerprintHash[:8])

	return &ProofOfSubmission{
		SubmissionID:   submissionID,
		Hash:           hashHex,
		Signature:      sigBase64,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		KeyFingerprint: fingerprint,
	}
}

// GetProofPublicKey returns the server's Ed25519 public key (for independent verification).
func GetProofPublicKey(c *fiber.Ctx) error {
	if !proofKeyLoaded {
		return c.Status(503).JSON(fiber.Map{
			"error": "Proof of submission not available",
		})
	}

	fingerprintHash := sha256.Sum256(proofPublicKey)
	fingerprint := fmt.Sprintf("%x", fingerprintHash[:8])

	return c.JSON(fiber.Map{
		"public_key":  base64.StdEncoding.EncodeToString(proofPublicKey),
		"fingerprint": fingerprint,
	})
}
