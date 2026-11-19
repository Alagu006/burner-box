package handlers

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"testing"
	"time"

	"burner-box-backend/internal/config"
	"burner-box-backend/internal/crypto"

	"github.com/gofiber/fiber/v2"
)

var (
	registryInitMu  sync.Mutex
	proofPublicKey  ed25519.PublicKey
	proofPrivateKey ed25519.PrivateKey
	proofKeyLoaded  bool
)

// InitProofSystem initializes the proof-of-submission signing registry from configuration.
// In production-like environments (production, staging, preview, cloud platforms), requires PROOF_SIGNING_PRIVATE_KEY.
// In development, falls back to an ephemeral in-memory Ed25519 key (zero disk writes).
// Guarantees atomic publication: builds and validates the candidate registry locally;
// crypto.GlobalRegistry and package globals are only updated if ALL validation checks succeed.
func InitProofSystem(cfg *config.Config) error {
	registryInitMu.Lock()
	defer registryInitMu.Unlock()

	isProd := false
	if cfg != nil && config.IsProductionLikeEnvironment(cfg.Environment) {
		isProd = true
	}

	// 1. Construct candidate registry locally; built-in legacy compromised key is registered inside constructor
	candidate := crypto.NewSigningRegistry(isProd)

	// 2. Configure active signing key
	if cfg != nil && cfg.ProofSigningPrivateKey != "" {
		priv, pub, err := crypto.ParseEd25519PrivateKey(cfg.ProofSigningPrivateKey)
		if err != nil {
			return fmt.Errorf("failed to parse proof signing private key: %w", err)
		}
		keyID := cfg.ProofSigningKeyID
		if keyID == "" {
			keyID = "bb-key-" + crypto.ComputeFingerprint(pub)
		}
		if err := candidate.SetActiveKey(keyID, priv, time.Now().UTC()); err != nil {
			return fmt.Errorf("failed to set active signing key: %w", err)
		}
		log.Printf("PROOF_KEY: Initialized production signing key ID=%s (fingerprint=%s)", keyID, crypto.ComputeFingerprint(pub))
	} else {
		if isProd {
			return fmt.Errorf("cannot initialize proof system: PROOF_SIGNING_PRIVATE_KEY is missing in production-like environment")
		}
		if err := candidate.InitDevEphemeralKey(); err != nil {
			return fmt.Errorf("failed to generate dev ephemeral key: %w", err)
		}
		log.Println("PROOF_KEY: Initialized ephemeral in-memory Ed25519 key (dev mode, zero disk writes)")
	}

	// 3. Register historical public verification keys if provided in config
	if cfg != nil && cfg.ProofHistoricalPublicKeys != "" {
		var historicalKeys []crypto.VerificationKey
		if err := json.Unmarshal([]byte(cfg.ProofHistoricalPublicKeys), &historicalKeys); err != nil {
			if isProd {
				return fmt.Errorf("failed to parse PROOF_HISTORICAL_PUBLIC_KEYS JSON in production-like environment: %w", err)
			}
			log.Printf("PROOF_KEY: Warning: Failed to parse PROOF_HISTORICAL_PUBLIC_KEYS JSON: %v", err)
		} else {
			for i := range historicalKeys {
				if regErr := candidate.RegisterHistoricalKey(&historicalKeys[i]); regErr != nil {
					if isProd {
						return fmt.Errorf("failed to register historical key %s in production-like environment: %w", historicalKeys[i].KeyID, regErr)
					}
					log.Printf("PROOF_KEY: Warning: Failed to register historical key %s: %v", historicalKeys[i].KeyID, regErr)
				}
			}
		}
	}

	// 4. ATOMIC PUBLICATION: Only upon complete success is candidate published as GlobalRegistry
	crypto.GlobalRegistry = candidate
	syncPackageGlobals()
	return nil
}

// InitProofSystemForTest initializes an in-memory test signing key with zero disk writes.
func InitProofSystemForTest(t *testing.T) {
	t.Helper()
	registryInitMu.Lock()
	defer registryInitMu.Unlock()

	candidate := crypto.NewSigningRegistry(false)
	_, _, err := candidate.InitTestKey("bb-test-key")
	if err != nil {
		t.Fatalf("Failed to initialize test signing key: %v", err)
	}
	crypto.GlobalRegistry = candidate
	syncPackageGlobals()
}

func syncPackageGlobals() {
	_, priv, pub, _, err := crypto.GlobalRegistry.GetActiveKey()
	if err == nil && priv != nil && pub != nil {
		proofPrivateKey = priv
		proofPublicKey = pub
		proofKeyLoaded = true
	} else {
		proofPrivateKey = nil
		proofPublicKey = nil
		proofKeyLoaded = false
	}
}

// LoadOrGenerateProofKey is maintained for backward-compatibility with existing boot paths.
// It initializes the in-memory signing system using config.AppConfig without writing any files to disk.
func LoadOrGenerateProofKey() {
	if err := InitProofSystem(config.AppConfig); err != nil {
		log.Printf("PROOF_KEY: Error during initialization: %v", err)
	}
}

type ProofOfSubmission struct {
	SubmissionID           string `json:"submission_id"`
	Hash                   string `json:"hash"`
	Signature              string `json:"signature"`
	Timestamp              string `json:"timestamp"`
	KeyID                  string `json:"key_id,omitempty"`
	KeyFingerprint         string `json:"key_fingerprint"`
	ServerPublicKey        string `json:"server_public_key,omitempty"`
	TrustStatus            string `json:"trust_status,omitempty"`
	BatchID                string `json:"batch_id,omitempty"`
	BatchNumber            int    `json:"batch_number,omitempty"`
	LeafIndex              int    `json:"leaf_index,omitempty"`
	LeafHash               string `json:"leaf_hash,omitempty"`
	MerkleStatus           string `json:"merkle_status,omitempty"`
	PortalSlug             string `json:"portal_slug,omitempty"`
	InclusionProofEndpoint string `json:"inclusion_proof_endpoint,omitempty"`
	PublishedRootsEndpoint string `json:"published_roots_endpoint,omitempty"`
}

// GenerateProofOfSubmission signs the SHA-256 hash of the encrypted payload using the active key from the registry.
// Returns a signed receipt the submitter can download.
func GenerateProofOfSubmission(submissionID, encryptedPayload string) *ProofOfSubmission {
	hash := sha256.Sum256([]byte(encryptedPayload))
	hashHex := fmt.Sprintf("%x", hash)

	sig, keyID, fingerprint, pub, err := crypto.GlobalRegistry.Sign(hash[:])
	if err != nil || sig == nil {
		return nil
	}

	sigBase64 := base64.StdEncoding.EncodeToString(sig)

	return &ProofOfSubmission{
		SubmissionID:    submissionID,
		Hash:            hashHex,
		Signature:       sigBase64,
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		KeyID:           keyID,
		KeyFingerprint:  fingerprint,
		ServerPublicKey: base64.StdEncoding.EncodeToString(pub),
		TrustStatus:     string(crypto.TrustStatusTrusted),
	}
}

// GetProofPublicKey returns the server's active Ed25519 public key (for independent verification).
// 100% backward compatible with existing frontend clients expecting { public_key, fingerprint }.
func GetProofPublicKey(c *fiber.Ctx) error {
	keyID, _, pub, fp, err := crypto.GlobalRegistry.GetActiveKey()
	if err != nil || pub == nil {
		return c.Status(503).JSON(fiber.Map{
			"error": "Proof of submission not available",
		})
	}

	return c.JSON(fiber.Map{
		"key_id":       keyID,
		"public_key":   base64.StdEncoding.EncodeToString(pub),
		"fingerprint":  fp,
		"trust_status": string(crypto.TrustStatusTrusted),
	})
}

// GetAllProofKeys returns all registered public verification keys (active and historical).
// Public information only; zero private key data is exposed.
func GetAllProofKeys(c *fiber.Ctx) error {
	keys := crypto.GlobalRegistry.GetAllKeys()
	keyID, _, _, _, _ := crypto.GlobalRegistry.GetActiveKey()

	return c.JSON(fiber.Map{
		"active_key_id": keyID,
		"total_keys":    len(keys),
		"keys":          keys,
	})
}

// GetProofKeyByIdentifier returns public verification metadata for a specific KeyID or Fingerprint.
func GetProofKeyByIdentifier(c *fiber.Ctx) error {
	identifier := c.Params("id")
	if identifier == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Key identifier or fingerprint required"})
	}

	vk, _ := crypto.GlobalRegistry.LookupKey(identifier)
	if vk == nil {
		return c.Status(404).JSON(fiber.Map{
			"error":        "Key not found in verification registry",
			"identifier":   identifier,
			"trust_status": string(crypto.TrustStatusUnknown),
		})
	}

	return c.JSON(fiber.Map{
		"key_id":          vk.KeyID,
		"key_fingerprint": vk.Fingerprint,
		"public_key":      vk.PublicKeyB64,
		"role":            string(vk.Role),
		"trust_status":    string(vk.TrustStatus),
		"valid_from":      vk.ValidFrom,
		"retired_at":      vk.RetiredAt,
		"description":     vk.Description,
	})
}
