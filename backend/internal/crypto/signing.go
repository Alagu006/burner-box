package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// TrustStatus represents the systemic trust classification of a verification key.
type TrustStatus string

const (
	TrustStatusTrusted   TrustStatus = "trusted"
	TrustStatusUntrusted TrustStatus = "untrusted"
	TrustStatusUnknown   TrustStatus = "unknown"
)

// KeyRole represents the operational lifecycle state of a signing key.
type KeyRole string

const (
	KeyRoleActive      KeyRole = "active"
	KeyRoleRetired     KeyRole = "retired"
	KeyRoleCompromised KeyRole = "compromised"
)

// Known legacy compromised key constants (from BB-SEC-001 archive exposure)
const (
	LegacyCompromisedKeyID       = "bb-legacy-compromised-2026"
	LegacyCompromisedPubKeyB64   = "XV01fwXz9SXyRbxDBHGjqx+sYZ/hOs4K+pjhchDm2XA="
	LegacyCompromisedFingerprint = "655029f24bebd724"
)

// VerificationKey represents public verification material and metadata for an Ed25519 key.
type VerificationKey struct {
	KeyID        string            `json:"key_id"`
	Fingerprint  string            `json:"key_fingerprint"`
	PublicKey    ed25519.PublicKey `json:"-"`
	PublicKeyB64 string            `json:"public_key"`
	Role         KeyRole           `json:"role"`
	TrustStatus  TrustStatus       `json:"trust_status"`
	ValidFrom    time.Time         `json:"valid_from"`
	RetiredAt    *time.Time        `json:"retired_at,omitempty"`
	Description  string            `json:"description,omitempty"`
}

// ComputeFingerprint computes the deterministic 16-hex character fingerprint of an Ed25519 public key.
// Matches the first 8 bytes of the SHA-256 hash of the 32-byte public key.
func ComputeFingerprint(pub ed25519.PublicKey) string {
	if len(pub) != ed25519.PublicKeySize {
		return ""
	}
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

// ParseEd25519PrivateKey parses a Base64-encoded string representing either a 32-byte seed
// or a 64-byte Ed25519 private key. Returns the private key, automatically derived public key, and error.
func ParseEd25519PrivateKey(b64Key string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(b64Key)
	if trimmed == "" {
		return nil, nil, errors.New("private key cannot be empty")
	}

	raw, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, nil, fmt.Errorf("malformed base64 encoding: %w", err)
	}

	switch len(raw) {
	case ed25519.SeedSize: // 32 bytes
		priv := ed25519.NewKeyFromSeed(raw)
		pub := priv.Public().(ed25519.PublicKey)
		return priv, pub, nil
	case ed25519.PrivateKeySize: // 64 bytes
		priv := ed25519.PrivateKey(raw)
		pub := priv.Public().(ed25519.PublicKey)
		return priv, pub, nil
	default:
		return nil, nil, fmt.Errorf("invalid ed25519 private key length: expected 32 or 64 bytes, got %d", len(raw))
	}
}

// ParseEd25519PublicKey parses a Base64-encoded string representing a 32-byte Ed25519 public key.
func ParseEd25519PublicKey(b64Key string) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(b64Key)
	if trimmed == "" {
		return nil, errors.New("public key cannot be empty")
	}

	raw, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("malformed base64 encoding: %w", err)
	}

	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key length: expected 32 bytes, got %d", len(raw))
	}

	return ed25519.PublicKey(raw), nil
}

// SigningRegistry manages active signing keys and historical public verification keys.
type SigningRegistry struct {
	mu           sync.RWMutex
	activeKeyID  string
	activePriv   ed25519.PrivateKey
	activePub    ed25519.PublicKey
	activeFp     string
	keysByID     map[string]*VerificationKey
	keysByFp     map[string]*VerificationKey
	isProduction bool
}

// GlobalRegistry is the default singleton instance used by the application.
var GlobalRegistry = NewSigningRegistry(false)

// NewSigningRegistry creates a new initialized SigningRegistry.
func NewSigningRegistry(isProduction bool) *SigningRegistry {
	r := &SigningRegistry{
		keysByID:     make(map[string]*VerificationKey),
		keysByFp:     make(map[string]*VerificationKey),
		isProduction: isProduction,
	}

	r.registerBuiltinLegacyKey()
	return r
}

func (r *SigningRegistry) registerBuiltinLegacyKey() {
	legacyPub, err := ParseEd25519PublicKey(LegacyCompromisedPubKeyB64)
	if err == nil {
		retDate := time.Date(2026, 8, 27, 20, 32, 47, 0, time.UTC)
		vk := &VerificationKey{
			KeyID:        LegacyCompromisedKeyID,
			Fingerprint:  LegacyCompromisedFingerprint,
			PublicKey:    legacyPub,
			PublicKeyB64: LegacyCompromisedPubKeyB64,
			Role:         KeyRoleCompromised,
			TrustStatus:  TrustStatusUntrusted,
			ValidFrom:    retDate,
			RetiredAt:    &retDate,
			Description:  "Compromised in source archive August 2026. Revoked and untrusted for production.",
		}
		r.keysByID[LegacyCompromisedKeyID] = vk
		r.keysByFp[LegacyCompromisedFingerprint] = vk
	}
}

// Reset clears all active and configured keys, restoring only the built-in legacy compromised entry.
func (r *SigningRegistry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.activeKeyID = ""
	r.activePriv = nil
	r.activePub = nil
	r.activeFp = ""
	r.keysByID = make(map[string]*VerificationKey)
	r.keysByFp = make(map[string]*VerificationKey)

	r.registerBuiltinLegacyKey()
}

// SetActiveKey configures the active signing key, deriving the public key and fingerprint.
// Rejects duplicate key IDs, duplicate fingerprints, collisions with existing entries, and multiple active keys.
func (r *SigningRegistry) SetActiveKey(keyID string, priv ed25519.PrivateKey, validFrom time.Time) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("invalid private key size")
	}

	pub := priv.Public().(ed25519.PublicKey)
	fp := ComputeFingerprint(pub)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	if keyID == "" {
		keyID = "key_" + fp
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check 1: Reject multiple active keys
	if r.activePriv != nil {
		return fmt.Errorf("active key collision: an active signing key is already configured (active_id=%q)", r.activeKeyID)
	}

	// Check 2: Reject collision with built-in legacy compromised key
	if keyID == LegacyCompromisedKeyID || fp == LegacyCompromisedFingerprint {
		return fmt.Errorf("key collision: active key collides with built-in legacy compromised key (id=%q, fingerprint=%q)", LegacyCompromisedKeyID, LegacyCompromisedFingerprint)
	}

	// Check 3: Reject duplicate KeyID
	if existing, exists := r.keysByID[keyID]; exists {
		return fmt.Errorf("active key ID collision: key ID %q is already registered (existing role=%s, trust=%s)", keyID, existing.Role, existing.TrustStatus)
	}

	// Check 4: Reject duplicate Fingerprint
	if existing, exists := r.keysByFp[fp]; exists {
		return fmt.Errorf("active key fingerprint collision: fingerprint %q is already registered to key ID %q (role=%s, trust=%s)", fp, existing.KeyID, existing.Role, existing.TrustStatus)
	}

	r.activeKeyID = keyID
	r.activePriv = priv
	r.activePub = pub
	r.activeFp = fp

	vk := &VerificationKey{
		KeyID:        keyID,
		Fingerprint:  fp,
		PublicKey:    pub,
		PublicKeyB64: pubB64,
		Role:         KeyRoleActive,
		TrustStatus:  TrustStatusTrusted,
		ValidFrom:    validFrom,
		Description:  "Active production signing key",
	}

	r.keysByID[keyID] = vk
	r.keysByFp[fp] = vk
	return nil
}

// RegisterHistoricalKey registers an existing or retired public verification key.
// Never silently overwrites any existing map entry.
// Rejects duplicate key IDs, duplicate fingerprints, active roles, and invalid trust metadata.
func (r *SigningRegistry) RegisterHistoricalKey(vk *VerificationKey) error {
	if vk == nil {
		return errors.New("verification key metadata cannot be nil")
	}
	if strings.TrimSpace(vk.KeyID) == "" {
		return errors.New("key_id is required for historical verification key")
	}
	if strings.TrimSpace(vk.PublicKeyB64) == "" {
		return fmt.Errorf("public_key is required for historical key %q", vk.KeyID)
	}

	// Check 1: Role must not be active
	if vk.Role == KeyRoleActive {
		return fmt.Errorf("invalid role: historical key %q cannot have role 'active'", vk.KeyID)
	}

	pub, err := ParseEd25519PublicKey(vk.PublicKeyB64)
	if err != nil {
		return fmt.Errorf("invalid public key for key %q: %w", vk.KeyID, err)
	}

	fp := ComputeFingerprint(pub)

	// Check 2: Collision with built-in legacy compromised key
	if vk.KeyID == LegacyCompromisedKeyID || fp == LegacyCompromisedFingerprint {
		return fmt.Errorf("historical key collision: key collides with built-in legacy compromised entry (id=%q, fingerprint=%q)", LegacyCompromisedKeyID, LegacyCompromisedFingerprint)
	}

	// Check 3: Validate trust status metadata
	// Do not automatically mark a retired key trusted merely because it is configured.
	// Require explicit, defensible trust metadata; unknown provenance remains unknown.
	switch vk.TrustStatus {
	case TrustStatusTrusted:
		if vk.Role == KeyRoleCompromised {
			return fmt.Errorf("conflicting metadata: compromised key %q cannot be marked as trusted", vk.KeyID)
		}
	case TrustStatusUntrusted:
		// Explicit untrusted classification
	case TrustStatusUnknown:
		// Explicit unknown provenance
	case "":
		// If trust_status was omitted, do NOT default to trusted!
		if vk.Role == KeyRoleCompromised {
			vk.TrustStatus = TrustStatusUntrusted
		} else {
			vk.TrustStatus = TrustStatusUnknown // Unknown provenance must remain unknown
		}
	default:
		return fmt.Errorf("invalid trust_status %q for key %q: must be 'trusted', 'untrusted', or 'unknown'", vk.TrustStatus, vk.KeyID)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check 4: Reject duplicate KeyID
	if existing, exists := r.keysByID[vk.KeyID]; exists {
		return fmt.Errorf("historical key registration rejected: duplicate key ID %q already registered (role=%s, trust=%s)", vk.KeyID, existing.Role, existing.TrustStatus)
	}

	// Check 5: Reject duplicate Fingerprint
	if existing, exists := r.keysByFp[fp]; exists {
		return fmt.Errorf("historical key registration rejected: duplicate fingerprint %q already registered to key ID %q (role=%s, trust=%s)", fp, existing.KeyID, existing.Role, existing.TrustStatus)
	}

	vk.PublicKey = pub
	vk.Fingerprint = fp

	r.keysByID[vk.KeyID] = vk
	r.keysByFp[fp] = vk
	return nil
}

// InitDevEphemeralKey initializes an ephemeral in-memory Ed25519 keypair for local development.
// NEVER writes any private key to disk.
func (r *SigningRegistry) InitDevEphemeralKey() error {
	r.Reset()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ephemeral dev key: %w", err)
	}

	return r.SetActiveKey("bb-dev-ephemeral", priv, time.Now().UTC())
}

// InitTestKey initializes an ephemeral in-memory keypair for automated test execution.
// Returns the generated keys. NEVER touches disk.
func (r *SigningRegistry) InitTestKey(keyID string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	r.Reset()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate test key: %w", err)
	}

	if keyID == "" {
		keyID = "bb-test-key"
	}

	err = r.SetActiveKey(keyID, priv, time.Now().UTC())
	return priv, pub, err
}

// GetActiveKey returns the active signing key information.
func (r *SigningRegistry) GetActiveKey() (keyID string, priv ed25519.PrivateKey, pub ed25519.PublicKey, fingerprint string, err error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.activePriv == nil || r.activePub == nil {
		return "", nil, nil, "", errors.New("no active signing key configured")
	}

	return r.activeKeyID, r.activePriv, r.activePub, r.activeFp, nil
}

// LookupKey retrieves a key by KeyID or Fingerprint and returns its VerificationKey and trust status.
// If the key is not found in the registry, returns (nil, TrustStatusUnknown).
func (r *SigningRegistry) LookupKey(identifier string) (*VerificationKey, TrustStatus) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if vk, ok := r.keysByID[identifier]; ok {
		return vk, vk.TrustStatus
	}
	if vk, ok := r.keysByFp[identifier]; ok {
		return vk, vk.TrustStatus
	}

	return nil, TrustStatusUnknown
}

// GetAllKeys returns public metadata for all registered keys (active and historical).
func (r *SigningRegistry) GetAllKeys() []*VerificationKey {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]bool)
	result := make([]*VerificationKey, 0, len(r.keysByID))

	for _, vk := range r.keysByID {
		if !seen[vk.KeyID] {
			seen[vk.KeyID] = true
			copyVk := *vk
			result = append(result, &copyVk)
		}
	}

	return result
}

// Sign generates an Ed25519 signature over data using the active private key.
func (r *SigningRegistry) Sign(data []byte) (signature []byte, keyID string, fingerprint string, pub ed25519.PublicKey, err error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.activePriv == nil {
		return nil, "", "", nil, errors.New("signing disabled: no active private key configured")
	}

	sig := ed25519.Sign(r.activePriv, data)
	return sig, r.activeKeyID, r.activeFp, r.activePub, nil
}

// Verify checks an Ed25519 signature mathematically using a provided public key.
// Note: Mathematical signature validity and systemic trust classification are separate concepts.
func (r *SigningRegistry) Verify(pub ed25519.PublicKey, data, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, data, sig)
}

// VerifySignature checks the mathematical validity of an Ed25519 signature against a registered key,
// and returns both whether the signature is mathematically valid AND the systemic trust status of the key.
func (r *SigningRegistry) VerifySignature(identifier string, data, sig []byte) (mathValid bool, trust TrustStatus, vk *VerificationKey) {
	vk, trust = r.LookupKey(identifier)
	if vk == nil || vk.PublicKey == nil {
		return false, TrustStatusUnknown, nil
	}
	mathValid = r.Verify(vk.PublicKey, data, sig)
	return mathValid, trust, vk
}
