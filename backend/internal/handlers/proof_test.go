package handlers

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"burner-box-backend/internal/config"
	"burner-box-backend/internal/crypto"

	"github.com/gofiber/fiber/v2"
)

func TestInitProofSystem_ProductionValidation(t *testing.T) {
	// Case 1: Missing production key configuration must fail
	prodCfgMissing := &config.Config{
		Environment:            "production",
		ProofSigningPrivateKey: "",
	}
	if err := InitProofSystem(prodCfgMissing); err == nil {
		t.Fatalf("InitProofSystem must fail when PROOF_SIGNING_PRIVATE_KEY is missing in production")
	}

	// Case 2: Invalid production key (malformed base64) must fail
	prodCfgInvalidB64 := &config.Config{
		Environment:            "production",
		ProofSigningPrivateKey: "not-valid-base64!!!",
	}
	if err := InitProofSystem(prodCfgInvalidB64); err == nil {
		t.Fatalf("InitProofSystem must fail when PROOF_SIGNING_PRIVATE_KEY is invalid base64")
	}

	// Case 3: Invalid byte length must fail
	prodCfgInvalidLen := &config.Config{
		Environment:            "production",
		ProofSigningPrivateKey: base64.StdEncoding.EncodeToString(make([]byte, 16)),
	}
	if err := InitProofSystem(prodCfgInvalidLen); err == nil {
		t.Fatalf("InitProofSystem must fail when key is neither 32 nor 64 bytes")
	}

	// Case 4: Valid 32-byte seed in production must succeed
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 42)
	}
	prodCfgValid := &config.Config{
		Environment:            "production",
		ProofSigningPrivateKey: base64.StdEncoding.EncodeToString(seed),
		ProofSigningKeyID:      "bb-prod-2026-v1",
	}
	if err := InitProofSystem(prodCfgValid); err != nil {
		t.Fatalf("InitProofSystem failed on valid production key: %v", err)
	}

	keyID, _, pub, fp, err := crypto.GlobalRegistry.GetActiveKey()
	if err != nil || pub == nil {
		t.Fatalf("Active key not available after valid production init: %v", err)
	}
	if keyID != "bb-prod-2026-v1" {
		t.Fatalf("Expected keyID 'bb-prod-2026-v1', got %s", keyID)
	}
	if fp == "" {
		t.Fatalf("Expected non-empty fingerprint")
	}
}

func TestInitProofSystem_DevEphemeral_NoDiskCreation(t *testing.T) {
	// Ensure data/proof_key.json does not exist before
	_ = os.RemoveAll("data")

	devCfg := &config.Config{
		Environment: "development",
	}
	if err := InitProofSystem(devCfg); err != nil {
		t.Fatalf("InitProofSystem failed in dev mode: %v", err)
	}

	// Verify key is loaded in memory
	keyID, _, pub, _, err := crypto.GlobalRegistry.GetActiveKey()
	if err != nil || pub == nil {
		t.Fatalf("Expected in-memory ephemeral key in dev mode")
	}
	if keyID != "bb-dev-ephemeral" {
		t.Fatalf("Expected keyID 'bb-dev-ephemeral', got %s", keyID)
	}

	// CRITICAL CHECK: Verify zero files were created on disk
	if _, err := os.Stat("data/proof_key.json"); !os.IsNotExist(err) {
		t.Fatalf("SECURITY VIOLATION: data/proof_key.json was written to disk during dev startup!")
	}
	if _, err := os.Stat("data"); !os.IsNotExist(err) {
		t.Fatalf("SECURITY VIOLATION: data/ directory was created during dev startup!")
	}
}

func TestProofEndpoints_CompatibilityAndRegistry(t *testing.T) {
	// Initialize test key in memory
	_, pub, err := crypto.GlobalRegistry.InitTestKey("bb-test-key-endpoint")
	if err != nil {
		t.Fatalf("Failed to initialize test key: %v", err)
	}
	syncPackageGlobals()

	// Register a mock historical key
	histPub, _, _ := ed25519.GenerateKey(rand.Reader)
	histPubB64 := base64.StdEncoding.EncodeToString(histPub)
	retDate := time.Now().UTC().Add(-48 * time.Hour)
	_ = crypto.GlobalRegistry.RegisterHistoricalKey(&crypto.VerificationKey{
		KeyID:        "bb-prod-historical-1",
		PublicKeyB64: histPubB64,
		Role:         crypto.KeyRoleRetired,
		TrustStatus:  crypto.TrustStatusTrusted,
		ValidFrom:    retDate.Add(-30 * 24 * time.Hour),
		RetiredAt:    &retDate,
	})

	app := fiber.New()
	app.Get("/api/v1/proof-key", GetProofPublicKey)
	app.Get("/api/v1/proof-keys", GetAllProofKeys)
	app.Get("/api/v1/proof-keys/:id", GetProofKeyByIdentifier)

	// 1. Test GET /api/v1/proof-key (Backward Compatibility)
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/proof-key", nil)
	resp1, err := app.Test(req1)
	if err != nil || resp1.StatusCode != http.StatusOK {
		t.Fatalf("GET /proof-key failed: status=%d, err=%v", resp1.StatusCode, err)
	}

	body1, _ := io.ReadAll(resp1.Body)
	var data1 map[string]interface{}
	if err := json.Unmarshal(body1, &data1); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	expectedPubB64 := base64.StdEncoding.EncodeToString(pub)
	if data1["public_key"] != expectedPubB64 {
		t.Fatalf("GET /proof-key public_key mismatch: expected %s, got %s", expectedPubB64, data1["public_key"])
	}
	if data1["fingerprint"] != crypto.ComputeFingerprint(pub) {
		t.Fatalf("GET /proof-key fingerprint mismatch")
	}
	if data1["trust_status"] != "trusted" {
		t.Fatalf("Active key must be reported as trusted")
	}

	// 2. Test GET /api/v1/proof-keys (Full Registry)
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/proof-keys", nil)
	resp2, err := app.Test(req2)
	if err != nil || resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET /proof-keys failed: status=%d, err=%v", resp2.StatusCode, err)
	}

	body2, _ := io.ReadAll(resp2.Body)
	var data2 struct {
		ActiveKeyID string                   `json:"active_key_id"`
		TotalKeys   int                      `json:"total_keys"`
		Keys        []crypto.VerificationKey `json:"keys"`
	}
	if err := json.Unmarshal(body2, &data2); err != nil {
		t.Fatalf("Failed to parse /proof-keys response: %v", err)
	}
	if data2.TotalKeys < 2 {
		t.Fatalf("Expected at least 2 keys (active + historical/legacy), got %d", data2.TotalKeys)
	}

	// 3. Test GET /api/v1/proof-keys/:id for Legacy Compromised Key
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/proof-keys/"+crypto.LegacyCompromisedFingerprint, nil)
	resp3, err := app.Test(req3)
	if err != nil || resp3.StatusCode != http.StatusOK {
		t.Fatalf("GET legacy key by fingerprint failed: status=%d", resp3.StatusCode)
	}

	body3, _ := io.ReadAll(resp3.Body)
	var data3 map[string]interface{}
	_ = json.Unmarshal(body3, &data3)
	if data3["trust_status"] != string(crypto.TrustStatusUntrusted) {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Legacy compromised key must be reported as 'untrusted', got %s", data3["trust_status"])
	}
	if data3["role"] != string(crypto.KeyRoleCompromised) {
		t.Fatalf("Legacy compromised key must have role 'compromised', got %s", data3["role"])
	}

	// 4. Test GET /api/v1/proof-keys/:id for Historical Key with Unknown Trust
	unknownProvPub, _, _ := ed25519.GenerateKey(rand.Reader)
	unknownProvPubB64 := base64.StdEncoding.EncodeToString(unknownProvPub)
	_ = crypto.GlobalRegistry.RegisterHistoricalKey(&crypto.VerificationKey{
		KeyID:        "bb-hist-unknown-prov",
		PublicKeyB64: unknownProvPubB64,
		Role:         crypto.KeyRoleRetired,
		TrustStatus:  crypto.TrustStatusUnknown,
	})

	reqUnknownProv := httptest.NewRequest(http.MethodGet, "/api/v1/proof-keys/bb-hist-unknown-prov", nil)
	respUnknownProv, err := app.Test(reqUnknownProv)
	if err != nil || respUnknownProv.StatusCode != http.StatusOK {
		t.Fatalf("GET registered key with unknown trust must return 200, got status=%d", respUnknownProv.StatusCode)
	}
	bodyUnknownProv, _ := io.ReadAll(respUnknownProv.Body)
	var dataUnknownProv map[string]interface{}
	_ = json.Unmarshal(bodyUnknownProv, &dataUnknownProv)
	if dataUnknownProv["trust_status"] != string(crypto.TrustStatusUnknown) {
		t.Fatalf("Registered key with unknown trust must return trust_status='unknown', got %s", dataUnknownProv["trust_status"])
	}
	if dataUnknownProv["key_id"] != "bb-hist-unknown-prov" {
		t.Fatalf("Expected key_id 'bb-hist-unknown-prov', got %v", dataUnknownProv["key_id"])
	}

	// 5. Test GET /api/v1/proof-keys/:id for Non-Existent Key
	req4 := httptest.NewRequest(http.MethodGet, "/api/v1/proof-keys/unknown-fingerprint-9999", nil)
	resp4, err := app.Test(req4)
	if err != nil || resp4.StatusCode != http.StatusNotFound {
		t.Fatalf("Unknown key must return 404, got status=%d", resp4.StatusCode)
	}
	body4, _ := io.ReadAll(resp4.Body)
	var data4 map[string]interface{}
	_ = json.Unmarshal(body4, &data4)
	if data4["trust_status"] != string(crypto.TrustStatusUnknown) {
		t.Fatalf("Unknown key must return trust_status='unknown', got %s", data4["trust_status"])
	}
}

func TestInitProofSystem_ProductionLikeEnvironments(t *testing.T) {
	// Staging environment missing key must fail
	stagingCfg := &config.Config{
		Environment:            "staging",
		ProofSigningPrivateKey: "",
	}
	if err := InitProofSystem(stagingCfg); err == nil {
		t.Fatalf("InitProofSystem must fail when PROOF_SIGNING_PRIVATE_KEY is missing in staging")
	}

	// Preview environment missing key must fail
	previewCfg := &config.Config{
		Environment:            "preview",
		ProofSigningPrivateKey: "",
	}
	if err := InitProofSystem(previewCfg); err == nil {
		t.Fatalf("InitProofSystem must fail when PROOF_SIGNING_PRIVATE_KEY is missing in preview")
	}

	// Cloud platform indicator (e.g. FLY_APP_NAME) missing key must fail
	origFly := os.Getenv("FLY_APP_NAME")
	defer os.Setenv("FLY_APP_NAME", origFly)
	os.Setenv("FLY_APP_NAME", "burnerbox-prod-app")

	cloudCfg := &config.Config{
		Environment:            "", // Unspecified env on Fly.io
		ProofSigningPrivateKey: "",
	}
	if err := InitProofSystem(cloudCfg); err == nil {
		t.Fatalf("InitProofSystem must fail when PROOF_SIGNING_PRIVATE_KEY is missing on cloud platform")
	}

	// Production-like with valid key
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	validKeyB64 := base64.StdEncoding.EncodeToString(seed)

	// Historical keys JSON parse error in production-like must fail fast
	badJSONCfg := &config.Config{
		Environment:               "staging",
		ProofSigningPrivateKey:    validKeyB64,
		ProofHistoricalPublicKeys: "{invalid-json}",
	}
	if err := InitProofSystem(badJSONCfg); err == nil {
		t.Fatalf("InitProofSystem must fail fast on malformed historical keys JSON in staging")
	}

	// Historical key collision error in production-like must fail fast
	collisionJSONCfg := &config.Config{
		Environment:            "staging",
		ProofSigningPrivateKey: validKeyB64,
		ProofHistoricalPublicKeys: `[
			{"key_id": "key-1", "public_key": "XV01fwXz9SXyRbxDBHGjqx+sYZ/hOs4K+pjhchDm2XA=", "role": "retired"}
		]`, // Collides with legacy compromised public key
	}
	if err := InitProofSystem(collisionJSONCfg); err == nil {
		t.Fatalf("InitProofSystem must fail fast on historical key collision in staging")
	}
}

func TestGenerateProofOfSubmission_Compatibility(t *testing.T) {
	InitProofSystemForTest(t)

	subID := "550e8400-e29b-41d4-a716-446655440000"
	payload := "encrypted-submission-test-payload-12345"

	proof := GenerateProofOfSubmission(subID, payload)
	if proof == nil {
		t.Fatalf("GenerateProofOfSubmission returned nil")
	}

	if proof.SubmissionID != subID {
		t.Fatalf("SubmissionID mismatch")
	}
	if proof.KeyFingerprint == "" || len(proof.KeyFingerprint) != 16 {
		t.Fatalf("Invalid KeyFingerprint: %s", proof.KeyFingerprint)
	}
	if proof.ServerPublicKey == "" {
		t.Fatalf("ServerPublicKey must not be empty")
	}

	// Verify Ed25519 signature directly
	pubBytes, err := base64.StdEncoding.DecodeString(proof.ServerPublicKey)
	if err != nil {
		t.Fatalf("Failed to decode ServerPublicKey: %v", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(proof.Signature)
	if err != nil {
		t.Fatalf("Failed to decode Signature: %v", err)
	}

	// Verify against sha256.Sum256([]byte(payload))
	h := sha256.Sum256([]byte(payload))
	if !ed25519.Verify(pubBytes, h[:], sigBytes) {
		t.Fatalf("Ed25519 signature verification failed on generated submission receipt")
	}
}

func TestInitProofSystem_AtomicPublicationOnFailure(t *testing.T) {
	// Clean environment variables
	origFly := os.Getenv("FLY_APP_NAME")
	defer os.Setenv("FLY_APP_NAME", origFly)
	os.Unsetenv("FLY_APP_NAME")

	// 1. Establish an initial valid registry state
	InitProofSystemForTest(t)
	initialRegistry := crypto.GlobalRegistry
	initialKeyID, _, _, initialFp, err := initialRegistry.GetActiveKey()
	if err != nil || initialKeyID == "" {
		t.Fatalf("Failed to establish initial active key: %v", err)
	}

	// 2. Stage A Failure: Malformed active private key
	badKeyCfg := &config.Config{
		Environment:            "production",
		ProofSigningPrivateKey: "bad-base64-not-a-key!!!",
	}
	if err := InitProofSystem(badKeyCfg); err == nil {
		t.Fatalf("Expected error on malformed private key, got nil")
	}
	if crypto.GlobalRegistry != initialRegistry {
		t.Fatalf("ATOMICITY VIOLATION: GlobalRegistry was replaced after Stage A parse failure")
	}
	curKeyID, _, _, curFp, _ := crypto.GlobalRegistry.GetActiveKey()
	if curKeyID != initialKeyID || curFp != initialFp {
		t.Fatalf("ATOMICITY VIOLATION: Active key was modified on Stage A failure")
	}

	// 3. Stage B Failure: Missing private key in production
	missingKeyCfg := &config.Config{
		Environment:            "production",
		ProofSigningPrivateKey: "",
	}
	if err := InitProofSystem(missingKeyCfg); err == nil {
		t.Fatalf("Expected error on missing production key, got nil")
	}
	if crypto.GlobalRegistry != initialRegistry {
		t.Fatalf("ATOMICITY VIOLATION: GlobalRegistry was replaced after Stage B missing key failure")
	}

	// 4. Stage C Failure: Active key collision with built-in legacy compromised KeyID
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	validKeyB64 := base64.StdEncoding.EncodeToString(seed)
	legacyIDCollisionCfg := &config.Config{
		Environment:            "production",
		ProofSigningPrivateKey: validKeyB64,
		ProofSigningKeyID:      crypto.LegacyCompromisedKeyID,
	}
	if err := InitProofSystem(legacyIDCollisionCfg); err == nil {
		t.Fatalf("Expected error on active key ID collision with legacy key, got nil")
	}
	if crypto.GlobalRegistry != initialRegistry {
		t.Fatalf("ATOMICITY VIOLATION: GlobalRegistry was replaced after Stage C collision failure")
	}

	// 5. Stage D Failure: Malformed historical JSON in production
	badHistJSONCfg := &config.Config{
		Environment:               "production",
		ProofSigningPrivateKey:    validKeyB64,
		ProofSigningKeyID:         "new-key-1",
		ProofHistoricalPublicKeys: "{invalid-json-content",
	}
	if err := InitProofSystem(badHistJSONCfg); err == nil {
		t.Fatalf("Expected error on malformed historical JSON, got nil")
	}
	if crypto.GlobalRegistry != initialRegistry {
		t.Fatalf("ATOMICITY VIOLATION: GlobalRegistry was replaced after Stage D historical parse failure")
	}

	// 6. Stage E Failure: Historical key collision in production
	collisionHistCfg := &config.Config{
		Environment:            "production",
		ProofSigningPrivateKey: validKeyB64,
		ProofSigningKeyID:      "new-key-2",
		ProofHistoricalPublicKeys: `[
			{"key_id": "duplicate-key", "public_key": "XV01fwXz9SXyRbxDBHGjqx+sYZ/hOs4K+pjhchDm2XA=", "role": "retired"}
		]`,
	}
	if err := InitProofSystem(collisionHistCfg); err == nil {
		t.Fatalf("Expected error on historical key collision, got nil")
	}
	if crypto.GlobalRegistry != initialRegistry {
		t.Fatalf("ATOMICITY VIOLATION: GlobalRegistry was replaced after Stage E historical collision failure")
	}

	// Final verification: Confirm original registry and globals are completely untouched
	finalKeyID, _, _, finalFp, _ := crypto.GlobalRegistry.GetActiveKey()
	if finalKeyID != initialKeyID || finalFp != initialFp {
		t.Fatalf("ATOMICITY VIOLATION: Global active key altered after failed initialization attempts")
	}

	// 7. Success case: All validations succeed -> GlobalRegistry is atomically published
	goodCfg := &config.Config{
		Environment:            "production",
		ProofSigningPrivateKey: validKeyB64,
		ProofSigningKeyID:      "new-atomic-prod-key",
	}
	if err := InitProofSystem(goodCfg); err != nil {
		t.Fatalf("Valid InitProofSystem failed: %v", err)
	}
	if crypto.GlobalRegistry == initialRegistry {
		t.Fatalf("Expected GlobalRegistry to be replaced upon successful initialization")
	}
	publishedKeyID, _, _, _, _ := crypto.GlobalRegistry.GetActiveKey()
	if publishedKeyID != "new-atomic-prod-key" {
		t.Fatalf("Expected active key to be 'new-atomic-prod-key', got %s", publishedKeyID)
	}
}
