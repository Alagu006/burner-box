package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"testing"
	"time"
)

func TestParseEd25519PrivateKey(t *testing.T) {
	// Case 1: Valid 32-byte seed
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	seedB64 := base64.StdEncoding.EncodeToString(seed)

	privFromSeed, pubFromSeed, err := ParseEd25519PrivateKey(seedB64)
	if err != nil {
		t.Fatalf("Failed to parse valid 32-byte seed: %v", err)
	}
	if len(privFromSeed) != ed25519.PrivateKeySize {
		t.Fatalf("Expected 64-byte private key, got %d", len(privFromSeed))
	}
	if len(pubFromSeed) != ed25519.PublicKeySize {
		t.Fatalf("Expected 32-byte public key, got %d", len(pubFromSeed))
	}

	// Verify derived public key matches private key's public part
	expectedPub := privFromSeed.Public().(ed25519.PublicKey)
	if base64.StdEncoding.EncodeToString(pubFromSeed) != base64.StdEncoding.EncodeToString(expectedPub) {
		t.Fatalf("Derived public key does not match private key public component")
	}

	// Case 2: Valid 64-byte private key
	_, rawPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate raw keypair: %v", err)
	}
	privB64 := base64.StdEncoding.EncodeToString(rawPriv)

	privFrom64, pubFrom64, err := ParseEd25519PrivateKey(privB64)
	if err != nil {
		t.Fatalf("Failed to parse valid 64-byte private key: %v", err)
	}
	if len(privFrom64) != ed25519.PrivateKeySize {
		t.Fatalf("Expected 64 bytes, got %d", len(privFrom64))
	}
	if len(pubFrom64) != ed25519.PublicKeySize {
		t.Fatalf("Expected 32 bytes, got %d", len(pubFrom64))
	}

	// Case 3: Empty string
	if _, _, err := ParseEd25519PrivateKey(""); err == nil {
		t.Fatalf("Expected error on empty key string")
	}

	// Case 4: Invalid base64
	if _, _, err := ParseEd25519PrivateKey("!not-valid-base64!"); err == nil {
		t.Fatalf("Expected error on invalid base64")
	}

	// Case 5: Invalid byte length (e.g. 16 bytes or 48 bytes)
	badLen := base64.StdEncoding.EncodeToString(make([]byte, 16))
	if _, _, err := ParseEd25519PrivateKey(badLen); err == nil {
		t.Fatalf("Expected error on 16-byte key")
	}

	badLen48 := base64.StdEncoding.EncodeToString(make([]byte, 48))
	if _, _, err := ParseEd25519PrivateKey(badLen48); err == nil {
		t.Fatalf("Expected error on 48-byte key")
	}
}

func TestFingerprintConsistency(t *testing.T) {
	pubBytes, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	fp1 := ComputeFingerprint(pubBytes)
	fp2 := ComputeFingerprint(pubBytes)

	if fp1 == "" || len(fp1) != 16 {
		t.Fatalf("Fingerprint must be 16 hex characters, got %q (len %d)", fp1, len(fp1))
	}
	if fp1 != fp2 {
		t.Fatalf("Fingerprint computation must be deterministic: %s != %s", fp1, fp2)
	}

	// Verify legacy compromised key fingerprint
	legacyPub, err := ParseEd25519PublicKey(LegacyCompromisedPubKeyB64)
	if err != nil {
		t.Fatalf("Failed to parse legacy public key: %v", err)
	}
	legacyFp := ComputeFingerprint(legacyPub)
	if legacyFp != LegacyCompromisedFingerprint {
		t.Fatalf("Legacy fingerprint mismatch: expected %s, got %s", LegacyCompromisedFingerprint, legacyFp)
	}
}

func TestSigningRegistry_SigningAndVerification(t *testing.T) {
	reg := NewSigningRegistry(false)

	priv, pub, err := reg.InitTestKey("bb-test-key-1")
	if err != nil {
		t.Fatalf("InitTestKey failed: %v", err)
	}

	testPayload := []byte("BurnerBox submission content integrity test")

	// Sign payload
	sig, keyID, fp, activePub, err := reg.Sign(testPayload)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if keyID != "bb-test-key-1" {
		t.Fatalf("Expected keyID 'bb-test-key-1', got %s", keyID)
	}
	if fp != ComputeFingerprint(pub) {
		t.Fatalf("Fingerprint mismatch: expected %s, got %s", ComputeFingerprint(pub), fp)
	}

	// Verify using registry
	if !reg.Verify(activePub, testPayload, sig) {
		t.Fatalf("Signature verification failed against active public key")
	}

	// Verify using standard ed25519.Verify
	if !ed25519.Verify(pub, testPayload, sig) {
		t.Fatalf("Direct ed25519.Verify failed")
	}

	// Negative case: Tampered payload
	tampered := []byte("Tampered content")
	if reg.Verify(activePub, tampered, sig) {
		t.Fatalf("Verification should have failed on tampered payload")
	}

	// Negative case: Wrong public key
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if reg.Verify(wrongPub, testPayload, sig) {
		t.Fatalf("Verification should have failed with wrong public key")
	}

	_ = priv
}

func TestSigningRegistry_HistoricalAndCompromisedKeys(t *testing.T) {
	reg := NewSigningRegistry(false)

	// 1. Verify that the legacy compromised key is registered automatically
	vk, status := reg.LookupKey(LegacyCompromisedFingerprint)
	if status != TrustStatusUntrusted {
		t.Fatalf("Legacy key must have status 'untrusted', got %s", status)
	}
	if vk.Role != KeyRoleCompromised {
		t.Fatalf("Legacy key must have role 'compromised', got %s", vk.Role)
	}

	// Also lookup by KeyID
	vkByID, statusByID := reg.LookupKey(LegacyCompromisedKeyID)
	if statusByID != TrustStatusUntrusted || vkByID.Fingerprint != LegacyCompromisedFingerprint {
		t.Fatalf("Lookup by KeyID failed for legacy key")
	}

	// 2. Register a retired historical production key
	retPub, retPriv, _ := ed25519.GenerateKey(rand.Reader)
	retPubB64 := base64.StdEncoding.EncodeToString(retPub)
	retFp := ComputeFingerprint(retPub)
	retDate := time.Now().UTC().Add(-24 * time.Hour)

	histKey := &VerificationKey{
		KeyID:        "bb-prod-historical-2025",
		PublicKeyB64: retPubB64,
		Role:         KeyRoleRetired,
		TrustStatus:  TrustStatusTrusted,
		ValidFrom:    retDate.Add(-30 * 24 * time.Hour),
		RetiredAt:    &retDate,
		Description:  "Historical 2025 production key",
	}

	if err := reg.RegisterHistoricalKey(histKey); err != nil {
		t.Fatalf("Failed to register historical key: %v", err)
	}

	// Verify historical key lookup
	foundHist, histStatus := reg.LookupKey("bb-prod-historical-2025")
	if histStatus != TrustStatusTrusted {
		t.Fatalf("Historical key should be trusted, got %s", histStatus)
	}
	if foundHist.Fingerprint != retFp {
		t.Fatalf("Historical key fingerprint mismatch")
	}

	// Verify historical signature
	historicalPayload := []byte("historical-sealed-merkle-root-payload")
	historicalSig := ed25519.Sign(retPriv, historicalPayload)
	if !ed25519.Verify(foundHist.PublicKey, historicalPayload, historicalSig) {
		t.Fatalf("Failed to verify signature using registered historical public key")
	}

	// 3. Lookup unknown key
	unknownKey, unknownStatus := reg.LookupKey("non-existent-fingerprint-1234")
	if unknownStatus != TrustStatusUnknown {
		t.Fatalf("Expected TrustStatusUnknown for non-existent key, got %s", unknownStatus)
	}
	if unknownKey != nil {
		t.Fatalf("Expected nil key object for non-existent key, got %+v", unknownKey)
	}
}

func TestSigningRegistry_CollisionRejection(t *testing.T) {
	reg := NewSigningRegistry(false)

	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub1 := priv1.Public().(ed25519.PublicKey)
	fp1 := ComputeFingerprint(pub1)

	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	pub2 := priv2.Public().(ed25519.PublicKey)
	fp2 := ComputeFingerprint(pub2)

	// 1. Set first active key -> success
	now := time.Now().UTC()
	if err := reg.SetActiveKey("key-active-1", priv1, now); err != nil {
		t.Fatalf("SetActiveKey(key-active-1) failed: %v", err)
	}

	// 2. Reject multiple active keys
	err := reg.SetActiveKey("key-active-2", priv2, now)
	if err == nil {
		t.Fatalf("Expected error when setting a second active key, got nil")
	}

	// 3. Reject active key collision with built-in legacy compromised KeyID
	regReset := NewSigningRegistry(false)
	err = regReset.SetActiveKey(LegacyCompromisedKeyID, priv2, now)
	if err == nil {
		t.Fatalf("Expected error when active key collides with legacy KeyID")
	}

	// 4. Reject active key collision with built-in legacy compromised Fingerprint
	legacyPub, _ := ParseEd25519PublicKey(LegacyCompromisedPubKeyB64)
	_ = legacyPub
	// Even without the legacy private key, any private key deriving that fingerprint must collide

	// 5. Historical key collisions:
	// a) Cannot register active role as historical key
	histActiveRole := &VerificationKey{
		KeyID:        "hist-active-role",
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub2),
		Role:         KeyRoleActive,
		TrustStatus:  TrustStatusTrusted,
	}
	if err := reg.RegisterHistoricalKey(histActiveRole); err == nil {
		t.Fatalf("Expected error when historical key has role 'active'")
	}

	// b) Reject duplicate KeyID against active key
	histActiveIDCol := &VerificationKey{
		KeyID:        "key-active-1",
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub2),
		Role:         KeyRoleRetired,
		TrustStatus:  TrustStatusTrusted,
	}
	if err := reg.RegisterHistoricalKey(histActiveIDCol); err == nil {
		t.Fatalf("Expected error on duplicate KeyID against active key")
	}

	// c) Reject duplicate Fingerprint against active key
	histActiveFpCol := &VerificationKey{
		KeyID:        "different-id-same-pub",
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub1),
		Role:         KeyRoleRetired,
		TrustStatus:  TrustStatusTrusted,
	}
	if err := reg.RegisterHistoricalKey(histActiveFpCol); err == nil {
		t.Fatalf("Expected error on duplicate Fingerprint against active key")
	}

	// d) Reject collision with built-in legacy KeyID
	histLegacyIDCol := &VerificationKey{
		KeyID:        LegacyCompromisedKeyID,
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub2),
		Role:         KeyRoleRetired,
		TrustStatus:  TrustStatusUntrusted,
	}
	if err := reg.RegisterHistoricalKey(histLegacyIDCol); err == nil {
		t.Fatalf("Expected error on collision with legacy KeyID")
	}

	// e) Reject collision with built-in legacy Fingerprint
	histLegacyFpCol := &VerificationKey{
		KeyID:        "new-id-legacy-pub",
		PublicKeyB64: LegacyCompromisedPubKeyB64,
		Role:         KeyRoleRetired,
		TrustStatus:  TrustStatusUntrusted,
	}
	if err := reg.RegisterHistoricalKey(histLegacyFpCol); err == nil {
		t.Fatalf("Expected error on collision with legacy Fingerprint")
	}

	// f) Register a valid historical key
	validHist := &VerificationKey{
		KeyID:        "hist-key-2",
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub2),
		Role:         KeyRoleRetired,
		TrustStatus:  TrustStatusTrusted,
	}
	if err := reg.RegisterHistoricalKey(validHist); err != nil {
		t.Fatalf("Failed to register valid historical key: %v", err)
	}

	// g) Reject duplicate KeyID against existing historical key
	_, priv3, _ := ed25519.GenerateKey(rand.Reader)
	pub3 := priv3.Public().(ed25519.PublicKey)
	histDupID := &VerificationKey{
		KeyID:        "hist-key-2",
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub3),
		Role:         KeyRoleRetired,
		TrustStatus:  TrustStatusTrusted,
	}
	if err := reg.RegisterHistoricalKey(histDupID); err == nil {
		t.Fatalf("Expected error on duplicate KeyID against historical key")
	}

	// h) Reject duplicate Fingerprint against existing historical key
	histDupFp := &VerificationKey{
		KeyID:        "hist-key-3-diff-id",
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub2),
		Role:         KeyRoleRetired,
		TrustStatus:  TrustStatusTrusted,
	}
	if err := reg.RegisterHistoricalKey(histDupFp); err == nil {
		t.Fatalf("Expected error on duplicate Fingerprint against historical key")
	}

	// Verify original entries were not silently overwritten
	originalActive, _ := reg.LookupKey("key-active-1")
	if originalActive == nil || originalActive.Fingerprint != fp1 {
		t.Fatalf("Original active key map entry was corrupted or overwritten")
	}
	originalHist, _ := reg.LookupKey("hist-key-2")
	if originalHist == nil || originalHist.Fingerprint != fp2 {
		t.Fatalf("Original historical key map entry was corrupted or overwritten")
	}
}

func TestSigningRegistry_HistoricalTrustClassification(t *testing.T) {
	reg := NewSigningRegistry(false)

	// Case 1: Explicit trusted historical key
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub1 := priv1.Public().(ed25519.PublicKey)
	if err := reg.RegisterHistoricalKey(&VerificationKey{
		KeyID:        "hist-trusted",
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub1),
		Role:         KeyRoleRetired,
		TrustStatus:  TrustStatusTrusted,
	}); err != nil {
		t.Fatalf("Failed to register explicit trusted historical key: %v", err)
	}
	vk1, status1 := reg.LookupKey("hist-trusted")
	if status1 != TrustStatusTrusted || vk1.TrustStatus != TrustStatusTrusted {
		t.Fatalf("Expected TrustStatusTrusted, got %s", status1)
	}

	// Case 2: Explicit untrusted historical key
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	pub2 := priv2.Public().(ed25519.PublicKey)
	if err := reg.RegisterHistoricalKey(&VerificationKey{
		KeyID:        "hist-untrusted",
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub2),
		Role:         KeyRoleCompromised,
		TrustStatus:  TrustStatusUntrusted,
	}); err != nil {
		t.Fatalf("Failed to register explicit untrusted historical key: %v", err)
	}
	vk2, status2 := reg.LookupKey("hist-untrusted")
	if status2 != TrustStatusUntrusted || vk2.TrustStatus != TrustStatusUntrusted {
		t.Fatalf("Expected TrustStatusUntrusted, got %s", status2)
	}

	// Case 3: Explicit unknown historical key
	_, priv3, _ := ed25519.GenerateKey(rand.Reader)
	pub3 := priv3.Public().(ed25519.PublicKey)
	if err := reg.RegisterHistoricalKey(&VerificationKey{
		KeyID:        "hist-unknown-explicit",
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub3),
		Role:         KeyRoleRetired,
		TrustStatus:  TrustStatusUnknown,
	}); err != nil {
		t.Fatalf("Failed to register explicit unknown historical key: %v", err)
	}
	vk3, status3 := reg.LookupKey("hist-unknown-explicit")
	if status3 != TrustStatusUnknown || vk3.TrustStatus != TrustStatusUnknown {
		t.Fatalf("Expected TrustStatusUnknown, got %s", status3)
	}

	// Case 4: Omitted trust_status with retired role must default to TrustStatusUnknown (never trusted)
	_, priv4, _ := ed25519.GenerateKey(rand.Reader)
	pub4 := priv4.Public().(ed25519.PublicKey)
	if err := reg.RegisterHistoricalKey(&VerificationKey{
		KeyID:        "hist-omitted-trust",
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub4),
		Role:         KeyRoleRetired,
		TrustStatus:  "", // Omitted
	}); err != nil {
		t.Fatalf("Failed to register historical key with omitted trust: %v", err)
	}
	vk4, status4 := reg.LookupKey("hist-omitted-trust")
	if status4 != TrustStatusUnknown || vk4.TrustStatus != TrustStatusUnknown {
		t.Fatalf("Omitted trust status must default to 'unknown', got %s", status4)
	}

	// Case 5: Omitted trust_status with compromised role must default to TrustStatusUntrusted
	_, priv5, _ := ed25519.GenerateKey(rand.Reader)
	pub5 := priv5.Public().(ed25519.PublicKey)
	if err := reg.RegisterHistoricalKey(&VerificationKey{
		KeyID:        "hist-omitted-compromised",
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub5),
		Role:         KeyRoleCompromised,
		TrustStatus:  "", // Omitted
	}); err != nil {
		t.Fatalf("Failed to register compromised key with omitted trust: %v", err)
	}
	vk5, status5 := reg.LookupKey("hist-omitted-compromised")
	if status5 != TrustStatusUntrusted || vk5.TrustStatus != TrustStatusUntrusted {
		t.Fatalf("Omitted trust status on compromised key must default to 'untrusted', got %s", status5)
	}

	// Case 6: Reject conflicting metadata (compromised role marked trusted)
	_, priv6, _ := ed25519.GenerateKey(rand.Reader)
	pub6 := priv6.Public().(ed25519.PublicKey)
	errCompromisedTrusted := reg.RegisterHistoricalKey(&VerificationKey{
		KeyID:        "hist-conflicting-compromised-trusted",
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub6),
		Role:         KeyRoleCompromised,
		TrustStatus:  TrustStatusTrusted,
	})
	if errCompromisedTrusted == nil {
		t.Fatalf("Expected error when compromised key is marked as trusted")
	}

	// Case 7: Reject invalid trust_status string
	_, priv7, _ := ed25519.GenerateKey(rand.Reader)
	pub7 := priv7.Public().(ed25519.PublicKey)
	errInvalidTrust := reg.RegisterHistoricalKey(&VerificationKey{
		KeyID:        "hist-invalid-trust",
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub7),
		Role:         KeyRoleRetired,
		TrustStatus:  "almost-trusted",
	})
	if errInvalidTrust == nil {
		t.Fatalf("Expected error on invalid trust_status string")
	}
}

func TestSigningRegistry_VerifySignature_TrustSeparation(t *testing.T) {
	reg := NewSigningRegistry(false)

	// 1. Setup active key
	_, activePriv, _ := ed25519.GenerateKey(rand.Reader)
	activePub := activePriv.Public().(ed25519.PublicKey)
	activeFp := ComputeFingerprint(activePub)
	if err := reg.SetActiveKey("active-key-verify", activePriv, time.Now().UTC()); err != nil {
		t.Fatalf("Failed to set active key: %v", err)
	}

	// 2. Setup untrusted historical key (simulate compromised key with known private key)
	_, untrustedPriv, _ := ed25519.GenerateKey(rand.Reader)
	untrustedPub := untrustedPriv.Public().(ed25519.PublicKey)
	untrustedFp := ComputeFingerprint(untrustedPub)
	if err := reg.RegisterHistoricalKey(&VerificationKey{
		KeyID:        "untrusted-hist-key",
		PublicKeyB64: base64.StdEncoding.EncodeToString(untrustedPub),
		Role:         KeyRoleCompromised,
		TrustStatus:  TrustStatusUntrusted,
	}); err != nil {
		t.Fatalf("Failed to register untrusted key: %v", err)
	}

	// 3. Setup historical key with unknown provenance
	_, unknownPriv, _ := ed25519.GenerateKey(rand.Reader)
	unknownPub := unknownPriv.Public().(ed25519.PublicKey)
	unknownFp := ComputeFingerprint(unknownPub)
	if err := reg.RegisterHistoricalKey(&VerificationKey{
		KeyID:        "unknown-provenance-key",
		PublicKeyB64: base64.StdEncoding.EncodeToString(unknownPub),
		Role:         KeyRoleRetired,
		TrustStatus:  TrustStatusUnknown,
	}); err != nil {
		t.Fatalf("Failed to register unknown provenance key: %v", err)
	}

	data := []byte("receipt-merkle-root-payload-integrity-test")

	// Verification Scenario A: Active Key
	// Must be mathematically valid AND trusted
	activeSig := ed25519.Sign(activePriv, data)
	mathValid, trust, vk := reg.VerifySignature("active-key-verify", data, activeSig)
	if !mathValid || trust != TrustStatusTrusted || vk == nil {
		t.Fatalf("Active key verification failed: mathValid=%v, trust=%s", mathValid, trust)
	}
	// By fingerprint lookup
	mathValidFp, trustFp, _ := reg.VerifySignature(activeFp, data, activeSig)
	if !mathValidFp || trustFp != TrustStatusTrusted {
		t.Fatalf("Active key fingerprint verification failed: mathValid=%v, trust=%s", mathValidFp, trustFp)
	}

	// Verification Scenario B: Untrusted Key (Demonstrates Math vs Trust separation)
	// A valid signature made with untrusted/compromised key is mathematically TRUE, but systemic trust is UNTRUSTED!
	untrustedSig := ed25519.Sign(untrustedPriv, data)
	mathValidUntrusted, trustUntrusted, vkUntrusted := reg.VerifySignature("untrusted-hist-key", data, untrustedSig)
	if !mathValidUntrusted {
		t.Fatalf("Untrusted key signature must be mathematically valid")
	}
	if trustUntrusted != TrustStatusUntrusted {
		t.Fatalf("Untrusted key must return TrustStatusUntrusted, got %s", trustUntrusted)
	}
	if vkUntrusted == nil || vkUntrusted.Fingerprint != untrustedFp {
		t.Fatalf("Untrusted key verification did not return correct verification key")
	}

	// Verification Scenario C: Unknown Provenance Key
	// A valid signature with unknown provenance is mathematically TRUE, but systemic trust is UNKNOWN!
	unknownSig := ed25519.Sign(unknownPriv, data)
	mathValidUnknown, trustUnknown, vkUnknown := reg.VerifySignature(unknownFp, data, unknownSig)
	if !mathValidUnknown {
		t.Fatalf("Unknown key signature must be mathematically valid")
	}
	if trustUnknown != TrustStatusUnknown {
		t.Fatalf("Unknown key must return TrustStatusUnknown, got %s", trustUnknown)
	}
	if vkUnknown == nil {
		t.Fatalf("Unknown key verification did not return verification key")
	}

	// Verification Scenario D: Non-existent / Unregistered Key
	mathValidNone, trustNone, vkNone := reg.VerifySignature("completely-unknown-key", data, activeSig)
	if mathValidNone || trustNone != TrustStatusUnknown || vkNone != nil {
		t.Fatalf("Unregistered key must return mathValid=false, trust=unknown, vk=nil")
	}

	// Verification Scenario E: Tampered Signature
	tamperedSig := make([]byte, len(activeSig))
	copy(tamperedSig, activeSig)
	tamperedSig[0] ^= 0xFF // Corrupt first byte
	mathValidTampered, _, _ := reg.VerifySignature("active-key-verify", data, tamperedSig)
	if mathValidTampered {
		t.Fatalf("Tampered signature must not be mathematically valid")
	}
}

func TestSigningRegistry_NoDiskPersistence(t *testing.T) {
	// Verify that creating a registry, setting active keys, and signing creates zero files on disk
	beforeFiles, _ := os.ReadDir(".")

	reg := NewSigningRegistry(false)
	if err := reg.InitDevEphemeralKey(); err != nil {
		t.Fatalf("InitDevEphemeralKey failed: %v", err)
	}

	for i := 0; i < 10; i++ {
		_, _, _, _, err := reg.Sign([]byte("ephemeral-sign-benchmark"))
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
	}

	afterFiles, _ := os.ReadDir(".")
	if len(beforeFiles) != len(afterFiles) {
		t.Fatalf("Signing registry generated files on disk: before=%d, after=%d", len(beforeFiles), len(afterFiles))
	}

	// Specifically ensure data/proof_key.json does not exist
	if _, err := os.Stat("data/proof_key.json"); !os.IsNotExist(err) {
		t.Fatalf("Found data/proof_key.json on disk! Key persistence must be completely eliminated.")
	}
}
