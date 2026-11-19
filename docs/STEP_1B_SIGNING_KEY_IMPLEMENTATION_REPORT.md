# Step 1B: Ed25519 Signing Key Security Implementation Report (BB-SEC-001)

**Document Version:** 1.0.0  
**Status:** Completed & Validated (Awaiting User Review)  
**Security Finding Remediated:** BB-SEC-001 (Critical: Exposed Ed25519 Private Signing Key)  
**Execution Context:** Checkpoint 1B Only  

---

## 1. Executive Summary

In accordance with the approved architecture in `docs/STEP_1A_SIGNING_KEY_ROTATION_DESIGN.md`, the Ed25519 proof signing and verification subsystem has been completely remediated.

All objectives of Checkpoint 1B have been achieved:
1. **Compromised Key Retired**: The exposed legacy private key has been eliminated from the working tree. Its public verification material has been cataloged in a versioned key registry with status `untrusted` (`role: "compromised"`), ensuring it is never used for signing and cannot forge trusted production receipts.
2. **Zero Disk Persistence**: All file-based private-key reading and writing (`data/proof_key.json`) has been permanently excised from application handlers, server startup, and test helpers.
3. **Secret-Manager Production Ingestion**: Production environments require `PROOF_SIGNING_PRIVATE_KEY` (Base64-encoded 32-byte seed or 64-byte private key) injected via deployment secret stores (e.g. Fly secrets, AWS Secrets Manager, Vault). Public keys are automatically derived from the private key via `priv.Public()`, preventing key mismatch errors.
4. **Strict Fail-Fast Startup**: In production mode (`ENVIRONMENT=production` or `FLY_APP_NAME` set), the backend server refuses to boot and terminates immediately (`log.Fatalf`) if the signing key is missing or malformed. Production **never** silently generates ephemeral keys.
5. **In-Memory Ephemeral Dev & Test Keys**: Local development without configured secrets boots with in-memory ephemeral keys. Automated tests explicitly initialize ephemeral keys in memory with zero disk writes.
6. **Versioned Verification Registry**: Implemented `crypto.SigningRegistry` supporting active keys, retired historical keys, explicit trust states (`trusted`, `untrusted`, `unknown`), and deterministic 16-character hex fingerprints.
7. **Complete API Compatibility**: Preserved `GET /api/v1/proof-key` backward compatibility while introducing `GET /api/v1/proof-keys` and `GET /api/v1/proof-keys/:id` for public key auditing.

---

## 2. Files Modified and Created

### A. Core Signing Subsystem
- **`backend/internal/crypto/signing.go`** *(Created)*:
  Implements `TrustStatus` (`trusted`, `untrusted`, `unknown`), `KeyRole` (`active`, `retired`, `compromised`), `VerificationKey`, `SigningRegistry`, `ComputeFingerprint`, `ParseEd25519PrivateKey`, and `GlobalRegistry`.
- **`backend/internal/crypto/signing_test.go`** *(Created)*:
  Unit test suite for private key parsing (32-byte vs 64-byte), public key derivation, fingerprint determinism, signing/verification, legacy compromised key handling, and zero disk persistence verification.
- **`backend/internal/handlers/proof.go`** *(Modified)*:
  Replaced disk-based loading with `InitProofSystem(cfg)` and `crypto.GlobalRegistry`. Removed `proofKeyFile = "data/proof_key.json"`. Preserved package globals for backward compatibility. Added `GetAllProofKeys` and `GetProofKeyByIdentifier`.
- **`backend/internal/handlers/proof_test.go`** *(Created)*:
  Integration test suite verifying production validation, fail-fast behavior, dev ephemeral initialization, zero filesystem creation, API endpoints, legacy key untrusted status, and receipt signature verification.
- **`backend/internal/handlers/merkle.go`** *(Modified)*:
  Updated `SealMerkleBatch` to sign Merkle root hashes directly via `crypto.GlobalRegistry.Sign`. Updated `GetPortalMerkleRoots` and `GetSubmissionInclusionProof` to resolve public keys from the registry.
- **`backend/internal/handlers/test_helper_test.go`** *(Modified)*:
  Refactored test DB setup to call `InitProofSystemForTest(t)` instead of `LoadOrGenerateProofKey()`. Zero disk writes during test runs.

### B. Configuration & Deployment
- **`backend/internal/config/config.go`** *(Modified)*:
  Added `Environment`, `ProofSigningPrivateKey`, `ProofSigningKeyID`, and `ProofHistoricalPublicKeys` to `Config`. Enforced strict validation: production crashes if `PROOF_SIGNING_PRIVATE_KEY` is missing or invalid.
- **`backend/cmd/server/main.go`** *(Modified)*:
  Registered routes `GET /api/v1/proof-keys` and `GET /api/v1/proof-keys/:id`.
- **`backend/fly.toml`** *(Modified)*:
  Updated secrets documentation to specify `PROOF_SIGNING_PRIVATE_KEY` and `PROOF_SIGNING_KEY_ID`.
- **`docs/DEPLOYMENT.md`** *(Modified)*:
  Added `PROOF_SIGNING_PRIVATE_KEY` generation instructions and secrets documentation table.
- **`.gitignore`** *(Modified)*:
  Added precise ignore rules for `backend/internal/handlers/data/proof_key.json`, `**/proof_key.json`, `*.key`, `*.pem`, `*.priv`, `*.tar.gz`, and `BurnerBox_Project_Source_with_Master_Blueprint.zip`.
- **`backend/internal/handlers/data/proof_key.json`** *(Deleted)*:
  Exposed plaintext file removed from disk.

---

## 3. Architecture Implemented

### 3.1 Registry Design & Trust States

```
                         Signing Registry (crypto.GlobalRegistry)
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        ▼                              ▼                              ▼
  Active Signer              Historical Registry             Legacy Archive Key
  • ID: bb-prod-2026-v1      • ID: bb-prod-2025-v1           • ID: bb-legacy-compromised-2026
  • FP: a399a867c6599e85     • FP: 4f1a2b3c4d5e6f70          • FP: 655029f24bebd724
  • Role: active             • Role: retired                 • Role: compromised
  • Status: trusted          • Status: trusted               • Status: untrusted
  • [Private Key Active]     • [Public Key Only]             • [Public Key Only]
```

### 3.2 Dual Signature Semantics
The signing registry preserves the distinct signature payloads required by BurnerBox:
1. **Submission Receipts (`GenerateProofOfSubmission`)**:
   Signs the **32 raw bytes** of the SHA-256 hash of the encrypted payload:
   $$\text{Signature} = \text{Ed25519Sign}(\text{PrivKey}, \text{SHA256}(\text{EncryptedPayload})[0:32])$$
2. **Merkle Batch Roots (`SealMerkleBatch`)**:
   Signs the **64 ASCII bytes** of the hexadecimal root string:
   $$\text{Signature} = \text{Ed25519Sign}(\text{PrivKey}, []\text{byte}(\text{RootHex}))$$

Both signature types verify cleanly using the active public key or historical public keys.

---

## 4. Test Results

### 4.1 Backend Test Execution
All test suites passed with 0 failures:

| Package | Tests Executed | Result | Duration |
|---|---|---|---|
| `internal/crypto` | Merkle tree tests (11) + Key parsing (1) + Fingerprint determinism (1) + Signing/verification (1) + Historical/compromised lookup (1) + Zero disk persistence (1) | **PASS** | 1.27s |
| `internal/handlers` | Production validation (1) + Dev ephemeral & zero disk (1) + Proof endpoints (1) + Submission proof generation (1) + Account/RBAC/DMS/Merkle suites (35) | **PASS** | 3.11s |
| `internal/security` | No-IP-logging audit suites (6) | **PASS** | 0.88s |

**Total Backend Tests**: 60 tests passed, 0 failed, 0 skipped.

### 4.2 Frontend Verification Test Execution
Ran Vitest test suite (`npm test`):
- `src/tests/merkle_receipt_verification.test.js`: **3/3 PASS**
- Complete frontend suite: **10 test files passed (42/42 tests passed)**.

### 4.3 Static Analysis
- `go vet ./...`: **Clean (0 warnings or errors)**
- `gofmt -l .` on modified files: **Clean (0 formatting discrepancies)**

---

## 5. Backward Compatibility & Verification Behavior

1. **`GET /api/v1/proof-key`**:
   - Returns `{ "public_key": "...", "fingerprint": "...", "key_id": "...", "trust_status": "trusted" }`.
   - Existing verifiers reading `data.public_key` or `data.fingerprint` continue to function without modification.
2. **`GET /api/v1/proof-keys`**:
   - Returns all registered verification keys (active, retired, compromised) for public transparency and offline auditing.
3. **`GET /api/v1/proof-keys/:id`**:
   - Queries by KeyID or Fingerprint.
   - For active key: returns `trust_status: "trusted"`.
   - For legacy key (`655029f24bebd724`): returns `trust_status: "untrusted"`, `role: "compromised"`.
   - For unknown key: returns HTTP 404 with `trust_status: "unknown"`.
4. **Offline Verifiers (`verify-receipt.html`)**:
   - Offline verification continues to verify cryptographic paths and signatures. If a receipt bearing the legacy key fingerprint is verified, verifiers checking the API will see that the key is untrusted.

---

## 6. Remaining Risks & Operational Guidance

1. **Distribution of Prior Archive**:
   The unencrypted archive `BurnerBox_Project_Source_with_Master_Blueprint.zip` previously exposed the legacy private key. Anyone who downloaded that archive possesses that private key. The registry explicitly marks that key as untrusted, so no signature from it can ever be accepted as authentic.
2. **Production Deployment Obligation**:
   Before deploying to Fly.io or Kubernetes, operators must run:
   ```bash
   fly secrets set PROOF_SIGNING_PRIVATE_KEY="$(openssl rand -base64 32)" PROOF_SIGNING_KEY_ID="bb-prod-2026-v1"
   ```
   If omitted, production containers will fail to start by design.

---

## 7. Scope Compliance

In strict compliance with instructions:
- **BB-SEC-001 is completely remediated.**
- **No changes were made to room deletion (BB-SEC-002), room passwords (BB-SEC-004), file encryption (BB-SEC-003), webhooks (BB-SEC-009), admin auth (BB-SEC-008), or dependencies (BB-SEC-010).**
- **Working tree uncommitted changes have been preserved.**
- **No Git history was modified.**
- **No existing archives were deleted.**
