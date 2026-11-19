# BurnerBox — Checkpoint 1B.2 Corrective Report: Signing Registry Hardening & Environment Safety

**Date:** 2026-11-19  
**Scope:** BB-SEC-001 (Corrective Checkpoint 1B.2)  
**Author:** Application Security & Systems Architecture  
**Status:** COMPLETE — Awaiting User Approval  

---

## 1. Executive Summary

Checkpoint 1B.2 resolves the specific edge cases and architectural hardening requirements identified during the independent review of BB-SEC-001:

1. **Collision Protection**: Strict collision rejection in `crypto.SigningRegistry` prevents duplicate KeyIDs, duplicate public key fingerprints, collisions with the built-in legacy compromised key, multiple active signing keys, and accidental map entry overwrites.
2. **Defensible Trust Classification**: Decoupled mathematical signature verification (`mathValid`) from systemic trust classification (`trust`). Retired historical keys are never automatically trusted; keys with omitted or unverified provenance remain strictly `unknown`. Compromised keys cannot be registered as `trusted`.
3. **Production-Like Environment Enforcement**: Implemented `config.IsProductionLikeEnvironment` to classify staging, preview, live, Fly.io, Kubernetes, AWS, Render, and Railway deployments as production-like. In these environments, `PROOF_SIGNING_PRIVATE_KEY` is strictly required, ephemeral key fallback is completely forbidden, and historical key parse or registration failures cause immediate startup failure.
4. **Endpoint Semantics**: `GET /api/v1/proof-keys/:id` properly distinguishes between registered keys with unknown trust (HTTP 200 with `trust_status: "unknown"`) and unregistered keys (HTTP 404 with `trust_status: "unknown"`).
5. **Archive & Repository Hygiene**: Forensic archive bundles (`BurnerBox_Project_Source_with_Master_Blueprint.zip` and `pre_remediation_checkpoint0.tar.gz`) remain intact on disk and safely ignored by `.gitignore` rules without modifying Git history.

---

## 2. Technical Modifications

### 2.1 Collision Protection in `backend/internal/crypto/signing.go`

The signing registry enforces five non-bypassable collision checks prior to inserting any key into memory:

```go
// SetActiveKey:
1. Rejects multiple active keys (r.activePriv != nil check)
2. Rejects collision with built-in legacy compromised KeyID or Fingerprint
3. Rejects duplicate KeyID if already registered in keysByID
4. Rejects duplicate Fingerprint if already registered in keysByFp

// RegisterHistoricalKey:
1. Rejects keys configured with Role == KeyRoleActive
2. Rejects collision with built-in legacy compromised KeyID or Fingerprint
3. Validates trust metadata (compromised keys cannot be trusted; invalid strings rejected)
4. Rejects duplicate KeyID if already registered in keysByID
5. Rejects duplicate Fingerprint if already registered in keysByFp
```

Map entries are never overwritten silently. Any collision immediately halts registration and returns a structured error identifying the conflicting identifier without leaking private key data.

### 2.2 Strict Trust Classification & Verification Separation

To prevent mathematical verification from being conflated with operational trust:
- Added `TrustStatus` enum (`trusted`, `untrusted`, `unknown`).
- **Default Provenance Rule**: When `trust_status` is omitted in historical key configuration:
  - If `Role == KeyRoleCompromised`, defaults to `untrusted`.
  - Otherwise, defaults to `unknown` (unknown provenance must never be elevated to `trusted`).
- **Metadata Consistency**: Attempting to register a key with `Role: "compromised"` and `TrustStatus: "trusted"` returns an immediate validation error.
- **Verification Separation (`VerifySignature`)**:
  ```go
  func (r *SigningRegistry) VerifySignature(identifier string, data, sig []byte) (mathValid bool, trust TrustStatus, vk *VerificationKey)
  ```
  Returns `mathValid` (pure Ed25519 cryptographic check) alongside `trust` (systemic trust classification from the registry). A signature produced by a compromised key returns `mathValid = true`, but `trust = TrustStatusUntrusted`.

### 2.3 Cloud & Environment Safety in `backend/internal/config/config.go` and `handlers/proof.go`

`IsProductionLikeEnvironment(env string) bool` protects deployments across tiers and cloud hosts:
- **Tiers**: `production`, `prod`, `staging`, `stage`, `preview`, `live`.
- **Infrastructure Detectors**: `FLY_APP_NAME`, `KUBERNETES_SERVICE_HOST`, `RENDER`, `RAILWAY_ENVIRONMENT`, `AWS_EXECUTION_ENV`, `HEROKU_APP_ID`, `DYNO`, `GAE_APPLICATION`, `K_SERVICE`.
- **Local Dev Preserved**: Explicit `development`, `dev`, `testing`, `test`, or `local` overrides cloud detectors, preserving local development simulation.
- **Fail-Fast Invariants**:
  - In production-like environments, `PROOF_SIGNING_PRIVATE_KEY` missing or invalid terminates the server immediately (`log.Fatalf`).
  - Ephemeral in-memory key generation is strictly forbidden in production-like environments.
  - Malformed `PROOF_HISTORICAL_PUBLIC_KEYS` JSON or key collision in production-like environments returns an error and aborts boot.

### 2.4 Lookup Endpoint Corrections in `backend/internal/handlers/proof.go`

Refactored `GetProofKeyByIdentifier`:
- Key found in registry (`vk != nil`): returns HTTP 200 with complete metadata and `trust_status: string(vk.TrustStatus)` (even if `vk.TrustStatus == "unknown"`).
- Key not found in registry (`vk == nil`): returns HTTP 404 with error message and `trust_status: "unknown"`.

---

## 3. Automated Test Coverage

### 3.1 Crypto Tests (`backend/internal/crypto/signing_test.go`)
- `TestSigningRegistry_CollisionRejection`:
  - Setting second active key returns active key collision error.
  - Setting active key with legacy compromised KeyID fails.
  - Registering historical key with active role fails.
  - Duplicate KeyID against active key fails.
  - Duplicate Fingerprint against active key fails.
  - Collision with legacy KeyID in historical registration fails.
  - Collision with legacy Fingerprint in historical registration fails.
  - Duplicate KeyID between two historical keys fails.
  - Duplicate Fingerprint between two historical keys fails.
  - Asserts that original registry map entries are never corrupted or overwritten.
- `TestSigningRegistry_HistoricalTrustClassification`:
  - Explicit `trusted`, `untrusted`, and `unknown` historical keys are properly stored and retrieved.
  - Omitted `trust_status` defaults to `unknown` for retired keys.
  - Omitted `trust_status` defaults to `untrusted` for compromised keys.
  - Attempting to mark compromised key as `trusted` is rejected.
  - Invalid `trust_status` strings are rejected.
- `TestSigningRegistry_VerifySignature_TrustSeparation`:
  - Active key: `mathValid = true`, `trust = "trusted"`.
  - Compromised historical key: `mathValid = true`, `trust = "untrusted"` (proves math vs trust separation).
  - Unknown provenance historical key: `mathValid = true`, `trust = "unknown"`.
  - Unregistered key: `mathValid = false`, `trust = "unknown"`, `vk = nil`.
  - Tampered signature: `mathValid = false`.

### 3.2 Config Tests (`backend/internal/config/config_test.go`)
- `TestIsProductionLikeEnvironment`:
  - Evaluates all production, staging, preview, and live variations.
  - Evaluates local dev and test environments.
  - Evaluates cloud platform environment variables (`FLY_APP_NAME`, `KUBERNETES_SERVICE_HOST`, `RENDER`, `RAILWAY_ENVIRONMENT`, etc.).
  - Evaluates explicit developer override during local simulation.

### 3.3 Handlers Tests (`backend/internal/handlers/proof_test.go`)
- `TestInitProofSystem_ProductionValidation`: Production startup validation.
- `TestInitProofSystem_DevEphemeral_NoDiskCreation`: Zero disk writes in dev mode.
- `TestInitProofSystem_ProductionLikeEnvironments`: Staging, preview, and Fly.io fail fast when key is missing, when historical JSON is invalid, or when historical keys collide.
- `TestProofEndpoints_CompatibilityAndRegistry`:
  - Backward compatibility of `GET /api/v1/proof-key`.
  - Comprehensive listing of `GET /api/v1/proof-keys`.
  - Lookup of legacy key returns HTTP 200 with `trust_status: "untrusted"`.
  - Lookup of historical key with unknown provenance returns HTTP 200 with `trust_status: "unknown"`.
  - Lookup of non-existent key returns HTTP 404 with `trust_status: "unknown"`.

---

## 4. Verification & Validation Summary

| Test Suite / Tool | Command | Result |
|---|---|---|
| Backend Config Tests | `go -C backend test ./internal/config/...` | PASS (0.77s) |
| Backend Crypto Tests | `go -C backend test ./internal/crypto/...` | PASS (1.17s) |
| Backend Handlers Tests | `go -C backend test ./internal/handlers/...` | PASS (3.21s) |
| Full Backend Test Suite | `go -C backend test ./...` | PASS (all packages) |
| Go Vet | `go -C backend vet ./...` | 0 errors |
| Go Formatting | `gofmt -l backend/internal/crypto/signing.go ...` | 100% compliant |
| Frontend Vitest Suite | `npm --prefix frontend test` | PASS (10 files, 42 tests) |

---

## 5. Scope Invariant Adherence

- **BB-SEC-001 scope only**: No modifications were made to room deletion (BB-SEC-002), file uploads (BB-SEC-003), room passwords (BB-SEC-004), webhooks (BB-SEC-009), or token comparison (BB-SEC-008).
- **Zero secrets logged or exposed**: No private key material has been logged, printed, or exposed.
- **Repository hygiene preserved**: Pre-existing working tree modifications and forensic archives remain intact.

---

## 6. Next Steps

With Checkpoint 1B.2 complete, audited, and tested, the signing-key architecture is robust, defensible, and ready for deployment.

Awaiting user approval before proceeding to the next checkpoint.
