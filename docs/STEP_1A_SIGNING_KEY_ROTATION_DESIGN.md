# Step 1A: Signing Key Security Investigation and Rotation Design (BB-SEC-001)

**Document Version:** 1.1.0 (Revised per Security Review 1A.1)  
**Status:** Under Review (Awaiting User Approval)  
**Author:** Senior Application Security & Systems Architect  
**Classification:** Defensive Security Architecture  
**Target:** Ed25519 Proof-of-Submission & Merkle Log Signing Subsystem  

---

## 1. Executive Summary & Problem Statement

During the Phase 0 Security Audit, an active Ed25519 private signing key was identified on disk at `backend/internal/handlers/data/proof_key.json` and was found bundled in the source archive `BurnerBox_Project_Source_with_Master_Blueprint.zip`.

This key is used by the BurnerBox backend to generate:
1. Non-repudiable **Proof-of-Submission** digital receipts for anonymous whistleblowers.
2. Digital signatures on hourly **Merkle Tree batch roots** published for public transparency.

Per the mandatory rules of engagement for **Checkpoint 1A and 1A.1**, this document establishes an exhaustive investigation of the current signing subsystem, analyzes repository and filesystem forensic evidence to establish production versus test usage, evaluates three key-management architectures, and defines an active-to-historical key rotation framework.

**Zero code modifications, file deletions, key generation, or git history alterations have been made during this checkpoint.**

---

## 2. Investigation Findings & Current Architecture

### 2.1 File & Code Inspection Inventory

The following files and paths were thoroughly inspected in the codebase:

| File Path | Component | Role in Signing / Verification |
|---|---|---|
| `backend/internal/handlers/proof.go` | Proof Handler | Defines key persistence, startup initialization (`LoadOrGenerateProofKey`), receipt generation (`GenerateProofOfSubmission`), and public key endpoint (`GetProofPublicKey`). |
| `backend/internal/handlers/merkle.go` | Merkle Log Handler | Signs batch root hashes (`SealMerkleBatch`), embeds public key & fingerprint in published roots (`GetPortalMerkleRoots`) and inclusion proofs (`GetSubmissionInclusionProof`). |
| `backend/internal/handlers/submission.go` | Submission Ingestion | Invokes `GenerateProofOfSubmission` upon tip receipt (lines 393–419), links receipt to active Merkle batch. |
| `backend/cmd/server/main.go` | Entry Point | Calls `handlers.LoadOrGenerateProofKey()` on server boot (line 38); registers `GET /api/v1/proof-key` (line 117). |
| `backend/internal/handlers/test_helper_test.go` | Test Fixture | Calls `LoadOrGenerateProofKey()` in `setupTestDB()` (line 29), causing creation of `proof_key.json` during test runs. |
| `backend/internal/models/merkle.go` | Database Model | Defines `models.MerkleBatch` containing `Signature` (`text`) and `KeyFingerprint` (`varchar(32)`). |
| `frontend/static/verify-receipt.html` | Offline Verifier | Standalone HTML/JS tool that parses receipt JSON, reconstructs Merkle path, and validates Ed25519 signature over root hash using Web Crypto API. |
| `scripts/verify-receipt.html` | Offline Verifier | Duplicate standalone verifier script. |
| `frontend/src/tests/merkle_receipt_verification.test.js` | Frontend Vitest | Tests Merkle path verification and receipt schema parsing. |
| `backend/internal/config/config.go` | Config Loader | Loads configuration from environment. **Omission verified:** contains no variables or logic for proof signing keys. |
| `backend/Dockerfile` | Container Build | Builds Alpine container image. Copies only `/server` and `./docs`. Does not copy `data/proof_key.json`. |
| `backend/fly.toml` | Fly.io Deployment | Mounts volume only at `/app/uploads`. Does not persist `/app/data`. |
| `docs/DEPLOYMENT.md` | Deployment Guide | Documents `DATABASE_URL`, `JWT_SECRET`, `TOTP_ENCRYPTION_KEY`, `FILE_ENCRYPTION_KEY`. **Omission verified:** proof signing key is completely undocumented. |

---

### 2.2 Forensic Evidence: Usage & Production History Determination

To determine whether the legacy key was used in production, local tests, or development, we examined filesystem metadata, Git history, Docker configuration, and test fixtures.

#### A. Filesystem Timestamps & Git Commit Correlation
- **Git Commit History**: The repository has exactly one commit (`191e137`) dated `2026-08-23 11:48:11 +0530`.
- **`proof_key.json` Timestamp**:
  - File Creation Time: `2026-08-27 20:32:47`
  - Last Modification Time: `2026-08-27 20:32:47`
  - File Size: `166 bytes`
- **Correlated File Modifications on 2026-08-27**:
  Files modified on the same evening within the same hour include:
  - `no_ip_logging_test.go` (20:10:20)
  - `dms_test.go` (20:17:04)
  - `go.mod` / `go.sum` (20:27:10)
  - `rooms.go` / `room_lifecycle_test.go` (20:29:38)
  - **`backend/internal/handlers/data/proof_key.json` (20:32:47)**
  - `session.go` / `organization.go` / `jwt.go` / `auth.go` (20:52)
  - `submission_settings_test.go` (20:56:08)
  - `rbac_test.go` (20:56:54)

#### B. Working Directory & Path Traversal Proof
In `backend/internal/handlers/proof.go`:
```go
const proofKeyFile = "data/proof_key.json"
```
- **Go Test Execution**: When `go test ./internal/handlers/...` executes, the Go test harness sets the current working directory (`os.Getwd()`) to the package directory being tested: `E:\burnerbox\backend\internal\handlers`.
- Because `setupTestDB()` in `test_helper_test.go:29` calls `LoadOrGenerateProofKey()`, the relative path `data/proof_key.json` resolved to `backend/internal/handlers/data/proof_key.json`.
- **Server Execution**: When the backend server is run via `go run ./cmd/server` or `./server` from the root of `backend/`, the working directory is `backend/`. The path `data/proof_key.json` resolves to `backend/data/proof_key.json`.
- **Verification on Disk**: `backend/data/` **does not exist** on disk (`Test-Path "backend/data"` returned `False`).
  This proves that running the server binary from `backend/` could not have loaded `backend/internal/handlers/data/proof_key.json`.

#### C. Production Deployment & Container Inspection
- **`backend/Dockerfile`**:
  ```dockerfile
  COPY --from=builder /server .
  COPY --from=builder /app/docs ./docs
  RUN mkdir -p uploads/submissions && chown -R appuser:appgroup /app
  ```
  The Dockerfile copies only the compiled binary `/server` and `./docs`. It does **not** copy `data/` or `internal/handlers/data/`.
- **`backend/fly.toml`**:
  ```toml
  [mounts]
    source = "burnerbox_uploads"
    destination = "/app/uploads"
  ```
  Only `/app/uploads` is mounted to persistent storage. `/app/data` is unmounted and ephemeral.
- **`backend/internal/config/config.go` & `docs/DEPLOYMENT.md`**:
  No configuration variable or secret existed for the proof signing key.

#### D. Production Usage Classification

| Assessment Category | Finding | Classification |
|---|---|---|
| **Local Unit Tests** | Conclusively generated by `test_helper_test.go` during test runs on 2026-08-27 at 20:32:47. | **Verified development/test use only** |
| **Local Dev Server** | Would only load this key if launched with working directory set explicitly to `backend/internal/handlers`. Running from `backend/` or repository root creates or looks for `backend/data/proof_key.json` (which does not exist). | **No evidence of dev server use** |
| **Container / Fly.io Deployments** | Docker image excludes `data/` directory; `fly.toml` does not persist `/app/data`. If deployed, container generated ephemeral keys on each boot. | **No evidence of production deployment with this key** |
| **Production Databases / Receipts** | No production databases or historical receipt logs exist in the repository. | **Unknown — insufficient evidence regarding remote live servers** |
| **External Distribution** | The source archive `BurnerBox_Project_Source_with_Master_Blueprint.zip` contained the file, making the private key publicly accessible to anyone with archive access. | **Public Exposure Confirmed** |

**Formal Verdict:**
- Within all available repository source code, build scripts, local records, and container configurations: **Verified development/test use only**.
- Regarding external or remote production environments not captured in the repository: **Unknown — insufficient evidence**.

---

### 2.3 Exact Data Signed by the Key

The Ed25519 key signs two distinct data structures:

#### A. Proof-of-Submission Receipts (`GenerateProofOfSubmission`)
- **Signed Payload**: The raw 32-byte SHA-256 hash of the submission's encrypted payload:
  $$\text{PayloadHash} = \text{SHA-256}(\text{EncryptedPayload})$$
  $$\text{Signature} = \text{Ed25519Sign}(\text{PrivateKey}, \text{PayloadHash}[0:32])$$
- **Format**: Deterministic 64-byte Ed25519 binary signature, encoded as standard Base64.
- **Fingerprint**: The first 8 bytes of the SHA-256 of the raw public key, formatted as 16 hexadecimal characters:
  $$\text{Fingerprint} = \text{Hex}(\text{SHA-256}(\text{PublicKey})[0:8])$$
- **Return Object**:
  ```json
  {
    "submission_id": "c7a8...",
    "hash": "<64-char hex of payload hash>",
    "signature": "<base64 ed25519 signature over 32 raw hash bytes>",
    "timestamp": "2026-11-19T21:40:00Z",
    "key_fingerprint": "<16-char hex>",
    "server_public_key": "<base64 32-byte public key>"
  }
  ```

#### B. Merkle Log Batch Roots (`SealMerkleBatch`)
- **Signed Payload**: The 64-character ASCII hexadecimal string representation of the computed Merkle root:
  $$\text{RootHex} = \text{HexEncode}(\text{ComputeMerkleRoot}(\text{Leaves}))$$
  $$\text{RootSignature} = \text{Ed25519Sign}(\text{PrivateKey}, []\text{byte}(\text{RootHex}))$$
- **Cryptographic Distinction**: While the submission receipt signs the **32 raw bytes** of the SHA-256 hash, the Merkle batch sealing signs the **64 ASCII bytes** of the hex-encoded root string.
- **Database Persistence**: Stored in PostgreSQL `merkle_batches` table under `root_hash`, `signature`, and `key_fingerprint`.

---

### 2.4 Existing Receipt Verification & Key Identifiers

1. **Receipt Verification Flow**:
   - Implemented in `frontend/static/verify-receipt.html` and `scripts/verify-receipt.html`.
   - Reconstructs RFC 6962 leaf hash ($H(0x00 \mathbin{\Vert} \text{PayloadHash})$) and interior nodes ($H(0x01 \mathbin{\Vert} \text{Left} \mathbin{\Vert} \text{Right})$).
   - Validates that the reconstructed root matches `root_hash`.
   - Validates the Ed25519 signature over `root_hash` using `server_public_key` via Web Crypto API.
2. **Key Identifiers**:
   - `key_fingerprint` (16-char hex string derived from public key SHA-256) is stored in the database (`merkle_batches.key_fingerprint`) and returned in receipts.
   - An explicit, versioned `key_id` (e.g. `bb-prod-2026-v1`) is not yet formalized.
   - The server only supports **one** in-memory public key; rotating the key without a registry breaks verification of previously issued receipts against `GET /api/v1/proof-key`.

---

## 3. Policy on Historical Public-Key Retention & Compromised Keys

A critical principle of cryptographic assurance governs this design:

> **Fundamental Invariant:**  
> A signature that verifies cryptographically does **not** establish that it was generated by a trustworthy server after the key became compromised.  
> Cryptographic verification $\neq$ Systemic trust.

We establish explicit policies categorizing receipts and key status:

### 3.1 Categorization and Treatment of Receipts

```
                                  Receipt Verification Request
                                                │
                                                ▼
                                    Lookup Key by Fingerprint
                                                │
                       ┌────────────────────────┼────────────────────────┐
                       ▼                        ▼                        ▼
               Key Role: Active         Key Role: Retired       Key Role: Compromised
                       │                        │                        │
                       ▼                        ▼                        ▼
             Cryptographically Valid   Cryptographically Valid   Cryptographically Valid
                       +                        +                        BUT
                FULLY TRUSTED            HISTORICALLY VALID        UNTRUSTED / REJECTED
```

1. **Production Receipts**:
   - Receipts signed by an active or retired production key during its designated validity window (`valid_from` to `retired_at`).
   - Treated as **fully valid and trustworthy**.
2. **Development Receipts**:
   - Generated during local developer runs using ephemeral keys.
   - Transient; no long-term trust guarantee.
3. **Test Receipts**:
   - Generated in-memory during unit or integration test runs.
   - Scoped strictly to the lifetime of the test process. Must never enter persistent production databases.
4. **Merkle Batches**:
   - Sealed batches persisted in the database carry `key_fingerprint`.
   - Inclusion proof verification queries the key registry using that fingerprint.
5. **Compromised Keys (The Legacy Key `proof_key.json`)**:
   - Because the private key was distributed in an unencrypted archive, **any holder of the archive could forge valid Ed25519 signatures** over arbitrary submission hashes or Merkle roots.
   - Therefore, the legacy key must **never** be registered as a trusted historical production key.
   - If retained in non-production environments to allow historical test data to verify during development, it must be explicitly cataloged with:
     ```json
     {
       "key_id": "bb-legacy-compromised-testkey",
       "fingerprint": "8f3e2b1c0d9a4e7f",
       "role": "compromised",
       "valid_from": "2026-08-27T20:32:47Z",
       "retired_at": "2026-08-27T20:32:47Z",
       "description": "Exposed in source archive Aug 2026. Revoked and untrusted for production."
     }
     ```
   - In production environments, any receipt signed by this key will be flagged as:
     `❌ VERIFICATION REJECTED: Key is revoked/compromised. Signatures cannot be trusted.`

---

## 4. Comparison of Key Management Solutions

| Dimension | Option A: Environment Secret Store | Option B: Managed KMS / Cloud HSM | Option C: Versioned Registry with Secret Manager (Recommended) |
|---|---|---|---|
| **Mechanism** | Key injected via `PROOF_SIGNING_PRIVATE_KEY` env var. | Remote signing via AWS KMS, GCP Cloud KMS, or Vault RPC. | Active key injected via secret store; historical public keys maintained in a typed registry; abstract `Signer` interface. |
| **Security of Private Key** | Stored in process memory. Host/container isolated. | Private key never leaves HSM hardware. Highest at-rest protection. | Local/Dev: In-memory; Prod: Secret manager (Fly/AWS/Vault). Zero keys on disk. |
| **Operational Simplicity** | Simple; zero third-party dependencies; high signing throughput (~50,000 ops/sec). | Complex setup; requires cloud provider IAM, network routing, and egress configuration. | Self-contained in Go binary with zero external runtime dependencies for standard deployments. |
| **Air-Gap / Self-Hosted Fit** | Excellent. Works on local machines, VPS, bare metal, and Tor hidden services. | Poor. Requires active internet connectivity to AWS/GCP, breaking air-gap and Tor setups. | Excellent. Standard deployments run standalone; enterprise can plug in KMS. |
| **Latency & Availability** | Zero latency (<0.1ms per sign); 100% availability without network failure modes. | Network round-trip per sign (15–80ms); fails if KMS network endpoint is unreachable. | Sub-millisecond signing; zero network dependency during user submissions. |
| **Historical Verification** | Fragile unless multiple env vars are manually parsed. | KMS versions public keys, but public retrieval requires API calls or caching. | Built-in: Registry indexes active + retired keys by `key_fingerprint` and `key_id`. |
| **Cost** | Free ($0). | Per-request and per-key KMS monthly fees. | Free ($0). |

---

## 5. Refined Production Key Management Architecture

We adopt **Option C: A Versioned Signing-Key Registry with Secret Manager Ingestion**.

```
   ┌────────────────────────────────────────────────────────────────────────┐
   │                       BurnerBox Backend Process                        │
   │                                                                        │
   │  ┌──────────────────────────────────────────────────────────────────┐  │
   │  │                      SigningKeyRegistry                          │  │
   │  │                                                                  │  │
   │  │  [Active Signer]                                                 │  │
   │  │  Key ID:      bb-prod-2026-v1                                    │  │
   │  │  Fingerprint: <derived 16-hex>                                   │  │
   │  │  Private Key: [Loaded from PROOF_SIGNING_PRIVATE_KEY secret]     │  │
   │  │  Public Key:  [DERIVED AUTOMATICALLY via priv.Public()]          │  │
   │  │  Role:        active                                             │  │
   │  │                                                                  │  │
   │  │  [Historical Verification Keys]                                  │  │
   │  │  Key 1: ID: bb-prod-2025-v1 | Fingerprint: 4f1a... | retired     │  │
   │  │  Key 2: ID: bb-legacy-test  | Fingerprint: 8f3e... | compromised │  │
   │  └──────────────────┬───────────────────────────────┬───────────────┘  │
   └─────────────────────┼───────────────────────────────┼──────────────────┘
                         │                               │
                  Sign New Batch                   Verify Old Receipt
                         │                               │
                         ▼                               ▼
                 Published Batch Root             Verified Inclusion Proof
```

### 5.1 Secret-Manager Ingestion & Automatic Public-Key Derivation

1. **Private Key Ingestion**:
   Injected via environment variable `PROOF_SIGNING_PRIVATE_KEY` populated by deployment secrets (e.g. `fly secrets set`, AWS Secrets Manager, Kubernetes Secret, HashiCorp Vault).
   - Format: Standard Base64-encoded 64-byte Ed25519 private key, or 32-byte seed.
2. **Automatic Public Key Derivation**:
   To prevent configuration errors where `PUBLIC_KEY` does not match `PRIVATE_KEY`, the application **derives the public key directly from the private key** at startup:
   ```go
   pubKey := privKey.Public().(ed25519.PublicKey)
   ```
   No separate `PROOF_SIGNING_PUBLIC_KEY` environment variable is required or permitted for the active key.
3. **Active Key ID & Stable Fingerprint**:
   - `PROOF_SIGNING_KEY_ID`: Operator-assigned string (e.g. `bb-prod-2026-v1`). If omitted, defaults deterministically to `key_<fingerprint>`.
   - `Fingerprint`: Computed deterministically as:
     $$\text{Fingerprint} = \text{Hex}(\text{SHA-256}(\text{DerivedPublicKey})[0:8])$$
     Always 16 lowercase hex characters, matching `merkle_batches.key_fingerprint`.
4. **Historical Verification Keys Registry**:
   Supplied via `PROOF_HISTORICAL_PUBLIC_KEYS` as a JSON string:
   ```json
   [
     {
       "key_id": "bb-prod-2025-v1",
       "public_key": "x2Y7...",
       "fingerprint": "4f1a2b3c4d5e6f70",
       "role": "retired",
       "valid_from": "2025-01-01T00:00:00Z",
       "retired_at": "2026-01-01T00:00:00Z"
     }
   ]
   ```

### 5.2 Strict Production Startup Validation (Fail-Fast)

In production (`ENVIRONMENT=production` or `FLY_APP_NAME` set):
- If `PROOF_SIGNING_PRIVATE_KEY` is missing or empty:
  ```
  FATAL: [SECURITY CONFIGURATION ERROR] PROOF_SIGNING_PRIVATE_KEY is missing.
  Production server cannot start without an authenticated proof signing key.
  Set this secret using your deployment secret manager.
  ```
  The process calls `log.Fatalf` and terminates with code 1.
- If `PROOF_SIGNING_PRIVATE_KEY` fails Base64 decoding or has invalid length ($\neq 64$ bytes and $\neq 32$ bytes):
  ```
  FATAL: [SECURITY CONFIGURATION ERROR] PROOF_SIGNING_PRIVATE_KEY is malformed.
  Must be a valid Base64-encoded Ed25519 private key or seed.
  ```
- **Prohibition on Ephemeral Keys in Production**:
  The application **must never silently generate an ephemeral key in production**. Ephemeral fallback is strictly confined to non-production development environments.

### 5.3 Routine Rotation & Rollback Procedures

#### A. Planned Key Rotation Procedure
1. **Generate New Keypair**: On an offline admin workstation:
   ```bash
   openssl genpkey -algorithm ed25519 -out new_key.pem
   ```
2. **Extract Material**: Extract Base64 private key and derive Base64 public key and fingerprint.
3. **Update Historical Registry**:
   Take the currently active public key, assign `"role": "retired"`, set `"retired_at"` to current UTC timestamp, and add it to `PROOF_HISTORICAL_PUBLIC_KEYS`.
4. **Deploy Secrets**:
   Update `PROOF_SIGNING_PRIVATE_KEY`, `PROOF_SIGNING_KEY_ID`, and `PROOF_HISTORICAL_PUBLIC_KEYS` in Fly.io / secret store:
   ```bash
   fly secrets set \
     PROOF_SIGNING_KEY_ID="bb-prod-2026-v2" \
     PROOF_SIGNING_PRIVATE_KEY="<new_base64_privkey>" \
     PROOF_HISTORICAL_PUBLIC_KEYS='[{"key_id":"bb-prod-2026-v1",...}]'
   ```
5. **Zero-Downtime Rollout**:
   The backend restarts with the new active key. Incoming submissions and next hourly Merkle batches are signed with `bb-prod-2026-v2`. Existing receipts continue to verify against `bb-prod-2026-v1` in the historical registry.

#### B. Rollback Procedure
If a newly deployed key causes operational issues:
1. Revert `PROOF_SIGNING_PRIVATE_KEY` and `PROOF_SIGNING_KEY_ID` to the previous key.
2. Remove the rolled-back key from `PROOF_HISTORICAL_PUBLIC_KEYS`.
3. Re-deploy secrets.

---

## 6. Refined Development & Testing Behavior

To eliminate repository leakage permanently:

1. **Zero Disk Writes**:
   - The logic in `proof.go` that writes to `proofKeyFile = "data/proof_key.json"` will be **completely removed**.
   - No signing private keys will ever be written to disk by any backend code.
2. **Development Environment**:
   - If `PROOF_SIGNING_PRIVATE_KEY` is present in local `.env`, use it.
   - If absent and `ENVIRONMENT != "production"`, generate an ephemeral in-memory Ed25519 keypair.
   - Log a conspicuous console warning: `[DEV ONLY] Ephemeral in-memory signing key generated. Receipts will not survive server restarts.`
3. **Automated Unit & Integration Tests**:
   - Tests will explicitly call an in-memory test initialization function: `InitTestSigningKey(t)` or `SetEphemeralSigningKey(priv, pub, keyID)`.
   - Tests will operate purely on in-memory state.
   - `test_helper_test.go` will be refactored to use in-memory key injection.
   - Test receipts generated during a test run will verify against the in-memory test public key within that test session.

---

## 7. Archive & Repository Hygiene Specification

### 7.1 Existing Archives Assessment
1. **`BurnerBox_Project_Source_with_Master_Blueprint.zip`**:
   - Contains: `burnerbox/backend/internal/handlers/data/proof_key.json` (timestamp `Aug 27 20:32`, length `166`).
   - Distribution Status: Internal handover archive. **Not intended for public distribution or production release.**
2. **`pre_remediation_checkpoint0.tar.gz`**:
   - Internal checkpoint backup created at Checkpoint 0 to guarantee exact baseline recoverability.
   - Not for distribution.
3. **Safety Constraint**: Per Checkpoint 1A instructions, **neither archive will be deleted or overwritten during this checkpoint**.

### 7.2 Sanitized Source Archive Production Procedure
When producing public release archives:
1. An explicit export script will be used:
   ```bash
   git archive --format=zip --prefix=burnerbox/ HEAD -o BurnerBox_Sanitized_Release.zip
   ```
2. Any untracked directories, development artifacts, and `.env` files are automatically excluded because `git archive` operates strictly on tracked Git tree objects.
3. A pre-release scan script will verify that no `.json` files containing `"private_key"` exist in the archive.

### 7.3 Precise Git Ignore Specification
To avoid broad patterns that could unintentionally ignore legitimate application data (such as database migrations, seed data, or static assets), the root `.gitignore` will be updated with **precise, targeted paths**:

```gitignore
# Cryptographic signing keys & secrets (BB-SEC-001)
backend/internal/handlers/data/proof_key.json
**/proof_key.json
*.key
*.pem
*.priv

# Local development archives
*.tar.gz
BurnerBox_Project_Source_with_Master_Blueprint.zip
```
Notice: A blanket `data/` rule is **explicitly avoided**.

---

## 8. Security Review Corrections and Outstanding Decisions

### 8.1 Categorized Evidence Matrix

| Fact / Finding | Classification | Evidence Base |
|---|---|---|
| Key generated on 2026-08-27 at 20:32:47 | **Verified Fact** | Filesystem timestamp of `proof_key.json` matches test files modified in the same commit window. |
| Key created by Go test runner | **Verified Fact** | `test_helper_test.go:29` calls `LoadOrGenerateProofKey()`; relative path `data/proof_key.json` resolved to `backend/internal/handlers/data/`. |
| Key never committed to Git | **Verified Fact** | `git log --all --full-history -- "**/proof_key.json"` returns 0 commits. |
| Key excluded from Docker build | **Verified Fact** | `Dockerfile` copies only `/server` and `./docs`; does not copy `data/` or `internal/handlers/data/`. |
| Fly.io does not mount `/app/data` | **Verified Fact** | `backend/fly.toml` mounts only `/app/uploads`. |
| Server from `backend/` cannot load key | **Verified Fact** | `backend/data/` does not exist on disk; running binary from `backend/` fails to find `data/proof_key.json`. |
| Public key derives from private key | **Verified Fact** | `crypto/ed25519` private key implements `Public()` method returning 32-byte public key. |
| No production receipts depend on key | **Assumption (High Probability)** | Based on absence of deployment configs, container exclusion, and test-only creation context. |
| Remote production server was never run manually from `handlers/` directory | **Unknown** | Cannot be proven without external server access logs; treated conservatively as compromised. |

---

### 8.2 Outstanding Decisions Requiring Approval Before Checkpoint 1B

1. **Compromised Key Treatment in Historical Registry**:
   - **Proposed Decision**: In non-production/development configurations, catalog the legacy key as `role: "compromised"` with `not_valid_after: "2026-08-27T20:32:47Z"`. In production configurations, omit it completely or return `400/403 Revoked` so forged receipts cannot be verified as legitimate production proofs.
   - *Confirmation Requested*: Confirm acceptance of this strict separation between cryptographic verification and production trust.
2. **Ephemeral In-Memory Dev Behavior**:
   - **Proposed Decision**: Remove all `os.WriteFile` logic. Local development without `PROOF_SIGNING_PRIVATE_KEY` generates an in-memory key on boot and never touches disk.
   - *Confirmation Requested*: Confirm that writing keys to disk should be completely eliminated across all environments.
3. **Approval to Proceed to Checkpoint 1B**:
   - Confirm that this revised design meets all architectural criteria and authorize proceeding to **Checkpoint 1B (Implementation)**.
