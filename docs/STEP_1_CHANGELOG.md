# BurnerBox — Step 1 Remediation Changelog

This document tracks all controlled security remediations, repository hygiene improvements, and architectural patches implemented during Step 1.

---

## [Checkpoint 1B] — 2026-11-19: Ed25519 Signing Key Security Implementation (BB-SEC-001)

### Fixed
- **BB-SEC-001 (Critical: Exposed Ed25519 Private Signing Key)**:
  - Eliminated on-disk plaintext private-key persistence across all code paths.
  - Removed `backend/internal/handlers/data/proof_key.json` from the repository working tree.
  - Added targeted `.gitignore` rules for `backend/internal/handlers/data/proof_key.json`, `**/proof_key.json`, `*.key`, `*.pem`, `*.priv`, `*.tar.gz`, and archive bundles.
  - Classified the exposed legacy private key as permanently compromised.

### Added
- **Versioned Public-Key Verification Registry (`backend/internal/crypto/signing.go`)**:
  - Implemented `crypto.SigningRegistry` and `crypto.GlobalRegistry`.
  - Added support for active keys, retired historical keys, and compromised keys.
  - Added explicit systemic trust states: `trusted`, `untrusted`, `unknown`.
  - Added deterministic 16-hex public-key fingerprint derivation ($H(\text{PublicKey})[0:8]$).
  - Automatically derives the public key from the configured private key, preventing mismatched key configuration.
  - Added validated Base64 parsing for both 32-byte seeds (`ed25519.NewKeyFromSeed`) and 64-byte Ed25519 private keys.
- **Fail-Fast Production Startup Validation (`backend/internal/config/config.go`)**:
  - Enforced mandatory `PROOF_SIGNING_PRIVATE_KEY` in production (`ENVIRONMENT=production` or `FLY_APP_NAME` set). The server terminates immediately (`log.Fatalf`) if the key is missing or malformed.
  - Strictly prohibited ephemeral key generation in production.
- **In-Memory Ephemeral Development & Test Keys**:
  - Local development without configured secrets automatically generates an ephemeral in-memory Ed25519 keypair with zero disk writes.
  - Automated tests explicitly initialize ephemeral in-memory keys via `InitProofSystemForTest(t)` or `InitTestKey()`.
- **Public Key Auditing Endpoints (`backend/cmd/server/main.go`, `backend/internal/handlers/proof.go`)**:
  - `GET /api/v1/proof-key`: Backward-compatible active public key endpoint returning `{ public_key, fingerprint, key_id, trust_status }`.
  - `GET /api/v1/proof-keys`: Returns all registered verification keys (active and historical). Exposes public material only.
  - `GET /api/v1/proof-keys/:id`: Looks up public verification metadata by KeyID or Fingerprint. Returns `trust_status: "untrusted"` for the compromised legacy key and `404` with `trust_status: "unknown"` for unrecognized keys.
- **Automated Test Suites**:
  - `backend/internal/crypto/signing_test.go`: Tests for key parsing, public key derivation, fingerprint determinism, signing/verification, historical/compromised status, and zero disk writes.
  - `backend/internal/handlers/proof_test.go`: Integration tests for production validation, fail-fast behavior, dev ephemeral mode, API compatibility, and receipt verification.

### Changed
- `backend/internal/handlers/proof.go`: Refactored to delegate signing and verification to `crypto.GlobalRegistry`. Excised `os.WriteFile` and `os.ReadFile` disk operations.
- `backend/internal/handlers/merkle.go`: Refactored `SealMerkleBatch` to sign Merkle roots via `crypto.GlobalRegistry.Sign`. Updated root publishing and inclusion proof endpoints to resolve keys from the registry.
- `backend/internal/handlers/test_helper_test.go`: Refactored test fixture to initialize in-memory test keys via `InitProofSystemForTest(t)`.
- `backend/fly.toml` & `docs/DEPLOYMENT.md`: Updated deployment documentation and Fly.io configuration to include `PROOF_SIGNING_PRIVATE_KEY` and `PROOF_SIGNING_KEY_ID`.

---

## [Checkpoint 1B.2] — 2026-11-19: Signing Registry Hardening and Environment Classification (BB-SEC-001 Corrective)

### Fixed
- **Collision Protection in Verification Registry (`backend/internal/crypto/signing.go`)**:
  - Enforced single active key constraint (`r.activePriv != nil` check). Setting a second active key returns an active key collision error.
  - Rejection of duplicate KeyIDs in `SetActiveKey` and `RegisterHistoricalKey`.
  - Rejection of duplicate fingerprints in `SetActiveKey` and `RegisterHistoricalKey`.
  - Rejection of active or historical collisions with built-in legacy compromised entry (`bb-legacy-compromised-2026` / `655029f24bebd724`).
  - Rejection of historical keys configured with `Role == KeyRoleActive`.
  - Guaranteed that registry lookup maps (`keysByID`, `keysByFp`) are never overwritten silently.
  - Clear, structured error messages without exposing private material.

### Added
- **Defensible Historical Trust Classification & Verification Separation (`backend/internal/crypto/signing.go`)**:
  - Formally separated mathematical signature verification from operational trust classification.
  - Added `VerifySignature(identifier, data, sig)` returning `(mathValid bool, trust TrustStatus, vk *VerificationKey)`.
  - Omitted `trust_status` on retired keys now defaults to `TrustStatusUnknown` (not `trusted`).
  - Omitted `trust_status` on compromised keys defaults to `TrustStatusUntrusted`.
  - Rejection of compromised keys configured with `TrustStatusTrusted`.
  - Rejection of invalid `trust_status` string values.
  - Added `Reset()` method to safely restore the registry to its default built-in state.
- **Production-Like Environment Enforcement (`backend/internal/config/config.go`, `backend/internal/handlers/proof.go`)**:
  - Added `config.IsProductionLikeEnvironment(env string) bool` covering `production`, `prod`, `staging`, `stage`, `preview`, `live`, and cloud host variables (`FLY_APP_NAME`, `KUBERNETES_SERVICE_HOST`, `RENDER`, `RAILWAY_ENVIRONMENT`, `AWS_EXECUTION_ENV`, `HEROKU_APP_ID`, `DYNO`, `GAE_APPLICATION`, `K_SERVICE`).
  - Preserved explicit developer override (`development`, `dev`, `testing`, `test`, `local`) during local emulation.
  - Mandatory fail-fast startup: `PROOF_SIGNING_PRIVATE_KEY` is required in all production-like environments; ephemeral generation is strictly forbidden.
  - Fail-fast configuration validation: malformed JSON or key collisions in `PROOF_HISTORICAL_PUBLIC_KEYS` immediately fail boot in production-like environments.
- **Audit Endpoint Lookup Semantics (`backend/internal/handlers/proof.go`)**:
  - `GET /api/v1/proof-keys/:id` returns HTTP 200 with `trust_status: "unknown"` for registered keys with unknown provenance.
  - Returns HTTP 404 with `trust_status: "unknown"` for unregistered keys.
- **Automated Test Coverage**:
  - `backend/internal/crypto/signing_test.go`: Added `TestSigningRegistry_CollisionRejection`, `TestSigningRegistry_HistoricalTrustClassification`, and `TestSigningRegistry_VerifySignature_TrustSeparation`.
  - `backend/internal/config/config_test.go`: Added comprehensive testing for `TestIsProductionLikeEnvironment`.
  - `backend/internal/handlers/proof_test.go`: Added `TestInitProofSystem_ProductionLikeEnvironments` and historical unknown trust endpoint assertions.

---

## [Checkpoint 1B.4] — 2026-11-19: Final Signing Security Corrections (BB-SEC-001 Conclusion)

### Fixed
- **Cloud Environment Downgrade Prevention (`backend/internal/config/config.go`)**:
  - Enforced that cloud platform indicators (`FLY_APP_NAME`, `KUBERNETES_SERVICE_HOST`, `RENDER`, `RAILWAY_ENVIRONMENT`, `AWS_EXECUTION_ENV`, `HEROKU_APP_ID`, `DYNO`, `GAE_APPLICATION`, `K_SERVICE`) unconditionally override `ENVIRONMENT=development` and `dev`.
  - Added `DetectCloudPlatformWithLookup` and `IsProductionLikeEnvironmentWithLookup` to enable deterministic testing without mutating process-global environment variables.
  - Updated `config.Load()` to default `AppConfig.Environment` to `"production"` when cloud indicators are present and `ENVIRONMENT` is unset or set to development/local.
- **Atomic Signing Registry Initialization (`backend/internal/handlers/proof.go`)**:
  - Re-architected `InitProofSystem` to build candidate registries locally in isolated memory.
  - Added `registryInitMu sync.Mutex` serialization to prevent concurrent initialization races.
  - `crypto.GlobalRegistry` and package globals are now updated atomically **only** if active key validation, parsing, fingerprint derivation, and historical key checks all succeed with zero errors.
  - Any failure at any initialization stage aborts immediately, leaving `crypto.GlobalRegistry` and globals untouched and uncorrupted.
- **Narrowed `.gitignore` Exclusions (`.gitignore`)**:
  - Replaced broad wildcard exclusions (`*.key`, `*.pem`, `*.priv`, `*.tar.gz`) with targeted rules for known project secrets and the specific forensic archives (`pre_remediation_checkpoint0.tar.gz`, `pre_remediation_*.tar.gz`, `BurnerBox_Project_Source_with_Master_Blueprint.zip`).
  - Preserved strict protection for `proof_key.json` and private keys while allowing non-secret assets like public certificates and localization files.

### Added
- **Automated Regression Tests**:
  - `backend/internal/config/config_test.go`: Added `TestIsProductionLikeEnvironmentWithLookup` verifying all cloud indicators override `development`, `dev`, `local`, and `""`. Added `TestIsProductionLikeEnvironment_ProcessEnv` verifying process environment integration with snapshotting and restoration.
  - `backend/internal/handlers/proof_test.go`: Added `TestInitProofSystem_AtomicPublicationOnFailure` asserting that failures at Stage A (malformed key), Stage B (missing key in prod), Stage C (legacy active key collision), Stage D (malformed historical JSON), and Stage E (historical key collision) do not alter or partially expose `crypto.GlobalRegistry`.

---

## [Checkpoint 2B] — 2026-11-19: Room Deletion Authorization Implementation (BB-SEC-002)

### Fixed
- **BB-SEC-002 (High Severity: Unauthenticated DELETE /api/v1/rooms/:code)**:
  - Eliminated unauthenticated room deletion endpoint vulnerability.
  - Implemented 256-bit cryptographically secure creator capability tokens (`bb_rt_<64hex>`) generated via `crypto/rand`.
  - Implemented SHA-256 hash-only storage in PostgreSQL and models (`creator_token_hash VARCHAR(64) NOT NULL DEFAULT ''`, `json:"-"`).
  - Implemented constant-time token verification (`subtle.ConstantTimeCompare`) in `DestroyRoom`.
  - Implemented fail-closed protection for legacy unmanaged rooms (`CreatorTokenHash == "" -> 403 Forbidden`).
  - Implemented deterministic PostgreSQL row locking (`SELECT ... FOR UPDATE`) via GORM `clause.Locking{Strength: "UPDATE"}` with `RowsAffected == 1` assertion and transactional cascade deletion (`RoomFile`, `RoomReaction`, `RoomMessage`, `Room`).
  - Serialized concurrent deletion outcomes: 1st valid deletion returns `200 OK`, waiting deletion returns `404 Not Found`, waiting deletion on reused code authenticates against the new generation (`403 Forbidden` for old token).

### Added
- **Generation-Safe In-Memory WebSocket Hub Lifecycle (`backend/internal/handlers/rooms_ws.go`)**:
  - Bound immutable database `roomID uuid.UUID` and `destroyed bool` into `wsHub`.
  - Implemented `destroyedRooms map[string]roomTombstone` with 10-minute TTL and background janitor sweep (`startTombstoneJanitor`).
  - Enforced bounded join handshake duration (`MaxJoinHandshakeDuration = 15 * time.Second`).
  - Implemented atomic client registration (`registerClientAtomic`) enforcing strict $L_1 (\text{roomHubsMu}) \rightarrow L_2 (\text{hub.mu})$ lock hierarchy, candidate hub local construction (deferred publication and deferred goroutine spawn), and double context check (`ctx.Err()`) to prevent empty orphan hubs or leaked goroutines.
  - Implemented generation-safe `CloseRoomHubAtomic` verifying `hub.roomID == roomID`; stale invalidation events for older room generations are harmless no-ops.
  - Implemented PostgreSQL `LISTEN / NOTIFY` broadcast and fail-safe periodic database reconciler (`reconcileActiveRoomHubs`) where query errors immediately abort without false disconnections.
- **Frontend Creator Capability Retention & Management (`frontend/src/routes/room/`)**:
  - Captured and stored creator token in `sessionStorage` (`bb_creator_token_${roomCode}`) upon room creation in `create/+page.svelte`.
  - Added "🔥 Burn Room" action in `[code]/+page.svelte` when creator token exists in tab `sessionStorage`.
  - Handled `room_destroyed` WebSocket control events by clearing storage and returning to home.
  - Formally documented same-origin `sessionStorage` XSS residual risk boundary.
- **Automated Security Test Suite (`backend/internal/handlers/room_lifecycle_test.go`)**:
  - Implemented all 24 security test cases (`SEC-TEST-201` through `SEC-TEST-224`): unauthenticated denial, invalid token denial, valid deletion, 404 on nonexistent room, cross-room token isolation, alternative header support, password protection enforcement, cascade deletions, active WebSocket severance, concurrent deletion idempotency, response contract verification, lost token handling, legacy fail-closed, token absence audit, atomic registration race interleavings, rollback safety, PostgreSQL migration driver scan tests, tombstone janitor sweep, safe reconciliation failure, generation-safe invalidation on code reuse, and deterministic concurrency serialization.

### Changed
- `backend/internal/models/room.go`: Added `CreatorTokenHash` field mapping to `creator_token_hash`.
- `backend/internal/handlers/rooms.go`: Updated `CreateRoom` to return `CreatorToken` in response; updated `DestroyRoom` to require authorization; updated `PurgeExpiredRoomsAt` to trigger `CloseRoomHubAtomic`.
- `backend/cmd/server/main.go`: Registered `StartRoomLifecycleWorkers()`.
- `backend/internal/handlers/test_helper_test.go`: Updated SQLite in-memory test database schema to declare `creator_token_hash TEXT NOT NULL DEFAULT ''`.
- `docs/STEP_2A_ROOM_DELETION_SECURITY_DESIGN.md`: Updated Section 7.1 concurrent deletion outcomes table.
- `docs/STEP_2B_ROOM_DELETION_IMPLEMENTATION_REPORT.md`: Comprehensive implementation report created.
