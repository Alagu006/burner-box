# BurnerBox — Checkpoint 1B.3: Final Security Review

**Date:** 2026-11-19  
**Review Scope:** Final Security & Correctness Audit of BB-SEC-001 (Ed25519 Signing Key & Verification Registry)  
**Status:** COMPLETE (READ-ONLY AUDIT & FINDINGS REPORT)  

---

## 1. Environment Variable Precedence & Classification Trace

### 1.1 Source Code Inspection (`backend/internal/config/config.go`)

In `backend/internal/config/config.go`, environment detection is handled across two functions: `Load()` and `IsProductionLikeEnvironment()`.

```go
// Line 33-56: backend/internal/config/config.go
func IsProductionLikeEnvironment(env string) bool {
	normalized := strings.ToLower(strings.TrimSpace(env))
	switch normalized {
	case "production", "prod", "staging", "stage", "preview", "live":
		return true
	}

	// Platform detection: if running on known hosting infrastructure and not explicitly "development" or "testing"
	if normalized != "development" && normalized != "dev" && normalized != "testing" && normalized != "test" && normalized != "local" {
		if os.Getenv("FLY_APP_NAME") != "" ||
			os.Getenv("KUBERNETES_SERVICE_HOST") != "" ||
			os.Getenv("RENDER") != "" ||
			os.Getenv("RAILWAY_ENVIRONMENT") != "" ||
			os.Getenv("AWS_EXECUTION_ENV") != "" ||
			os.Getenv("HEROKU_APP_ID") != "" ||
			os.Getenv("DYNO") != "" ||
			os.Getenv("GAE_APPLICATION") != "" ||
			os.Getenv("K_SERVICE") != "" {
			return true
		}
	}

	return false
}

// Line 65-71: backend/internal/config/config.go
rawEnv := getEnv("ENVIRONMENT", "")
env := "development"
if rawEnv != "" {
	env = rawEnv
} else if os.Getenv("FLY_APP_NAME") != "" {
	env = "production"
}
```

### 1.2 Exact Precedence Analysis

1. **In `config.Load()` (lines 65–71)**:
   - **First**: `ENVIRONMENT` is evaluated via `getEnv("ENVIRONMENT", "")`. If non-empty, `env` is assigned its exact string value.
   - **Second**: If `ENVIRONMENT` is empty, `FLY_APP_NAME` is evaluated. If non-empty, `env` defaults to `"production"`.
   - **Third**: If both are empty, `env` defaults to `"development"`.
   - *Note*: Other cloud variables (`KUBERNETES_SERVICE_HOST`, `RENDER`, `RAILWAY_ENVIRONMENT`, `AWS_EXECUTION_ENV`, `HEROKU_APP_ID`, `DYNO`, `GAE_APPLICATION`, `K_SERVICE`) are **not** checked in `Load()` for setting `AppConfig.Environment`.

2. **In `config.IsProductionLikeEnvironment(env string)` (lines 33–56)**:
   - **Step 1 (Explicit Production Tiers)**: If normalized `env` is `production`, `prod`, `staging`, `stage`, `preview`, or `live`, returns `true`.
   - **Step 2 (Development Exemption Filter)**: If normalized `env` is `development`, `dev`, `testing`, `test`, or `local`, line 41 evaluates to `false`. The entire block of cloud platform detectors (lines 42–52) is **bypassed**, and the function returns `false`.
   - **Step 3 (Cloud Platform Detectors)**: Only if `env` is **not** an explicit dev/test string and **not** a recognized production tier (e.g. `env == ""` or an unrecognized tier name), lines 42–52 evaluate the 9 cloud platform environment variables in order:
     1. `FLY_APP_NAME` (Fly.io)
     2. `KUBERNETES_SERVICE_HOST` (Kubernetes cluster)
     3. `RENDER` (Render.com)
     4. `RAILWAY_ENVIRONMENT` (Railway)
     5. `AWS_EXECUTION_ENV` (AWS ECS, Fargate, Lambda)
     6. `HEROKU_APP_ID` (Heroku)
     7. `DYNO` (Heroku dyno)
     8. `GAE_APPLICATION` (Google App Engine)
     9. `K_SERVICE` (Google Cloud Run / Knative)
   - **Step 4 (Default)**: Returns `false`.

---

## 2. Cloud-Hosted Environment Downgrade Demonstration

### 2.1 Vulnerability Finding: Cloud Ephemeral Key Downgrade

**Question:** Can any cloud-hosted environment set `ENVIRONMENT=development` and obtain an ephemeral signing key?  
**Result:** **YES. A cloud deployment can be downgraded to an ephemeral in-memory signing key.**

### 2.2 Proof of Vulnerability (Execution Trace)

Assume a container is deployed in Kubernetes (`KUBERNETES_SERVICE_HOST="10.96.0.1"`), Fly.io (`FLY_APP_NAME="burnerbox-api"`), or AWS ECS (`AWS_EXECUTION_ENV="AWS_ECS_FARGATE"`).

Suppose the deployment manifest sets:
```yaml
env:
  - name: ENVIRONMENT
    value: "development"
  # PROOF_SIGNING_PRIVATE_KEY is intentionally or accidentally omitted
```

Tracing the execution flow:
1. `config.Load()`:
   - Line 65: `rawEnv` is `"development"`.
   - Line 68: `env` becomes `"development"`.
   - Line 79: `AppConfig.Environment = "development"`.
   - Line 80: `AppConfig.ProofSigningPrivateKey = ""` (empty).
   - Line 123: `IsProductionLikeEnvironment(AppConfig.Environment)` is evaluated.
2. Inside `IsProductionLikeEnvironment("development")`:
   - Line 35: `switch normalized` does not match `"development"`.
   - Line 41: `normalized != "development"` evaluates to `false`.
   - Lines 42–52: **The platform detection block is skipped entirely!**
   - Line 55: `return false`.
3. Back in `config.Load()`:
   - Line 123: `if IsProductionLikeEnvironment(AppConfig.Environment)` evaluates to `false`.
   - Line 130: `else if AppConfig.ProofSigningPrivateKey != ""` evaluates to `false`.
   - `config.Load()` returns `AppConfig` successfully without error or panic.
4. In `handlers.InitProofSystem(AppConfig)`:
   - Line 30: `config.IsProductionLikeEnvironment(cfg.Environment)` evaluates to `false`.
   - Line 31: `isProd` is `false`.
   - Line 37: `cfg.ProofSigningPrivateKey != ""` is `false`.
   - Line 50: `else` branch executes.
   - Line 51: `if isProd` is `false`.
   - Line 54: `crypto.GlobalRegistry.InitDevEphemeralKey()` **executes**.
   - Line 57: Logs: `PROOF_KEY: Initialized ephemeral in-memory Ed25519 key (dev mode, zero disk writes)`.
   - `InitProofSystem` returns `nil`.

### 2.3 Impact
- The container successfully boots on managed cloud infrastructure with an ephemeral in-memory key.
- Whenever a pod restarts, crashes, or autoscales, a new random Ed25519 key is minted.
- All previously issued submission receipts and Merkle root proofs become unverifiable against the new key.
- An operator or compromised configuration can bypass the mandatory signing key requirement in production/staging cloud clusters simply by setting `ENVIRONMENT=development`.

---

## 3. Proposed Minimal Remediation & Regression Test

### 3.1 Proposed Fix: Authoritative Cloud Platform Detection

In `backend/internal/config/config.go`, cloud infrastructure detection must take unconditional precedence over developer convenience overrides. If running inside managed cloud infrastructure, setting `ENVIRONMENT=development` must **never** disable production signing requirements.

```go
// Smallest, safest correction in backend/internal/config/config.go:

func HasCloudPlatformIndicator() bool {
	return os.Getenv("FLY_APP_NAME") != "" ||
		os.Getenv("KUBERNETES_SERVICE_HOST") != "" ||
		os.Getenv("RENDER") != "" ||
		os.Getenv("RAILWAY_ENVIRONMENT") != "" ||
		os.Getenv("AWS_EXECUTION_ENV") != "" ||
		os.Getenv("HEROKU_APP_ID") != "" ||
		os.Getenv("DYNO") != "" ||
		os.Getenv("GAE_APPLICATION") != "" ||
		os.Getenv("K_SERVICE") != ""
}

func IsProductionLikeEnvironment(env string) bool {
	// Rule 1: Managed cloud infrastructure is unconditionally production-like.
	// Ephemeral key downgrade is strictly forbidden in the cloud.
	if HasCloudPlatformIndicator() {
		return true
	}

	// Rule 2: On local machines (no cloud indicators), check explicit environment tiers.
	normalized := strings.ToLower(strings.TrimSpace(env))
	switch normalized {
	case "production", "prod", "staging", "stage", "preview", "live":
		return true
	}

	return false
}
```

In `config.Load()`:
```go
	rawEnv := getEnv("ENVIRONMENT", "")
	env := "development"
	if rawEnv != "" {
		env = rawEnv
	} else if HasCloudPlatformIndicator() {
		env = "production"
	}
```

### 3.2 Regression Test

Add the following regression test to `backend/internal/config/config_test.go`:

```go
func TestIsProductionLikeEnvironment_PreventsCloudDevDowngrade(t *testing.T) {
	cloudVars := []string{
		"FLY_APP_NAME",
		"KUBERNETES_SERVICE_HOST",
		"RENDER",
		"RAILWAY_ENVIRONMENT",
		"AWS_EXECUTION_ENV",
		"HEROKU_APP_ID",
		"DYNO",
		"GAE_APPLICATION",
		"K_SERVICE",
	}

	for _, v := range cloudVars {
		orig := os.Getenv(v)
		defer os.Setenv(v, orig)
		os.Setenv(v, "active-cloud-indicator")

		// Verify that setting ENVIRONMENT=development or dev does NOT bypass production key enforcement
		if !IsProductionLikeEnvironment("development") {
			t.Errorf("SECURITY REGRESSION: Setting ENVIRONMENT=development allowed ephemeral downgrade under cloud host %s", v)
		}
		if !IsProductionLikeEnvironment("dev") {
			t.Errorf("SECURITY REGRESSION: Setting ENVIRONMENT=dev allowed ephemeral downgrade under cloud host %s", v)
		}
		os.Unsetenv(v)
	}
}
```

---

## 4. Inspection of `.gitignore` Exclusion Rules

### 4.1 Audit of Key & Archive Rules in `.gitignore`

Lines 53–62 of `.gitignore`:
```gitignore
# Cryptographic signing keys & local secrets (BB-SEC-001)
backend/internal/handlers/data/proof_key.json
**/proof_key.json
*.key
*.pem
*.priv

# Local archives
*.tar.gz
BurnerBox_Project_Source_with_Master_Blueprint.zip
```

### 4.2 Necessity & Scope Evaluation

| Rule | Evaluation | Risk / Impact | Narrower Alternative | Recommendation |
|---|---|---|---|---|
| `backend/internal/handlers/data/proof_key.json` | **Exact & Necessary** | Directly matches the original leaked file location. | None needed. | **Keep** |
| `**/proof_key.json` | **Targeted & Necessary** | Protects against any recreated `proof_key.json` in any package or subfolder. | None needed. | **Keep** |
| `*.key` | **Broad** | Intended to catch private key exports (`ed25519.key`, `server.key`). However, it globally excludes any file ending in `.key` (e.g. potential future translation keys, licensing files). | `**/*_private*.key`, `secrets/**/*.key`, `data/**/*.key` | **Retain as defense-in-depth** unless a tracked `.key` file is introduced. No `.key` files currently exist in the repository. |
| `*.pem` | **Broad** | Blocks all PEM files, including public certificates (e.g. public CA roots, self-signed test certificates, public HTTPS chains). | `**/*private*.pem`, `**/*.priv.pem`, `secrets/**/*.pem` | **Refine if public cert fixtures are added**; currently no PEM files exist in the repo. |
| `*.priv` | **Targeted** | Excludes private key dumps. | `*.priv.key`, `**/*_private*` | **Keep** |
| `*.tar.gz` | **Broad** | Intended to protect the forensic archive `pre_remediation_checkpoint0.tar.gz`. Wildcard `*.tar.gz` excludes any gzipped tar archive. | `pre_remediation_checkpoint0.tar.gz` | **Refine to explicit filename** while keeping general archive rule in root if desired. |
| `BurnerBox_Project_Source_with_Master_Blueprint.zip` | **Exact & Necessary** | Targets the exact forensic archive containing the original source and blueprint. | None needed. | **Keep** |

---

## 5. Registry Initialization Order & Atomic Exposure Audit

### 5.1 Verification of Initialization Steps

1. **Built-in compromised key registered first**:
   - **Verified**: `crypto.NewSigningRegistry(isProduction bool)` ([signing.go#L126-L135](file:///e:/burnerbox/backend/internal/crypto/signing.go#L126-L135)) explicitly invokes `r.registerBuiltinLegacyKey()` at line 133 inside the constructor.
   - The compromised key (`bb-legacy-compromised-2026`, fingerprint `655029f24bebd724`) is inserted into `keysByID` and `keysByFp` before any other key can be configured.
2. **Active key registered without collisions**:
   - **Verified**: `SetActiveKey` ([signing.go#L174-L229](file:///e:/burnerbox/backend/internal/crypto/signing.go#L174-L229)):
     - Line 191: Rejects second active key (`r.activePriv != nil`).
     - Line 196: Rejects collisions with legacy KeyID or Fingerprint.
     - Line 201: Rejects duplicate KeyID in `keysByID`.
     - Line 206: Rejects duplicate Fingerprint in `keysByFp`.
3. **Historical keys registered without collisions**:
   - **Verified**: `RegisterHistoricalKey` ([signing.go#L234-L304](file:///e:/burnerbox/backend/internal/crypto/signing.go#L234-L304)):
     - Line 246: Rejects `Role == KeyRoleActive`.
     - Line 258: Rejects collisions with legacy KeyID or Fingerprint.
     - Lines 265–283: Enforces valid trust status metadata.
     - Line 289: Rejects duplicate KeyID.
     - Line 294: Rejects duplicate Fingerprint.
4. **Invalid or conflicting configuration fails initialization**:
   - **Verified**: In production-like environments, `InitProofSystem` ([proof.go#L28-L83](file:///e:/burnerbox/backend/internal/handlers/proof.go#L28-L83)) returns errors on missing key (line 52), malformed key (line 40), collision (line 47), historical key JSON parse failure (line 65), and historical registration failure (line 72).

### 5.2 Finding: Registry Exposure Prior to Complete Initialization

**Issue:** In `backend/internal/handlers/proof.go`:
```go
// Line 35: proof.go
crypto.GlobalRegistry = crypto.NewSigningRegistry(isProd)
```
`crypto.GlobalRegistry` is assigned immediately at line 35, **before** active and historical keys are validated.
If parsing `PROOF_SIGNING_PRIVATE_KEY` fails at line 40 or `SetActiveKey` fails at line 47, `InitProofSystem` returns an error, but `crypto.GlobalRegistry` remains mutated in a partially initialized state (containing only the built-in legacy compromised key and no active key).

**Proposed Atomic Initialization Fix:**
```go
func InitProofSystem(cfg *config.Config) error {
	isProd := false
	if cfg != nil && config.IsProductionLikeEnvironment(cfg.Environment) {
		isProd = true
	}

	// 1. Build new registry in local isolated instance
	newRegistry := crypto.NewSigningRegistry(isProd)

	if cfg != nil && cfg.ProofSigningPrivateKey != "" {
		priv, pub, err := crypto.ParseEd25519PrivateKey(cfg.ProofSigningPrivateKey)
		if err != nil {
			return fmt.Errorf("failed to parse proof signing private key: %w", err)
		}
		keyID := cfg.ProofSigningKeyID
		if keyID == "" {
			keyID = "bb-key-" + crypto.ComputeFingerprint(pub)
		}
		if err := newRegistry.SetActiveKey(keyID, priv, time.Now().UTC()); err != nil {
			return fmt.Errorf("failed to set active signing key: %w", err)
		}
	} else {
		if isProd {
			return fmt.Errorf("cannot initialize proof system: PROOF_SIGNING_PRIVATE_KEY is missing in production-like environment")
		}
		if err := newRegistry.InitDevEphemeralKey(); err != nil {
			return fmt.Errorf("failed to generate dev ephemeral key: %w", err)
		}
	}

	// Register historical keys into newRegistry...
	// ... (all validation against newRegistry)

	// 2. Commit atomically ONLY upon complete success
	crypto.GlobalRegistry = newRegistry
	syncPackageGlobals()
	return nil
}
```

---

## 6. Trust Metadata & Cryptographic Separation Audit

### 6.1 Verified Behavior vs Assumptions

| Requirement | Verified Source Reference | Relevant Automated Test | Verification Status |
|---|---|---|---|
| Explicit trusted historical keys require an explicit trust decision | [signing.go#L266-L270](file:///e:/burnerbox/backend/internal/crypto/signing.go#L266-L270) | `TestSigningRegistry_HistoricalTrustClassification` ([signing_test.go#L309-L322](file:///e:/burnerbox/backend/internal/crypto/signing_test.go#L309-L322)) | **VERIFIED** — Keys are only trusted if configured with `TrustStatusTrusted`. |
| Unknown provenance remains unknown | [signing.go#L274-L280](file:///e:/burnerbox/backend/internal/crypto/signing.go#L274-L280) | `TestSigningRegistry_HistoricalTrustClassification` ([signing_test.go#L339-L354](file:///e:/burnerbox/backend/internal/crypto/signing_test.go#L339-L354)) | **VERIFIED** — Omitted `trust_status` on retired keys defaults to `TrustStatusUnknown`. |
| Compromised keys remain untrusted | [signing.go#L147](file:///e:/burnerbox/backend/internal/crypto/signing.go#L147), [L267-L269](file:///e:/burnerbox/backend/internal/crypto/signing.go#L267-L269), [L276-L277](file:///e:/burnerbox/backend/internal/crypto/signing.go#L276-L277) | `TestSigningRegistry_HistoricalTrustClassification` ([signing_test.go#L370-L382](file:///e:/burnerbox/backend/internal/crypto/signing_test.go#L370-L382)) | **VERIFIED** — Compromised keys default to `untrusted` and reject `TrustStatusTrusted`. |
| Mathematical verification does not override trust status | [signing.go#L406-L413](file:///e:/burnerbox/backend/internal/crypto/signing.go#L406-L413) | `TestSigningRegistry_VerifySignature_TrustSeparation` ([signing_test.go#L391-L403](file:///e:/burnerbox/backend/internal/crypto/signing_test.go#L391-L403)) | **VERIFIED** — `VerifySignature` returns `mathValid = true` with `trust = "untrusted"` for compromised keys. |

---

## 7. Line Reference Summary

- `config.go`:
  - `IsProductionLikeEnvironment`: [L33-L56](file:///e:/burnerbox/backend/internal/config/config.go#L33-L56)
  - `config.Load`: [L58-L138](file:///e:/burnerbox/backend/internal/config/config.go#L58-L138)
  - Production key requirement check: [L123-L135](file:///e:/burnerbox/backend/internal/config/config.go#L123-L135)
- `signing.go`:
  - `NewSigningRegistry`: [L126-L135](file:///e:/burnerbox/backend/internal/crypto/signing.go#L126-L135)
  - `registerBuiltinLegacyKey`: [L137-L155](file:///e:/burnerbox/backend/internal/crypto/signing.go#L137-L155)
  - `SetActiveKey` collision checks: [L190-L209](file:///e:/burnerbox/backend/internal/crypto/signing.go#L190-L209)
  - `RegisterHistoricalKey` trust & collision checks: [L245-L297](file:///e:/burnerbox/backend/internal/crypto/signing.go#L245-L297)
  - `VerifySignature` (math vs trust separation): [L406-L413](file:///e:/burnerbox/backend/internal/crypto/signing.go#L406-L413)
- `proof.go`:
  - `InitProofSystem`: [L28-L83](file:///e:/burnerbox/backend/internal/handlers/proof.go#L28-L83)
  - `GetProofKeyByIdentifier`: [L187-L218](file:///e:/burnerbox/backend/internal/handlers/proof.go#L187-L218)
- `.gitignore`:
  - Key & archive ignore rules: [L53-L62](file:///e:/burnerbox/backend/.gitignore#L53-L62)
- Unit & Integration Tests:
  - `backend/internal/crypto/signing_test.go`:
    - `TestSigningRegistry_CollisionRejection` ([L220-L307](file:///e:/burnerbox/backend/internal/crypto/signing_test.go#L220-L307))
    - `TestSigningRegistry_HistoricalTrustClassification` ([L309-L388](file:///e:/burnerbox/backend/internal/crypto/signing_test.go#L309-L388))
    - `TestSigningRegistry_VerifySignature_TrustSeparation` ([L390-L457](file:///e:/burnerbox/backend/internal/crypto/signing_test.go#L390-L457))
  - `backend/internal/config/config_test.go`:
    - `TestIsProductionLikeEnvironment` ([L8-L63](file:///e:/burnerbox/backend/internal/config/config_test.go#L8-L63))
  - `backend/internal/handlers/proof_test.go`:
    - `TestInitProofSystem_ProductionValidation` ([L22-L74](file:///e:/burnerbox/backend/internal/handlers/proof_test.go#L22-L74))
    - `TestInitProofSystem_ProductionLikeEnvironments` ([L246-L306](file:///e:/burnerbox/backend/internal/handlers/proof_test.go#L246-L306))
    - `TestProofEndpoints_CompatibilityAndRegistry` ([L105-L244](file:///e:/burnerbox/backend/internal/handlers/proof_test.go#L105-L244))

---

## 8. Conclusion & Status

The final security review for Checkpoint 1B.3 is complete. Two actionable findings were identified and documented:
1. **Cloud Downgrade Vulnerability**: In `config.go`, setting `ENVIRONMENT=development` bypasses cloud host detection, allowing a cloud container to run with ephemeral keys. A minimal fix and regression test have been designed and documented.
2. **Atomic Registry Exposure**: In `proof.go`, `GlobalRegistry` is assigned prior to full configuration; adopting a local registry variable prior to final assignment guarantees atomic exposure.

Per the instructions, no application code has been modified. The review report is published and ready for user evaluation.
