package config

import (
	"encoding/base64"
	"log"
	"os"
	"strings"

	"burner-box-backend/internal/crypto"

	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL               string
	Port                      string
	JWTSecret                 string
	TOTPEncryptionKey         []byte
	FileEncryptionKey         []byte
	SubmissionURLPrefix       string
	CORSOrigins               string
	APIURL                    string
	Environment               string
	ProofSigningPrivateKey    string
	ProofSigningKeyID         string
	ProofHistoricalPublicKeys string
}

var AppConfig *Config

// CloudPlatformIndicators lists the environment variables that indicate execution on managed cloud hosting infrastructure.
var CloudPlatformIndicators = []string{
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

// EnvLookupFunc is a function signature for looking up environment variables.
type EnvLookupFunc func(key string) (string, bool)

// DetectCloudPlatformWithLookup checks if any cloud hosting indicator is present using the provided lookup function.
// Returns the name of the first detected cloud indicator, or empty string if none are present.
func DetectCloudPlatformWithLookup(lookup EnvLookupFunc) string {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	for _, envVar := range CloudPlatformIndicators {
		if val, ok := lookup(envVar); ok && strings.TrimSpace(val) != "" {
			return envVar
		}
	}
	return ""
}

// DetectCloudPlatform checks if any cloud hosting indicator is present in the process environment.
func DetectCloudPlatform() string {
	return DetectCloudPlatformWithLookup(os.LookupEnv)
}

// IsProductionLikeEnvironmentWithLookup evaluates environment classification using a custom lookup function.
// Security Invariant: Any cloud platform indicator unconditionally forces production-like classification,
// overriding ENVIRONMENT=development, dev, test, or local.
func IsProductionLikeEnvironmentWithLookup(env string, lookup EnvLookupFunc) bool {
	// Rule 1: A cloud platform indicator unconditionally forces production-like signing configuration.
	// Cloud deployments must NEVER be downgraded to ephemeral keys by setting ENVIRONMENT=development.
	if indicator := DetectCloudPlatformWithLookup(lookup); indicator != "" {
		return true
	}

	// Rule 2: Outside cloud platforms (e.g. local machines), check explicit environment labels.
	normalized := strings.ToLower(strings.TrimSpace(env))
	switch normalized {
	case "production", "prod", "staging", "stage", "preview", "live":
		return true
	}

	return false
}

// IsProductionLikeEnvironment returns true if the environment is a deployed tier (production, staging, preview, live)
// or running on managed cloud infrastructure where ephemeral signing fallback is forbidden.
func IsProductionLikeEnvironment(env string) bool {
	return IsProductionLikeEnvironmentWithLookup(env, os.LookupEnv)
}

func Load() *Config {
	// Load .env file (ignore error if not found - for production, use env vars or secrets manager)
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, using environment variables")
	}

	rawEnv := getEnv("ENVIRONMENT", "")
	env := "development"
	if cloudIndicator := DetectCloudPlatform(); cloudIndicator != "" {
		// When running on a cloud platform, if ENVIRONMENT is unset or set to development/dev/local,
		// default to production to avoid running dev mode in a deployed cloud environment.
		// If explicitly set to staging/preview/live, preserve that explicit tier label.
		if rawEnv == "" || rawEnv == "development" || rawEnv == "dev" || rawEnv == "local" {
			env = "production"
		} else {
			env = rawEnv
		}
	} else if rawEnv != "" {
		env = rawEnv
	}

	AppConfig = &Config{
		DatabaseURL:               getEnv("DATABASE_URL", ""),
		Port:                      getEnv("PORT", "8080"),
		SubmissionURLPrefix:       getEnv("SUBMISSION_URL_PREFIX", "http://localhost:5173/submit"),
		CORSOrigins:               getEnv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"),
		APIURL:                    getEnv("API_URL", ""),
		Environment:               env,
		ProofSigningPrivateKey:    os.Getenv("PROOF_SIGNING_PRIVATE_KEY"),
		ProofSigningKeyID:         getEnv("PROOF_SIGNING_KEY_ID", ""),
		ProofHistoricalPublicKeys: os.Getenv("PROOF_HISTORICAL_PUBLIC_KEYS"),
	}

	if AppConfig.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}

	// JWT_SECRET is mandatory — refuse to boot with an insecure default
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is required. Generate one with: openssl rand -base64 64")
	}
	AppConfig.JWTSecret = jwtSecret

	totpKeyB64 := os.Getenv("TOTP_ENCRYPTION_KEY")
	if totpKeyB64 == "" {
		log.Fatal("TOTP_ENCRYPTION_KEY is required (base64-encoded 32-byte key)")
	}
	decoded, err := base64.StdEncoding.DecodeString(totpKeyB64)
	if err != nil {
		log.Fatalf("TOTP_ENCRYPTION_KEY is not valid base64: %v", err)
	}
	if len(decoded) != 32 {
		log.Fatalf("TOTP_ENCRYPTION_KEY must decode to exactly 32 bytes, got %d", len(decoded))
	}
	AppConfig.TOTPEncryptionKey = decoded

	fileKeyB64 := os.Getenv("FILE_ENCRYPTION_KEY")
	if fileKeyB64 == "" {
		log.Fatal("FILE_ENCRYPTION_KEY is required (base64-encoded 32-byte key)")
	}
	fileKeyDecoded, err := base64.StdEncoding.DecodeString(fileKeyB64)
	if err != nil {
		log.Fatalf("FILE_ENCRYPTION_KEY is not valid base64: %v", err)
	}
	if len(fileKeyDecoded) != 32 {
		log.Fatalf("FILE_ENCRYPTION_KEY must decode to exactly 32 bytes, got %d", len(fileKeyDecoded))
	}
	AppConfig.FileEncryptionKey = fileKeyDecoded

	// BB-SEC-001: Validate Proof Signing Key Configuration
	if IsProductionLikeEnvironment(AppConfig.Environment) {
		if AppConfig.ProofSigningPrivateKey == "" {
			log.Fatalf("PROOF_SIGNING_PRIVATE_KEY is required in %s environment (base64-encoded 32-byte seed or 64-byte Ed25519 private key)", AppConfig.Environment)
		}
		if _, _, err := crypto.ParseEd25519PrivateKey(AppConfig.ProofSigningPrivateKey); err != nil {
			log.Fatalf("PROOF_SIGNING_PRIVATE_KEY is invalid: %v", err)
		}
	} else if AppConfig.ProofSigningPrivateKey != "" {
		// In dev/test, if explicitly provided, it must be valid
		if _, _, err := crypto.ParseEd25519PrivateKey(AppConfig.ProofSigningPrivateKey); err != nil {
			log.Fatalf("PROOF_SIGNING_PRIVATE_KEY is invalid: %v", err)
		}
	}

	return AppConfig
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
