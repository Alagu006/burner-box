package config

import (
	"encoding/base64"
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL         string
	Port                string
	JWTSecret           string
	TOTPEncryptionKey   []byte
	FileEncryptionKey   []byte
	SubmissionURLPrefix string
	CORSOrigins         string
	APIURL              string
}

var AppConfig *Config

func Load() *Config {
	// Load .env file (ignore error if not found - for production, use env vars or secrets manager)
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, using environment variables")
	}

	AppConfig = &Config{
		DatabaseURL:         getEnv("DATABASE_URL", ""),
		Port:                getEnv("PORT", "8080"),
		SubmissionURLPrefix: getEnv("SUBMISSION_URL_PREFIX", "http://localhost:5173/submit"),
		CORSOrigins:         getEnv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"),
		APIURL:              getEnv("API_URL", ""),
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

	return AppConfig
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}