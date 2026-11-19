package handlers

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"burner-box-backend/internal/config"
	"burner-box-backend/internal/crypto"
	"burner-box-backend/internal/models"

	"github.com/glebarez/sqlite"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	config.AppConfig = &config.Config{
		JWTSecret:         "test-jwt-secret-very-secure-random-bytes-1234567890",
		TOTPEncryptionKey: bytes.Repeat([]byte{1}, 32),
		FileEncryptionKey: bytes.Repeat([]byte{2}, 32),
		Environment:       "testing",
	}

	InitProofSystemForTest(t)

	dsn := fmt.Sprintf("file:memdb_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("Failed to connect to in-memory sqlite test db: %v", err)
	}

	// Create tables with SQLite-compatible schema
	schema := `
	CREATE TABLE IF NOT EXISTS organizations (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		email TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		public_key TEXT,
		encryption_scheme TEXT DEFAULT 'libsodium',
		submission_slug TEXT NOT NULL UNIQUE,
		welcome_message TEXT,
		logo_url TEXT,
		custom_fields TEXT,
		is_verified BOOLEAN DEFAULT 0,
		totp_secret TEXT,
		totp_enabled BOOLEAN DEFAULT 0,
		submission_deadline DATETIME,
		retention_days INTEGER,
		webhook_url TEXT,
		notification_email TEXT,
		created_at DATETIME,
		updated_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		organization_id TEXT NOT NULL,
		token_hash TEXT NOT NULL,
		created_at DATETIME,
		last_seen_at DATETIME,
		expires_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS team_members (
		id TEXT PRIMARY KEY,
		organization_id TEXT NOT NULL,
		email TEXT NOT NULL,
		role TEXT DEFAULT 'reader',
		invited_at DATETIME,
		accepted_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS submissions (
		id TEXT PRIMARY KEY,
		organization_id TEXT NOT NULL,
		anonymous_name TEXT NOT NULL,
		encrypted_message TEXT,
		encryption_meta TEXT,
		message_text TEXT,
		reply_public_key TEXT,
		has_reply_key BOOLEAN DEFAULT 0,
		has_files BOOLEAN DEFAULT 0,
		file_count INTEGER DEFAULT 0,
		status TEXT DEFAULT 'unread',
		priority TEXT DEFAULT 'normal',
		assigned_to TEXT,
		internal_notes TEXT,
		created_at DATETIME,
		updated_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS submission_files (
		id TEXT PRIMARY KEY,
		submission_id TEXT NOT NULL,
		file_name TEXT NOT NULL,
		file_size INTEGER,
		storage_key TEXT NOT NULL,
		mime_type TEXT,
		encryption_meta TEXT,
		file_encryption_key TEXT,
		created_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS replies (
		id TEXT PRIMARY KEY,
		submission_id TEXT NOT NULL,
		encrypted_message TEXT,
		encryption_meta TEXT,
		message_text TEXT,
		created_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS submission_messages (
		id TEXT PRIMARY KEY,
		submission_id TEXT NOT NULL,
		anonymous_name TEXT NOT NULL,
		sender_type TEXT NOT NULL,
		encrypted_text TEXT,
		encryption_meta TEXT,
		message_text TEXT,
		organization_id TEXT NOT NULL,
		created_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS internal_notes (
		id TEXT PRIMARY KEY,
		submission_id TEXT NOT NULL,
		organization_id TEXT NOT NULL,
		author_email TEXT NOT NULL,
		author_role TEXT NOT NULL,
		content TEXT NOT NULL,
		parent_note_id TEXT,
		depth INTEGER DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS activities (
		id TEXT PRIMARY KEY,
		submission_id TEXT NOT NULL,
		organization_id TEXT NOT NULL,
		actor_email TEXT NOT NULL,
		actor_role TEXT NOT NULL,
		action_type TEXT NOT NULL,
		detail TEXT,
		created_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS rooms (
		id TEXT PRIMARY KEY,
		room_code TEXT NOT NULL UNIQUE,
		password_hash TEXT,
		creator_token_hash TEXT NOT NULL DEFAULT '',
		max_participants INTEGER DEFAULT 10,
		expires_at DATETIME NOT NULL,
		destroyed_at DATETIME,
		created_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS room_messages (
		id TEXT PRIMARY KEY,
		room_code TEXT NOT NULL,
		sender_tag TEXT NOT NULL,
		encrypted_message TEXT NOT NULL,
		encryption_meta TEXT,
		self_destruct_at DATETIME,
		created_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS room_files (
		id TEXT PRIMARY KEY,
		room_code TEXT NOT NULL,
		sender_tag TEXT NOT NULL,
		original_name TEXT NOT NULL,
		mime_type TEXT,
		file_size INTEGER NOT NULL,
		encrypted_data BLOB NOT NULL,
		encryption_meta TEXT,
		self_destruct_at DATETIME,
		created_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS room_reactions (
		id TEXT PRIMARY KEY,
		room_code TEXT NOT NULL,
		message_id TEXT NOT NULL,
		sender_tag TEXT NOT NULL,
		encrypted_emoji TEXT NOT NULL,
		encryption_meta TEXT,
		created_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS dead_mans_switches (
		id TEXT PRIMARY KEY,
		organization_id TEXT NOT NULL UNIQUE,
		enabled BOOLEAN DEFAULT 0,
		trigger_days INTEGER DEFAULT 30,
		action_type TEXT DEFAULT 'email',
		encrypted_config TEXT,
		last_login_at DATETIME,
		triggered_at DATETIME,
		created_at DATETIME,
		updated_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS merkle_batches (
		id TEXT PRIMARY KEY,
		organization_id TEXT NOT NULL,
		batch_number INTEGER NOT NULL,
		status TEXT DEFAULT 'open',
		root_hash TEXT,
		signature TEXT,
		key_fingerprint TEXT,
		leaf_count INTEGER DEFAULT 0,
		sealed_at DATETIME,
		created_at DATETIME,
		updated_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS merkle_leaves (
		id TEXT PRIMARY KEY,
		batch_id TEXT NOT NULL,
		organization_id TEXT NOT NULL,
		submission_id TEXT NOT NULL UNIQUE,
		leaf_index INTEGER NOT NULL,
		leaf_hash TEXT NOT NULL,
		created_at DATETIME
	);
	`

	if err := db.Exec(schema).Error; err != nil {
		t.Fatalf("Failed to initialize sqlite test schema: %v", err)
	}

	models.DB = db
	return db
}

func setupTestApp() *fiber.App {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})
	return app
}

// CreateTestSessionToken creates a real session in models.DB and returns a valid session-backed JWT
func CreateTestSessionToken(orgID uuid.UUID, email string) string {
	sessionID := uuid.New()
	token, err := crypto.GenerateTokenWithSession(orgID, email, sessionID, config.AppConfig.JWTSecret)
	if err != nil {
		panic(err)
	}

	tokenHash := crypto.HashToken(token)
	now := time.Now()
	session := models.Session{
		ID:             sessionID,
		OrganizationID: orgID,
		TokenHash:      tokenHash,
		CreatedAt:      now,
		LastSeenAt:     now,
		ExpiresAt:      now.Add(24 * time.Hour),
	}

	if err := models.DB.Create(&session).Error; err != nil {
		panic(err)
	}

	return token
}
