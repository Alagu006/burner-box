package handlers

import (
	"burner-box-backend/internal/crypto"
	"burner-box-backend/internal/models"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

func TestDMSPublishWarrantCanary(t *testing.T) {
	// Create a temporary directory structure mimicking the repo
	tempDir, err := os.MkdirTemp("", "burnerbox-canary-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	docsDir := filepath.Join(tempDir, "docs")
	if err := os.MkdirAll(docsDir, 0755); err != nil {
		t.Fatalf("Failed to create docs dir: %v", err)
	}

	canaryFile := filepath.Join(docsDir, "WARRANT_CANARY.md")
	initialContent := "# BurnerBox Warrant Canary\n\n**Last updated:** August 17, 2026\n\nAs of the date above, no orders received.\n"
	if err := os.WriteFile(canaryFile, []byte(initialContent), 0644); err != nil {
		t.Fatalf("Failed to write initial canary: %v", err)
	}

	// Change cwd to tempDir
	origWd, _ := os.Getwd()
	defer os.Chdir(origWd)
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}

	orgID := uuid.New()
	testOrg := models.Organization{
		ID:   orgID,
		Name: "Test Whistleblower Org",
	}

	// Trigger DMS publish action
	publishDMSTriggerStatement(testOrg, 45)

	// Verify WARRANT_CANARY.md was updated
	contentBytes, err := os.ReadFile(canaryFile)
	if err != nil {
		t.Fatalf("Failed to read canary file: %v", err)
	}
	content := string(contentBytes)

	if !strings.Contains(content, "Dead Man's Switch Triggered Alert") {
		t.Errorf("Expected canary to contain DMS alert, got:\n%s", content)
	}
	if !strings.Contains(content, orgID.String()) {
		t.Errorf("Expected canary to contain org ID %s, got:\n%s", orgID.String(), content)
	}
	if !strings.Contains(content, "45 days without login") {
		t.Errorf("Expected canary to contain inactivity days, got:\n%s", content)
	}

	// Verify DMS_RELEASED.md log
	releasedFile := filepath.Join(docsDir, "DMS_RELEASED.md")
	releasedBytes, err := os.ReadFile(releasedFile)
	if err != nil {
		t.Fatalf("Failed to read DMS_RELEASED.md: %v", err)
	}
	if !strings.Contains(string(releasedBytes), orgID.String()) {
		t.Errorf("Expected DMS_RELEASED.md to contain org ID, got:\n%s", string(releasedBytes))
	}
}

func TestDMSReAuthPasswordVerification(t *testing.T) {
	password := "CorrectSecurePassword123!"
	hashed, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// Test valid password
	ok, err := crypto.VerifyPassword(password, hashed)
	if err != nil || !ok {
		t.Errorf("Expected valid password to verify, got ok=%v, err=%v", ok, err)
	}

	// Test wrong password
	ok, _ = crypto.VerifyPassword("WrongPassword456!", hashed)
	if ok {
		t.Errorf("Expected wrong password to fail verification")
	}

	// Test empty password
	ok, _ = crypto.VerifyPassword("", hashed)
	if ok {
		t.Errorf("Expected empty password to fail verification")
	}
}

func TestDMSReAuthTOTPVerification(t *testing.T) {
	// Generate TOTP key
	totpSecret, _, err := crypto.GenerateTOTPSecret("TestOrg", "test@example.com")
	if err != nil {
		t.Fatalf("GenerateTOTPSecret failed: %v", err)
	}

	code, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	// Test valid TOTP
	if !crypto.ValidateTOTPCode(totpSecret, code) {
		t.Errorf("Expected valid TOTP code to pass")
	}

	// Test invalid TOTP
	if crypto.ValidateTOTPCode(totpSecret, "000000") && code != "000000" {
		t.Errorf("Expected invalid TOTP code to fail")
	}
}
