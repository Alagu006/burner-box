package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"burner-box-backend/internal/config"
	"burner-box-backend/internal/crypto"
	"burner-box-backend/internal/middleware"
	"burner-box-backend/internal/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

func setupAccountDeletionTestApp() *fiber.App {
	app := setupTestApp()
	protected := app.Group("/api/v1/dashboard")
	protected.Use(middleware.Protected())
	protected.Use(middleware.ResolveRole())

	adminRole := middleware.RequireRole("admin")
	protected.Delete("/account", adminRole, DeleteAccount)
	return app
}

func TestDeleteAccount_RejectsNonAdminRole(t *testing.T) {
	setupTestDB(t)
	app := setupAccountDeletionTestApp()

	orgID := uuid.New()
	passwordHash, _ := crypto.HashPassword("AdminPassword123!")
	org := models.Organization{
		ID:             orgID,
		Name:           "Test Org",
		Email:          "admin@test.org",
		PasswordHash:   passwordHash,
		SubmissionSlug: "test-slug-1",
	}
	models.DB.Create(&org)

	// Create responder team member
	models.DB.Create(&models.TeamMember{
		ID:             uuid.New(),
		OrganizationID: orgID,
		Email:          "responder@test.org",
		Role:           "responder",
	})

	responderToken := CreateTestSessionToken(orgID, "responder@test.org")

	reqBody, _ := json.Marshal(map[string]string{
		"password": "AdminPassword123!",
	})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/dashboard/account", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+responderToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden for non-admin role, got %d", resp.StatusCode)
	}

	// Verify org still exists
	var count int64
	models.DB.Model(&models.Organization{}).Where("id = ?", orgID).Count(&count)
	if count != 1 {
		t.Fatalf("Org should not be deleted by non-admin")
	}
}

func TestDeleteAccount_RejectsWrongPassword(t *testing.T) {
	setupTestDB(t)
	app := setupAccountDeletionTestApp()

	orgID := uuid.New()
	passwordHash, _ := crypto.HashPassword("CorrectPassword123!")
	org := models.Organization{
		ID:             orgID,
		Name:           "Test Org",
		Email:          "admin@test.org",
		PasswordHash:   passwordHash,
		SubmissionSlug: "test-slug-2",
	}
	models.DB.Create(&org)

	adminToken := CreateTestSessionToken(orgID, "admin@test.org")

	reqBody, _ := json.Marshal(map[string]string{
		"password": "WrongPasswordAttempt!",
	})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/dashboard/account", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for wrong password, got %d", resp.StatusCode)
	}

	// Verify org still exists
	var count int64
	models.DB.Model(&models.Organization{}).Where("id = ?", orgID).Count(&count)
	if count != 1 {
		t.Fatalf("Org should not be deleted on wrong password")
	}
}

func TestDeleteAccount_RejectsMissingOrInvalidTOTP_When2FAEnabled(t *testing.T) {
	setupTestDB(t)
	app := setupAccountDeletionTestApp()

	orgID := uuid.New()
	passwordHash, _ := crypto.HashPassword("CorrectPassword123!")
	totpSecret, _, _ := crypto.GenerateTOTPSecret("Test Org", "admin@test.org")
	encryptedSecret, _ := crypto.EncryptTOTPSecret(totpSecret, config.AppConfig.TOTPEncryptionKey)

	org := models.Organization{
		ID:             orgID,
		Name:           "Test Org",
		Email:          "admin@test.org",
		PasswordHash:   passwordHash,
		SubmissionSlug: "test-slug-3",
		TOTPEnabled:    true,
		TOTPSecret:     encryptedSecret,
	}
	models.DB.Create(&org)

	adminToken := CreateTestSessionToken(orgID, "admin@test.org")

	// 1. Missing TOTP code
	reqBodyMissing, _ := json.Marshal(map[string]string{
		"password": "CorrectPassword123!",
	})
	req1 := httptest.NewRequest(http.MethodDelete, "/api/v1/dashboard/account", bytes.NewReader(reqBodyMissing))
	req1.Header.Set("Authorization", "Bearer "+adminToken)
	req1.Header.Set("Content-Type", "application/json")

	resp1, err := app.Test(req1, 5000)
	if err != nil {
		t.Fatalf("Request 1 failed: %v", err)
	}
	if resp1.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request when TOTP code is missing, got %d", resp1.StatusCode)
	}

	// 2. Invalid TOTP code
	reqBodyInvalid, _ := json.Marshal(map[string]string{
		"password": "CorrectPassword123!",
		"code":     "000000",
	})
	req2 := httptest.NewRequest(http.MethodDelete, "/api/v1/dashboard/account", bytes.NewReader(reqBodyInvalid))
	req2.Header.Set("Authorization", "Bearer "+adminToken)
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := app.Test(req2, 5000)
	if err != nil {
		t.Fatalf("Request 2 failed: %v", err)
	}
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for invalid TOTP code, got %d", resp2.StatusCode)
	}

	// Verify org still exists
	var count int64
	models.DB.Model(&models.Organization{}).Where("id = ?", orgID).Count(&count)
	if count != 1 {
		t.Fatalf("Org should not be deleted on invalid 2FA")
	}
}

func TestDeleteAccount_HardDeletesOrgAndAllAssociatedData(t *testing.T) {
	setupTestDB(t)
	app := setupAccountDeletionTestApp()

	// Create Target Org A
	orgAID := uuid.New()
	passwordHashA, _ := crypto.HashPassword("AdminSuperPassword123!")
	totpSecretA, _, _ := crypto.GenerateTOTPSecret("Org A", "admin@orga.test")
	encryptedSecretA, _ := crypto.EncryptTOTPSecret(totpSecretA, config.AppConfig.TOTPEncryptionKey)

	orgA := models.Organization{
		ID:             orgAID,
		Name:           "Organization A (To Delete)",
		Email:          "admin@orga.test",
		PasswordHash:   passwordHashA,
		SubmissionSlug: "orga-slug",
		TOTPEnabled:    true,
		TOTPSecret:     encryptedSecretA,
	}
	models.DB.Create(&orgA)

	// Create Control Org B (must remain untouched!)
	orgBID := uuid.New()
	orgB := models.Organization{
		ID:             orgBID,
		Name:           "Organization B (Survivor)",
		Email:          "admin@orgb.test",
		PasswordHash:   passwordHashA,
		SubmissionSlug: "orgb-slug",
	}
	models.DB.Create(&orgB)

	// 1. Submissions for Org A
	subAID := uuid.New()
	subA := models.Submission{
		ID:               subAID,
		OrganizationID:   orgAID,
		AnonymousName:    "Whistleblower-A",
		EncryptedMessage: "encrypted-payload-a",
		EncryptionMeta:   `{"scheme":"libsodium"}`,
		InternalNotes:    "Sensitive internal note",
		Status:           "unread",
	}
	models.DB.Create(&subA)

	// Submissions for Org B
	subBID := uuid.New()
	subB := models.Submission{
		ID:               subBID,
		OrganizationID:   orgBID,
		AnonymousName:    "Whistleblower-B",
		EncryptedMessage: "encrypted-payload-b",
		Status:           "unread",
	}
	models.DB.Create(&subB)

	// 2. Files on disk and in DB for Org A
	fileDirA := filepath.Join("uploads", "submissions", subAID.String())
	os.MkdirAll(fileDirA, 0755)
	filePathA := filepath.Join(fileDirA, "document_a.pdf")
	os.WriteFile(filePathA, []byte("TOP SECRET LEAK FOR ORG A"), 0644)

	storageKeyA := fmt.Sprintf("submissions/%s/document_a.pdf", subAID.String())
	subFileA := models.SubmissionFile{
		ID:           uuid.New(),
		SubmissionID: subAID,
		FileName:     "document_a.pdf",
		FileSize:     25,
		StorageKey:   storageKeyA,
		MimeType:     "application/pdf",
	}
	models.DB.Create(&subFileA)

	// Files on disk and in DB for Org B
	fileDirB := filepath.Join("uploads", "submissions", subBID.String())
	os.MkdirAll(fileDirB, 0755)
	filePathB := filepath.Join(fileDirB, "document_b.pdf")
	os.WriteFile(filePathB, []byte("DOCUMENT FOR ORG B"), 0644)
	defer func() {
		os.RemoveAll(fileDirB)
	}()

	storageKeyB := fmt.Sprintf("submissions/%s/document_b.pdf", subBID.String())
	subFileB := models.SubmissionFile{
		ID:           uuid.New(),
		SubmissionID: subBID,
		FileName:     "document_b.pdf",
		FileSize:     18,
		StorageKey:   storageKeyB,
		MimeType:     "application/pdf",
	}
	models.DB.Create(&subFileB)

	// 3. Replies
	models.DB.Create(&models.Reply{
		ID:               uuid.New(),
		SubmissionID:     subAID,
		EncryptedMessage: "reply-to-a",
	})
	models.DB.Create(&models.Reply{
		ID:               uuid.New(),
		SubmissionID:     subBID,
		EncryptedMessage: "reply-to-b",
	})

	// 4. Thread messages
	models.DB.Create(&models.SubmissionMessage{
		ID:             uuid.New(),
		SubmissionID:   subAID,
		OrganizationID: orgAID,
		AnonymousName:  "Staff",
		SenderType:     "org",
		EncryptedText:  "thread-message-a",
	})
	models.DB.Create(&models.SubmissionMessage{
		ID:             uuid.New(),
		SubmissionID:   subBID,
		OrganizationID: orgBID,
		AnonymousName:  "Staff",
		SenderType:     "org",
		EncryptedText:  "thread-message-b",
	})

	// 5. Internal Notes
	models.DB.Create(&models.InternalNote{
		ID:             uuid.New(),
		SubmissionID:   subAID,
		OrganizationID: orgAID,
		AuthorEmail:    "admin@orga.test",
		AuthorRole:     "admin",
		Content:        "Investigate note A",
	})
	models.DB.Create(&models.InternalNote{
		ID:             uuid.New(),
		SubmissionID:   subBID,
		OrganizationID: orgBID,
		AuthorEmail:    "admin@orgb.test",
		AuthorRole:     "admin",
		Content:        "Investigate note B",
	})

	// 6. Activity logs
	models.DB.Create(&models.Activity{
		ID:             uuid.New(),
		SubmissionID:   subAID,
		OrganizationID: orgAID,
		ActorEmail:     "admin@orga.test",
		ActorRole:      "admin",
		ActionType:     "status_change",
		Detail:         "read",
	})
	models.DB.Create(&models.Activity{
		ID:             uuid.New(),
		SubmissionID:   subBID,
		OrganizationID: orgBID,
		ActorEmail:     "admin@orgb.test",
		ActorRole:      "admin",
		ActionType:     "status_change",
		Detail:         "read",
	})

	// 7. Merkle batches & leaves
	batchA := models.MerkleBatch{
		ID:             uuid.New(),
		OrganizationID: orgAID,
		BatchNumber:    1,
		Status:         "open",
	}
	models.DB.Create(&batchA)
	models.DB.Create(&models.MerkleLeaf{
		ID:             uuid.New(),
		BatchID:        batchA.ID,
		OrganizationID: orgAID,
		SubmissionID:   subAID,
		LeafIndex:      0,
		LeafHash:       "leafhash-a",
	})

	batchB := models.MerkleBatch{
		ID:             uuid.New(),
		OrganizationID: orgBID,
		BatchNumber:    1,
		Status:         "open",
	}
	models.DB.Create(&batchB)
	models.DB.Create(&models.MerkleLeaf{
		ID:             uuid.New(),
		BatchID:        batchB.ID,
		OrganizationID: orgBID,
		SubmissionID:   subBID,
		LeafIndex:      0,
		LeafHash:       "leafhash-b",
	})

	// 8. Sessions
	sessionA := models.Session{
		ID:             uuid.New(),
		OrganizationID: orgAID,
		ExpiresAt:      time.Now().Add(24 * time.Hour),
	}
	models.DB.Create(&sessionA)
	sessionB := models.Session{
		ID:             uuid.New(),
		OrganizationID: orgBID,
		ExpiresAt:      time.Now().Add(24 * time.Hour),
	}
	models.DB.Create(&sessionB)

	// 9. Team members
	models.DB.Create(&models.TeamMember{
		ID:             uuid.New(),
		OrganizationID: orgAID,
		Email:          "memberA@orga.test",
		Role:           "responder",
	})
	models.DB.Create(&models.TeamMember{
		ID:             uuid.New(),
		OrganizationID: orgBID,
		Email:          "memberB@orgb.test",
		Role:           "responder",
	})

	// 10. Dead man's switch
	models.DB.Create(&models.DeadMansSwitch{
		ID:             uuid.New(),
		OrganizationID: orgAID,
		Enabled:        true,
		TriggerDays:    30,
	})
	models.DB.Create(&models.DeadMansSwitch{
		ID:             uuid.New(),
		OrganizationID: orgBID,
		Enabled:        true,
		TriggerDays:    30,
	})

	// Confirm file on disk exists before deletion
	if _, err := os.Stat(filePathA); os.IsNotExist(err) {
		t.Fatalf("Pre-condition failed: File A must exist on disk before deletion")
	}

	// Generate valid TOTP code for Org A
	validCodeA, err := totp.GenerateCode(totpSecretA, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate TOTP code: %v", err)
	}

	adminTokenA := CreateTestSessionToken(orgAID, "admin@orga.test")

	// Execute deletion request
	deletePayload, _ := json.Marshal(map[string]string{
		"password": "AdminSuperPassword123!",
		"code":     validCodeA,
	})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/dashboard/account", bytes.NewReader(deletePayload))
	req.Header.Set("Authorization", "Bearer "+adminTokenA)
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Deletion request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for account deletion, got %d", resp.StatusCode)
	}

	// ==========================================
	// VERIFY NOTHING REMAINS FOR ORG A
	// ==========================================

	// 1. Organization record
	var orgCount int64
	models.DB.Model(&models.Organization{}).Where("id = ?", orgAID).Count(&orgCount)
	if orgCount != 0 {
		t.Errorf("LEAK: Organization A still exists in DB (%d)", orgCount)
	}

	// 2. Submissions
	var subCount int64
	models.DB.Model(&models.Submission{}).Where("organization_id = ?", orgAID).Count(&subCount)
	if subCount != 0 {
		t.Errorf("LEAK: Submissions for Org A still exist in DB (%d)", subCount)
	}

	// 3. Submission Files
	var fileCount int64
	models.DB.Model(&models.SubmissionFile{}).Where("submission_id = ?", subAID).Count(&fileCount)
	if fileCount != 0 {
		t.Errorf("LEAK: SubmissionFile records for Org A still exist in DB (%d)", fileCount)
	}

	// 4. Replies
	var replyCount int64
	models.DB.Model(&models.Reply{}).Where("submission_id = ?", subAID).Count(&replyCount)
	if replyCount != 0 {
		t.Errorf("LEAK: Replies for Org A still exist in DB (%d)", replyCount)
	}

	// 5. Submission Messages (threads)
	var msgCount int64
	models.DB.Model(&models.SubmissionMessage{}).Where("organization_id = ?", orgAID).Count(&msgCount)
	if msgCount != 0 {
		t.Errorf("LEAK: SubmissionMessage records for Org A still exist in DB (%d)", msgCount)
	}

	// 6. Internal Notes
	var noteCount int64
	models.DB.Model(&models.InternalNote{}).Where("organization_id = ?", orgAID).Count(&noteCount)
	if noteCount != 0 {
		t.Errorf("LEAK: InternalNotes for Org A still exist in DB (%d)", noteCount)
	}

	// 7. Activities
	var actCount int64
	models.DB.Model(&models.Activity{}).Where("organization_id = ?", orgAID).Count(&actCount)
	if actCount != 0 {
		t.Errorf("LEAK: Activity records for Org A still exist in DB (%d)", actCount)
	}

	// 8. Merkle Batches & Leaves
	var batchCount, leafCount int64
	models.DB.Model(&models.MerkleBatch{}).Where("organization_id = ?", orgAID).Count(&batchCount)
	if batchCount != 0 {
		t.Errorf("LEAK: MerkleBatch records for Org A still exist in DB (%d)", batchCount)
	}
	models.DB.Model(&models.MerkleLeaf{}).Where("organization_id = ?", orgAID).Count(&leafCount)
	if leafCount != 0 {
		t.Errorf("LEAK: MerkleLeaf records for Org A still exist in DB (%d)", leafCount)
	}

	// 9. Sessions
	var sessionCount int64
	models.DB.Model(&models.Session{}).Where("organization_id = ?", orgAID).Count(&sessionCount)
	if sessionCount != 0 {
		t.Errorf("LEAK: Sessions for Org A still exist in DB (%d)", sessionCount)
	}

	// 10. Team Members
	var memberCount int64
	models.DB.Model(&models.TeamMember{}).Where("organization_id = ?", orgAID).Count(&memberCount)
	if memberCount != 0 {
		t.Errorf("LEAK: TeamMembers for Org A still exist in DB (%d)", memberCount)
	}

	// 11. Dead Man's Switch
	var dmsCount int64
	models.DB.Model(&models.DeadMansSwitch{}).Where("organization_id = ?", orgAID).Count(&dmsCount)
	if dmsCount != 0 {
		t.Errorf("LEAK: DeadMansSwitch for Org A still exists in DB (%d)", dmsCount)
	}

	// 12. Disk Files
	if _, err := os.Stat(filePathA); !os.IsNotExist(err) {
		t.Errorf("LEAK: File on disk %s still exists after deletion!", filePathA)
	}
	if _, err := os.Stat(fileDirA); !os.IsNotExist(err) {
		t.Errorf("LEAK: Directory on disk %s still exists after deletion!", fileDirA)
	}

	// ==========================================
	// VERIFY ORG B IS UNTOUCHED
	// ==========================================
	var orgBCount, subBCount int64
	models.DB.Model(&models.Organization{}).Where("id = ?", orgBID).Count(&orgBCount)
	if orgBCount != 1 {
		t.Errorf("CORRUPTION: Org B was unexpectedly deleted or modified (%d)", orgBCount)
	}
	models.DB.Model(&models.Submission{}).Where("organization_id = ?", orgBID).Count(&subBCount)
	if subBCount != 1 {
		t.Errorf("CORRUPTION: Org B submissions were affected (%d)", subBCount)
	}
	if _, err := os.Stat(filePathB); os.IsNotExist(err) {
		t.Errorf("CORRUPTION: Org B file on disk was unexpectedly deleted!")
	}
}
