package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"burner-box-backend/internal/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

func TestSubmitAnonymousTip_RejectsPlaintextOnly_WithBadRequest(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Post("/api/v1/submit/:slug", SubmitAnonymousTip)

	// Create an organization with an E2EE public key
	org := models.Organization{
		ID:             uuid.New(),
		Name:           "Whistleblower Outlet",
		Email:          "tips@outlet.test",
		SubmissionSlug: "secure-portal-1234",
		PublicKey:      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
	}
	models.DB.Create(&org)

	// Attempt to send a plaintext message without encrypted payload
	payload := map[string]string{
		"message_text": "This is a sensitive plaintext tip sent directly without client encryption.",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/submit/secure-portal-1234", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	// Security Assertion: Plaintext must be rejected with 400 Bad Request
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("SECURITY VIOLATION: Expected 400 Bad Request when sending plaintext tip to encrypted org, got %d", resp.StatusCode)
	}

	var respData map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&respData)
	if respData["error"] == nil {
		t.Errorf("Expected error message in response body")
	}

	// Verify no unencrypted submission was stored in the database
	var count int64
	models.DB.Model(&models.Submission{}).Where("organization_id = ?", org.ID).Count(&count)
	if count != 0 {
		t.Errorf("SECURITY VIOLATION: Plaintext submission was stored in database! (found %d records)", count)
	}
}

func TestSubmitAnonymousTip_AcceptsEncryptedPayload_WithCreated(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Post("/api/v1/submit/:slug", SubmitAnonymousTip)

	org := models.Organization{
		ID:             uuid.New(),
		Name:           "Whistleblower Outlet",
		Email:          "tips2@outlet.test",
		SubmissionSlug: "secure-portal-5678",
		PublicKey:      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
	}
	models.DB.Create(&org)

	// Encrypted tip payload
	payload := map[string]string{
		"encrypted_message": "dGVzdC1jaXBoZXJ0ZXh0LWJhc2U2NA==",
		"encryption_meta":   `{"nonce":"123","encryptedKey":"456","boxNonce":"789","senderPublicKey":"abc"}`,
		"reply_public_key":  "c3VibWl0dGVyLXJlcGx5LXB1YmxpYy1rZXk=",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/submit/secure-portal-5678", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected 201 Created for valid encrypted submission, got %d", resp.StatusCode)
	}

	var respData map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&respData)

	if respData["submission_id"] == nil || respData["anonymous_name"] == nil {
		t.Errorf("Expected submission_id and anonymous_name in response, got %v", respData)
	}

	// Verify proof is returned
	proof, ok := respData["proof"].(map[string]interface{})
	if !ok || proof["signature"] == nil {
		t.Errorf("Expected cryptographic proof with signature in response, got %v", respData["proof"])
	}

	// Verify database record
	var sub models.Submission
	if err := models.DB.Where("organization_id = ?", org.ID).First(&sub).Error; err != nil {
		t.Fatalf("Submission not found in DB: %v", err)
	}
	if sub.EncryptedMessage != "dGVzdC1jaXBoZXJ0ZXh0LWJhc2U2NA==" {
		t.Errorf("Expected encrypted ciphertext to be stored")
	}
	if sub.MessageText != "" {
		t.Errorf("Expected plaintext message_text to be empty for E2EE submission, got %s", sub.MessageText)
	}
}

func TestReplyToSubmission_RejectsPlaintextOnly_WithBadRequest(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()

	// Mock protected context
	orgID := uuid.New()
	app.Post("/api/v1/dashboard/submissions/:id/reply", func(c *fiber.Ctx) error {
		c.Locals("orgID", orgID.String())
		c.Locals("email", "editor@outlet.test")
		c.Locals("role", "responder")
		return ReplyToSubmission(c)
	})

	// Create submission with reply key
	sub := models.Submission{
		ID:             uuid.New(),
		OrganizationID: orgID,
		AnonymousName:  "Crimson Fox-1234",
		ReplyPublicKey: "c3VibWl0dGVyLXJlcGx5LXB1YmxpYy1rZXk=",
		HasReplyKey:    true,
	}
	models.DB.Create(&sub)

	// Attempt to reply with plaintext and no encrypted message
	payload := map[string]string{
		"message_text": "We received your tip and are looking into it (sent unencrypted).",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dashboard/submissions/"+sub.ID.String()+"/reply", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	// Security Assertion: Plaintext reply must be rejected when submission has reply key
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("SECURITY VIOLATION: Expected 400 Bad Request when replying with plaintext, got %d", resp.StatusCode)
	}

	var count int64
	models.DB.Model(&models.Reply{}).Where("submission_id = ?", sub.ID).Count(&count)
	if count != 0 {
		t.Errorf("SECURITY VIOLATION: Plaintext reply was stored in database! (found %d records)", count)
	}
}

func TestReplyToSubmission_AcceptsEncryptedPayload_WithCreated(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()

	orgID := uuid.New()
	app.Post("/api/v1/dashboard/submissions/:id/reply", func(c *fiber.Ctx) error {
		c.Locals("orgID", orgID.String())
		c.Locals("email", "editor@outlet.test")
		c.Locals("role", "responder")
		return ReplyToSubmission(c)
	})

	sub := models.Submission{
		ID:             uuid.New(),
		OrganizationID: orgID,
		AnonymousName:  "Silver Hawk-5678",
		ReplyPublicKey: "c3VibWl0dGVyLXJlcGx5LXB1YmxpYy1rZXk=",
		HasReplyKey:    true,
	}
	models.DB.Create(&sub)

	payload := map[string]string{
		"encrypted_message": "ZW5jcnlwdGVkLXJlcGx5LWNpcGhlcnRleHQ=",
		"encryption_meta":   `{"nonce":"111","encryptedKey":"222","boxNonce":"333","senderPublicKey":"444"}`,
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dashboard/submissions/"+sub.ID.String()+"/reply", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected 201 Created for encrypted reply, got %d", resp.StatusCode)
	}

	var reply models.Reply
	if err := models.DB.Where("submission_id = ?", sub.ID).First(&reply).Error; err != nil {
		t.Fatalf("Reply not found in database: %v", err)
	}
	if reply.EncryptedMessage != "ZW5jcnlwdGVkLXJlcGx5LWNpcGhlcnRleHQ=" {
		t.Errorf("Expected encrypted reply to be stored")
	}
}

func TestSubmitAnonymousTip_HoneypotField_SilentlyDiscardsSubmission(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Post("/api/v1/submit/:slug", SubmitAnonymousTip)

	org := models.Organization{
		ID:             uuid.New(),
		Name:           "Anti-Spam Target Org",
		Email:          "spam-target@org.test",
		SubmissionSlug: "honeypot-test-slug",
		PublicKey:      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
	}
	models.DB.Create(&org)

	// Automated bot submits encrypted tip but fills out the hidden non-semantic honeypot
	botPayload := map[string]interface{}{
		"encrypted_message": "dGVzdC1jaXBoZXJ0ZXh0",
		"encryption_meta":   `{"nonce":"123"}`,
		"honeypot_field":    "hp_bot_trap",
		"hp_bot_trap":       "https://automated-bot-spam.ru/buy-cheap",
		"rendered_at":       time.Now().Add(-10 * time.Second).UnixMilli(),
	}
	body, _ := json.Marshal(botPayload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/submit/honeypot-test-slug", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	// Security Assertion 1: Returns a normal-looking 201 Created (doesn't alert the bot)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected fake 201 Created response for bot honeypot trap, got %d", resp.StatusCode)
	}

	var respData map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&respData)
	if respData["submission_id"] == nil || respData["anonymous_name"] == nil {
		t.Errorf("Expected realistic submission response to fool bot, got %v", respData)
	}

	// Security Assertion 2: Discarded spam submission must NOT receive a signed proof
	if respData["proof"] != nil {
		t.Fatalf("SECURITY VIOLATION: Honeypot-discarded submission received a signed proof receipt!")
	}

	// Security Assertion 3: Must NOT write any records to the database
	var count int64
	models.DB.Model(&models.Submission{}).Where("organization_id = ?", org.ID).Count(&count)
	if count != 0 {
		t.Fatalf("SPAM VIOLATION: Honeypot-triggered submission was saved to the database! (count=%d)", count)
	}
}

func TestSubmitAnonymousTip_FastFillTime_SilentlyDiscardsSubmission(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Post("/api/v1/submit/:slug", SubmitAnonymousTip)

	org := models.Organization{
		ID:             uuid.New(),
		Name:           "Fast Fill Org",
		Email:          "fast-fill@org.test",
		SubmissionSlug: "fast-fill-slug",
		PublicKey:      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
	}
	models.DB.Create(&org)

	// Automated script submits 150ms after rendering (faster than humanly possible < 2000ms)
	fastPayload := map[string]interface{}{
		"encrypted_message": "dGVzdC1jaXBoZXJ0ZXh0",
		"encryption_meta":   `{"nonce":"123"}`,
		"rendered_at":       time.Now().Add(-150 * time.Millisecond).UnixMilli(),
	}
	body, _ := json.Marshal(fastPayload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/submit/fast-fill-slug", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	// Returns fake 201 Created
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected fake 201 Created response for fast fill, got %d", resp.StatusCode)
	}

	var respData map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&respData)

	// Security Assertion: Discarded fast-fill submission must NOT receive a signed proof
	if respData["proof"] != nil {
		t.Fatalf("SECURITY VIOLATION: Fast-fill discarded submission received a signed proof receipt!")
	}

	// Must NOT write to DB
	var count int64
	models.DB.Model(&models.Submission{}).Where("organization_id = ?", org.ID).Count(&count)
	if count != 0 {
		t.Fatalf("SPAM VIOLATION: Sub-2-second fast fill submission was saved to database! (count=%d)", count)
	}
}

func TestSubmitAnonymousTip_LegitimateHumanSubmission_PersistsToDatabase(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Post("/api/v1/submit/:slug", SubmitAnonymousTip)

	org := models.Organization{
		ID:             uuid.New(),
		Name:           "Human Submitter Org",
		Email:          "human@org.test",
		SubmissionSlug: "human-submitter-slug",
		PublicKey:      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
	}
	models.DB.Create(&org)

	// Real user: honeypot empty, fill time 15 seconds (> 2000ms).
	// Even if browser autofill populated "website" or "confirm_email", it is NOT treated as spam!
	humanPayload := map[string]interface{}{
		"encrypted_message": "dGVzdC1jaXBoZXJ0ZXh0",
		"encryption_meta":   `{"nonce":"123"}`,
		"honeypot_field":    "hp_user_view_982",
		"hp_user_view_982":  "",
		"website":           "https://user-personal-site.org", // Browser autofill filled website
		"confirm_email":     "autofill-user@example.com",      // Browser autofill filled email
		"rendered_at":       time.Now().Add(-15 * time.Second).UnixMilli(),
	}
	body, _ := json.Marshal(humanPayload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/submit/human-submitter-slug", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected 201 Created for legitimate submission, got %d", resp.StatusCode)
	}

	var respData map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&respData)

	// Security Assertion: Genuine submission MUST receive a real, signed proof
	proof, ok := respData["proof"].(map[string]interface{})
	if !ok || proof == nil {
		t.Fatalf("Expected legitimate submission to receive a signed proof receipt, got nil")
	}
	if proof["signature"] == nil || proof["hash"] == nil || proof["key_fingerprint"] == nil {
		t.Errorf("Proof missing expected cryptographic fields: %v", proof)
	}

	// Must persist to DB
	var count int64
	models.DB.Model(&models.Submission{}).Where("organization_id = ?", org.ID).Count(&count)
	if count != 1 {
		t.Fatalf("Expected legitimate submission to be saved in database, found %d", count)
	}
}

func TestSubmitAnonymousTip_SpamVsGenuine_ProofComparison(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Post("/api/v1/submit/:slug", SubmitAnonymousTip)

	org := models.Organization{
		ID:             uuid.New(),
		Name:           "Receipt Comparison Org",
		Email:          "receipts@org.test",
		SubmissionSlug: "receipts-slug",
		PublicKey:      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
	}
	models.DB.Create(&org)

	// 1. Genuine Human Submission
	genuinePayload := map[string]interface{}{
		"encrypted_message": "Z2VudWluZS1lbmNyeXB0ZWQtbWVzc2FnZQ==",
		"encryption_meta":   `{"nonce":"123"}`,
		"honeypot_field":    "hp_rnd_481",
		"hp_rnd_481":        "",
		"rendered_at":       time.Now().Add(-10 * time.Second).UnixMilli(),
	}
	genuineBody, _ := json.Marshal(genuinePayload)
	reqGenuine := httptest.NewRequest(http.MethodPost, "/api/v1/submit/receipts-slug", bytes.NewReader(genuineBody))
	reqGenuine.Header.Set("Content-Type", "application/json")
	respGenuine, err := app.Test(reqGenuine, 5000)
	if err != nil {
		t.Fatalf("Genuine request failed: %v", err)
	}
	if respGenuine.StatusCode != http.StatusCreated {
		t.Fatalf("Expected 201 Created, got %d", respGenuine.StatusCode)
	}
	var genuineData map[string]interface{}
	json.NewDecoder(respGenuine.Body).Decode(&genuineData)

	// 2. Spam Honeypot Submission
	spamPayload := map[string]interface{}{
		"encrypted_message": "c3BhbS1lbmNyeXB0ZWQtbWVzc2FnZQ==",
		"encryption_meta":   `{"nonce":"123"}`,
		"honeypot_field":    "hp_rnd_481",
		"hp_rnd_481":        "https://spambot-link.com",
		"rendered_at":       time.Now().Add(-10 * time.Second).UnixMilli(),
	}
	spamBody, _ := json.Marshal(spamPayload)
	reqSpam := httptest.NewRequest(http.MethodPost, "/api/v1/submit/receipts-slug", bytes.NewReader(spamBody))
	reqSpam.Header.Set("Content-Type", "application/json")
	respSpam, err := app.Test(reqSpam, 5000)
	if err != nil {
		t.Fatalf("Spam request failed: %v", err)
	}
	if respSpam.StatusCode != http.StatusCreated {
		t.Fatalf("Expected 201 Created for spam response, got %d", respSpam.StatusCode)
	}
	var spamData map[string]interface{}
	json.NewDecoder(respSpam.Body).Decode(&spamData)

	// Verification 1: Genuine submission MUST have proof field
	if genuineData["proof"] == nil {
		t.Fatalf("Verification failed: Genuine submission missing 'proof' field")
	}
	genuineProof := genuineData["proof"].(map[string]interface{})
	if genuineProof["signature"] == "" || genuineProof["hash"] == "" {
		t.Fatalf("Verification failed: Genuine proof missing signature or hash")
	}

	// Verification 2: Spam submission MUST NOT have proof field
	if _, exists := spamData["proof"]; exists && spamData["proof"] != nil {
		t.Fatalf("Verification failed: Spam submission has 'proof' field (%v)", spamData["proof"])
	}

	// Verification 3: Genuine has Merkle batch fields, spam has none
	if genuineData["batch_id"] == nil || genuineData["leaf_hash"] == nil {
		t.Errorf("Expected Merkle batch details in genuine response")
	}
	if spamData["batch_id"] != nil || spamData["leaf_hash"] != nil {
		t.Errorf("Spam response should not contain Merkle batch details")
	}

	prettyGenuine, _ := json.MarshalIndent(genuineData, "", "  ")
	prettySpam, _ := json.MarshalIndent(spamData, "", "  ")
	t.Logf("\n--- GENUINE SUBMISSION RESPONSE ---\n%s\n\n--- SPAM SUBMISSION RESPONSE ---\n%s\n", string(prettyGenuine), string(prettySpam))
}

func TestGetOrganizationPublicKey_ReturnsPGPScheme(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Get("/api/v1/submit/:slug/public-key", GetOrganizationPublicKey)

	pgpKey := "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: OpenPGP\n\nmQENBF...\n-----END PGP PUBLIC KEY BLOCK-----"
	org := models.Organization{
		ID:               uuid.New(),
		Name:             "PGP Investigative Desk",
		Email:            "desk@investigative.test",
		SubmissionSlug:   "pgp-desk-slug",
		PublicKey:        pgpKey,
		EncryptionScheme: "pgp",
	}
	models.DB.Create(&org)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/submit/pgp-desk-slug/public-key", nil)
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", resp.StatusCode)
	}

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)

	if data["encryption_scheme"] != "pgp" {
		t.Errorf("Expected encryption_scheme 'pgp', got %v", data["encryption_scheme"])
	}
	if data["public_key"] != pgpKey {
		t.Errorf("Expected PGP public key returned")
	}
}

func TestSubmitAnonymousTip_AcceptsPGPEncryptedTip(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Post("/api/v1/submit/:slug", SubmitAnonymousTip)

	org := models.Organization{
		ID:               uuid.New(),
		Name:             "PGP Whistleblower Desk",
		Email:            "whistle@pgp.test",
		SubmissionSlug:   "pgp-whistle-slug",
		PublicKey:        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQEN...\n-----END PGP PUBLIC KEY BLOCK-----",
		EncryptionScheme: "pgp",
	}
	models.DB.Create(&org)

	pgpCiphertext := "-----BEGIN PGP MESSAGE-----\nVersion: OpenPGP.js\n\nwcBMA6...\n-----END PGP MESSAGE-----"

	payload := map[string]interface{}{
		"encrypted_message": pgpCiphertext,
		"encryption_meta":   `{"scheme":"pgp"}`,
		"rendered_at":       time.Now().Add(-5 * time.Second).UnixMilli(),
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/submit/pgp-whistle-slug", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected 201 Created for PGP submission, got %d", resp.StatusCode)
	}

	var sub models.Submission
	if err := models.DB.Where("organization_id = ?", org.ID).First(&sub).Error; err != nil {
		t.Fatalf("Submission not found in DB: %v", err)
	}
	if sub.EncryptedMessage != pgpCiphertext {
		t.Errorf("Expected PGP ciphertext to be saved in DB")
	}
}
