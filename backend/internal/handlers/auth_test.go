package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestSignup_CreatesOrgWithHashedPasswordAndPublicKey(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Post("/api/v1/auth/signup", SignupOrganization)

	signupReq := map[string]string{
		"name":       "Freedom of the Press Org",
		"email":      "press@freedom.org",
		"password":   "SuperSecretPressPass123!",
		"public_key": "base64EncodedPublicKeySample1234567890=",
	}
	body, _ := json.Marshal(signupReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected status 201 Created, got %d", resp.StatusCode)
	}

	// Verify organization in database
	var org models.Organization
	if err := models.DB.Where("email = ?", "press@freedom.org").First(&org).Error; err != nil {
		t.Fatalf("Organization not saved in database: %v", err)
	}

	if org.Name != "Freedom of the Press Org" {
		t.Errorf("Expected name 'Freedom of the Press Org', got %s", org.Name)
	}
	if org.PublicKey != "base64EncodedPublicKeySample1234567890=" {
		t.Errorf("Expected public key to be saved, got %s", org.PublicKey)
	}
	if org.SubmissionSlug == "" {
		t.Errorf("Expected unique submission slug to be generated")
	}

	// Verify password was securely hashed (not stored in plaintext)
	if org.PasswordHash == "SuperSecretPressPass123!" {
		t.Fatalf("Security violation: Password stored in plaintext!")
	}
	match, err := crypto.VerifyPassword("SuperSecretPressPass123!", org.PasswordHash)
	if err != nil || !match {
		t.Errorf("Password hash verification failed: match=%v, err=%v", match, err)
	}
}

func TestLogin_IssuesSessionToken_WhenTOTPDisabled(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Post("/api/v1/auth/login", LoginOrganization)

	hashedPass, _ := crypto.HashPassword("ValidPassword123!")
	org := models.Organization{
		ID:           uuid.New(),
		Name:         "Standard Org",
		Email:        "standard@org.test",
		PasswordHash: hashedPass,
		TOTPEnabled:  false,
	}
	models.DB.Create(&org)

	loginReq := map[string]string{
		"email":    "standard@org.test",
		"password": "ValidPassword123!",
	}
	body, _ := json.Marshal(loginReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 OK, got %d", resp.StatusCode)
	}

	var respData map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&respData)

	token, ok := respData["token"].(string)
	if !ok || token == "" {
		t.Fatalf("Expected full session JWT token in response, got %v", respData["token"])
	}

	// Validate token
	claims, err := crypto.ValidateToken(token, config.AppConfig.JWTSecret)
	if err != nil {
		t.Fatalf("Generated token invalid: %v", err)
	}
	if claims.OrganizationID != org.ID.String() {
		t.Errorf("Expected org ID %s in token claims, got %s", org.ID.String(), claims.OrganizationID)
	}
}

func TestLogin_RequiresTOTP_WhenEnabled(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Post("/api/v1/auth/login", LoginOrganization)

	// Protected endpoint to verify pending token cannot be used as session token
	app.Get("/api/v1/dashboard", middleware.Protected(), func(c *fiber.Ctx) error {
		return c.SendString("dashboard access granted")
	})

	hashedPass, _ := crypto.HashPassword("SecurePassword123!")
	totpSecret, _, _ := crypto.GenerateTOTPSecret("2FA Org", "twofa@org.test")

	org := models.Organization{
		ID:           uuid.New(),
		Name:         "2FA Org",
		Email:        "twofa@org.test",
		PasswordHash: hashedPass,
		TOTPSecret:   totpSecret,
		TOTPEnabled:  true,
	}
	models.DB.Create(&org)

	// Attempt login with valid email/password but no 2FA
	loginReq := map[string]string{
		"email":    "twofa@org.test",
		"password": "SecurePassword123!",
	}
	body, _ := json.Marshal(loginReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	var respData map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&respData)

	// Security Assertion 1: Must indicate 2FA is required
	if respData["requires_2fa"] != true {
		t.Errorf("Expected requires_2fa=true, got %v", respData["requires_2fa"])
	}

	// Security Assertion 2: Must NOT return a session token
	if respData["token"] != nil {
		t.Fatalf("SECURITY VIOLATION: Full session token returned before 2FA verification: %v", respData["token"])
	}

	// Security Assertion 3: Pending token is issued
	pendingToken, ok := respData["pending_token"].(string)
	if !ok || pendingToken == "" {
		t.Fatalf("Expected pending_token in response, got %v", respData["pending_token"])
	}

	// Security Assertion 4: Pending token MUST NOT grant access to protected routes
	protReq := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard", nil)
	protReq.Header.Set("Authorization", "Bearer "+pendingToken)

	protResp, err := app.Test(protReq, 5000)
	if err != nil {
		t.Fatalf("Protected request failed: %v", err)
	}
	if protResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("SECURITY VIOLATION: Pending 2FA token was accepted on protected dashboard route (status %d)", protResp.StatusCode)
	}
}

func TestLogin2FA_IssuesSessionToken_WithValidTOTPCode(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Post("/api/v1/auth/login/2fa", Login2FA)

	totpSecret, _, _ := crypto.GenerateTOTPSecret("2FA Org", "twofa2@org.test")
	encryptedSecret, _ := crypto.EncryptTOTPSecret(totpSecret, config.AppConfig.TOTPEncryptionKey)
	org := models.Organization{
		ID:          uuid.New(),
		Name:        "2FA Org",
		Email:       "twofa2@org.test",
		TOTPSecret:  encryptedSecret,
		TOTPEnabled: true,
	}
	models.DB.Create(&org)

	pendingToken, err := crypto.GeneratePendingToken(org.ID, org.Email, config.AppConfig.JWTSecret)
	if err != nil {
		t.Fatalf("Failed to generate pending token: %v", err)
	}

	validCode, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate TOTP code: %v", err)
	}

	reqBody := map[string]string{
		"pending_token": pendingToken,
		"code":          validCode,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/2fa", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 OK, got %d", resp.StatusCode)
	}

	var respData map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&respData)

	sessionToken, ok := respData["token"].(string)
	if !ok || sessionToken == "" {
		t.Fatalf("Expected session token upon successful 2FA verification")
	}

	claims, err := crypto.ValidateToken(sessionToken, config.AppConfig.JWTSecret)
	if err != nil || claims.OrganizationID != org.ID.String() {
		t.Errorf("Invalid session token issued after 2FA: err=%v", err)
	}
}

func TestLogin2FA_RejectsInvalidTOTPCode_WithUnauthorized(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Post("/api/v1/auth/login/2fa", Login2FA)

	totpSecret, _, _ := crypto.GenerateTOTPSecret("2FA Org", "twofa3@org.test")
	encryptedSecret, _ := crypto.EncryptTOTPSecret(totpSecret, config.AppConfig.TOTPEncryptionKey)
	org := models.Organization{
		ID:          uuid.New(),
		Name:        "2FA Org",
		Email:       "twofa3@org.test",
		TOTPSecret:  encryptedSecret,
		TOTPEnabled: true,
	}
	models.DB.Create(&org)

	pendingToken, _ := crypto.GeneratePendingToken(org.ID, org.Email, config.AppConfig.JWTSecret)

	reqBody := map[string]string{
		"pending_token": pendingToken,
		"code":          "000000", // Deliberately invalid code
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/2fa", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected status 401 Unauthorized for invalid TOTP code, got %d", resp.StatusCode)
	}
}

func TestLogin2FA_RejectsInvalidPendingToken_WithUnauthorized(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Post("/api/v1/auth/login/2fa", Login2FA)

	reqBody := map[string]string{
		"pending_token": "forged.or.invalid.token",
		"code":          "123456",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/2fa", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected status 401 Unauthorized for invalid pending token, got %d", resp.StatusCode)
	}
}

func TestSignup_SupportsPGPEncryptionScheme(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Post("/api/v1/auth/signup", SignupOrganization)

	pgpPublicKeySample := "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: TestPGP\n\nmQENBF+SampleKey...\n-----END PGP PUBLIC KEY BLOCK-----"

	signupReq := map[string]string{
		"name":              "Air-gapped Press",
		"email":             "pgp@press.org",
		"password":          "StrongPassword123!",
		"public_key":        pgpPublicKeySample,
		"encryption_scheme": "pgp",
	}
	body, _ := json.Marshal(signupReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected status 201 Created, got %d", resp.StatusCode)
	}

	var respBody map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&respBody)
	orgData := respBody["organization"].(map[string]interface{})

	if orgData["encryption_scheme"] != "pgp" {
		t.Errorf("Expected encryption_scheme 'pgp' in response, got %v", orgData["encryption_scheme"])
	}

	var org models.Organization
	if err := models.DB.Where("email = ?", "pgp@press.org").First(&org).Error; err != nil {
		t.Fatalf("Organization not found in DB: %v", err)
	}
	if org.EncryptionScheme != "pgp" {
		t.Errorf("Expected org.EncryptionScheme 'pgp' in DB, got %s", org.EncryptionScheme)
	}
	if org.PublicKey != pgpPublicKeySample {
		t.Errorf("Expected armored PGP public key to be saved in DB")
	}
}

func TestRotatePublicKey_SwitchesToPGPScheme(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()

	org := models.Organization{
		ID:               uuid.New(),
		Name:             "Migrating Org",
		Email:            "migrate@org.test",
		PasswordHash:     "$argon2id$v=19$m=65536,t=3,p=2$sample",
		PublicKey:        "oldLibsodiumPublicKey123=",
		EncryptionScheme: "libsodium",
	}
	models.DB.Create(&org)

	token := CreateTestSessionToken(org.ID, org.Email)

	protected := app.Group("/api/v1/dashboard", middleware.Protected())
	protected.Put("/public-key", RotatePublicKey)

	newPGPKey := "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: OpenPGP.js\n\nmQGNBF...\n-----END PGP PUBLIC KEY BLOCK-----"

	reqBody := map[string]string{
		"public_key":        newPGPKey,
		"encryption_scheme": "pgp",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/dashboard/public-key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 OK, got %d", resp.StatusCode)
	}

	var updated models.Organization
	models.DB.First(&updated, "id = ?", org.ID)
	if updated.EncryptionScheme != "pgp" {
		t.Errorf("Expected scheme updated to 'pgp', got %s", updated.EncryptionScheme)
	}
	if updated.PublicKey != newPGPKey {
		t.Errorf("Expected public key updated to new PGP key")
	}
}

func TestLogin_CreatesDBSessionAndEmbedsSessionID(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Post("/api/v1/auth/login", LoginOrganization)

	passHash, _ := crypto.HashPassword("ValidPassword123!")
	org := models.Organization{
		ID:           uuid.New(),
		Name:         "Session Tracked Org",
		Email:        "session@tracked.test",
		PasswordHash: passHash,
	}
	models.DB.Create(&org)

	body, _ := json.Marshal(map[string]string{
		"email":    org.Email,
		"password": "ValidPassword123!",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", resp.StatusCode)
	}

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	tokenStr, ok := data["token"].(string)
	if !ok || tokenStr == "" {
		t.Fatalf("Expected token in login response")
	}

	// Validate claims embed session_id
	claims, err := crypto.ValidateToken(tokenStr, config.AppConfig.JWTSecret)
	if err != nil {
		t.Fatalf("Token validation error: %v", err)
	}
	if claims.SessionID == "" {
		t.Fatalf("Expected session_id claim embedded in JWT")
	}

	// Verify session row exists in DB
	var session models.Session
	if err := models.DB.Where("id = ? AND organization_id = ?", claims.SessionID, org.ID).First(&session).Error; err != nil {
		t.Fatalf("Session record not found in database: %v", err)
	}

	// Verify token hash matches raw token
	expectedHash := crypto.HashToken(tokenStr)
	if session.TokenHash != expectedHash {
		t.Errorf("Expected token hash %s, got %s", expectedHash, session.TokenHash)
	}
}

func TestProtected_RejectsRevokedSession_ImmediatelyWith401(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()

	org := models.Organization{
		ID:    uuid.New(),
		Name:  "Revocation Org",
		Email: "revoke@org.test",
	}
	models.DB.Create(&org)

	// Create valid session
	token := CreateTestSessionToken(org.ID, org.Email)
	claims, _ := crypto.ValidateToken(token, config.AppConfig.JWTSecret)

	protected := app.Group("/api/v1/dashboard", middleware.Protected())
	protected.Get("/test-guard", func(c *fiber.Ctx) error {
		return c.SendString("ACCESS_GRANTED")
	})

	// 1. Initial request succeeds
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/test-guard", nil)
	req1.Header.Set("Authorization", "Bearer "+token)
	resp1, _ := app.Test(req1, 5000)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK before revocation, got %d", resp1.StatusCode)
	}

	// 2. Revoke / delete session row in DB
	models.DB.Where("id = ?", claims.SessionID).Delete(&models.Session{})

	// 3. Subsequent request with same JWT must be immediately rejected with 401
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/test-guard", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	resp2, _ := app.Test(req2, 5000)
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("SECURITY VIOLATION: Revoked session was accepted with status %d (expected 401 Unauthorized)", resp2.StatusCode)
	}
}

func TestSession_RevokeAllOtherSessions_PreservesCurrentSession(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()

	org := models.Organization{
		ID:    uuid.New(),
		Name:  "Multi Session Org",
		Email: "multi@org.test",
	}
	models.DB.Create(&org)

	// Create 3 active sessions
	token1 := CreateTestSessionToken(org.ID, org.Email)
	_ = CreateTestSessionToken(org.ID, org.Email)
	_ = CreateTestSessionToken(org.ID, org.Email)

	var countBefore int64
	models.DB.Model(&models.Session{}).Where("organization_id = ?", org.ID).Count(&countBefore)
	if countBefore != 3 {
		t.Fatalf("Expected 3 sessions, found %d", countBefore)
	}

	protected := app.Group("/api/v1/dashboard", middleware.Protected())
	protected.Delete("/sessions", RevokeAllOtherSessions)
	protected.Get("/check", func(c *fiber.Ctx) error {
		return c.SendString("ACTIVE")
	})

	// Revoke other sessions using token1
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/dashboard/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token1)
	resp, _ := app.Test(req, 5000)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK from RevokeAllOtherSessions, got %d", resp.StatusCode)
	}

	// Check DB count: only 1 session left (token1)
	var countAfter int64
	models.DB.Model(&models.Session{}).Where("organization_id = ?", org.ID).Count(&countAfter)
	if countAfter != 1 {
		t.Fatalf("Expected 1 session remaining after bulk revoke, found %d", countAfter)
	}

	// Token1 still works
	reqCheck := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/check", nil)
	reqCheck.Header.Set("Authorization", "Bearer "+token1)
	respCheck, _ := app.Test(reqCheck, 5000)
	if respCheck.StatusCode != http.StatusOK {
		t.Fatalf("Expected current session token1 to still work (got %d)", respCheck.StatusCode)
	}
}

func TestAuthLogout_DeletesSessionRowAndRemovesFromActiveSessions(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()

	hashedPass, _ := crypto.HashPassword("SecurePass123!")
	org := models.Organization{
		ID:           uuid.New(),
		Name:         "Logout Test Org",
		Email:        "logout-test@org.test",
		PasswordHash: hashedPass,
		TOTPEnabled:  false,
	}
	models.DB.Create(&org)

	// Auth routes
	app.Post("/api/v1/auth/login", LoginOrganization)
	app.Post("/api/v1/auth/logout", middleware.Protected(), LogoutOrganization)
	dashboard := app.Group("/api/v1/dashboard", middleware.Protected())
	dashboard.Get("/sessions", ListActiveSessions)

	// 1. Log in to get initial session JWT
	loginReq := map[string]string{
		"email":    "logout-test@org.test",
		"password": "SecurePass123!",
	}
	body1, _ := json.Marshal(loginReq)
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body1))
	req1.Header.Set("Content-Type", "application/json")
	resp1, err := app.Test(req1, 5000)
	if err != nil || resp1.StatusCode != http.StatusOK {
		t.Fatalf("Login failed: status=%d, err=%v", resp1.StatusCode, err)
	}

	var loginData1 map[string]interface{}
	json.NewDecoder(resp1.Body).Decode(&loginData1)
	token1 := loginData1["token"].(string)

	claims1, err := crypto.ValidateToken(token1, config.AppConfig.JWTSecret)
	if err != nil || claims1.SessionID == "" {
		t.Fatalf("Failed to extract session ID from initial token: %v", err)
	}
	session1ID := claims1.SessionID

	// 2. Query active sessions with Token 1
	reqSessions1 := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/sessions", nil)
	reqSessions1.Header.Set("Authorization", "Bearer "+token1)
	respSessions1, _ := app.Test(reqSessions1, 5000)
	if respSessions1.StatusCode != http.StatusOK {
		t.Fatalf("Failed to list active sessions: %d", respSessions1.StatusCode)
	}

	var sessionList1 struct {
		Sessions []struct {
			ID        string `json:"id"`
			IsCurrent bool   `json:"is_current"`
		} `json:"sessions"`
	}
	json.NewDecoder(respSessions1.Body).Decode(&sessionList1)

	foundSession1 := false
	for _, s := range sessionList1.Sessions {
		if s.ID == session1ID && s.IsCurrent {
			foundSession1 = true
			break
		}
	}
	if !foundSession1 {
		t.Fatalf("Expected session %s in initial active sessions list", session1ID)
	}

	// 3. Log out via POST /api/v1/auth/logout with Token 1
	reqLogout := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	reqLogout.Header.Set("Authorization", "Bearer "+token1)
	respLogout, _ := app.Test(reqLogout, 5000)
	if respLogout.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK from Logout, got %d", respLogout.StatusCode)
	}

	// 4. Verify session row in database is physically deleted
	var deletedSession models.Session
	err = models.DB.Where("id = ?", session1ID).First(&deletedSession).Error
	if err == nil {
		t.Fatalf("Expected session %s to be deleted from database, but it still exists", session1ID)
	}

	// 5. Verify Token 1 is now rejected on protected endpoints
	reqRejected := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/sessions", nil)
	reqRejected.Header.Set("Authorization", "Bearer "+token1)
	respRejected, _ := app.Test(reqRejected, 5000)
	if respRejected.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized after logout, got %d", respRejected.StatusCode)
	}

	// 6. Log back in to get a new session (Token 2)
	body2, _ := json.Marshal(loginReq)
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	resp2, _ := app.Test(req2, 5000)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("Second login failed: %d", resp2.StatusCode)
	}

	var loginData2 map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&loginData2)
	token2 := loginData2["token"].(string)

	claims2, _ := crypto.ValidateToken(token2, config.AppConfig.JWTSecret)
	session2ID := claims2.SessionID
	if session2ID == session1ID {
		t.Fatalf("New session should have a new ID, got identical ID %s", session2ID)
	}

	// 7. Query active sessions with Token 2: Confirm old session ID is NOT in the list
	reqSessions2 := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/sessions", nil)
	reqSessions2.Header.Set("Authorization", "Bearer "+token2)
	respSessions2, _ := app.Test(reqSessions2, 5000)
	if respSessions2.StatusCode != http.StatusOK {
		t.Fatalf("Failed to query sessions on second login: %d", respSessions2.StatusCode)
	}

	var sessionList2 struct {
		Sessions []struct {
			ID        string `json:"id"`
			IsCurrent bool   `json:"is_current"`
		} `json:"sessions"`
	}
	json.NewDecoder(respSessions2.Body).Decode(&sessionList2)

	for _, s := range sessionList2.Sessions {
		if s.ID == session1ID {
			t.Fatalf("Old session ID %s still present in active sessions list after logout!", session1ID)
		}
	}

	foundSession2 := false
	for _, s := range sessionList2.Sessions {
		if s.ID == session2ID && s.IsCurrent {
			foundSession2 = true
			break
		}
	}
	if !foundSession2 {
		t.Fatalf("New session %s not found in active sessions list", session2ID)
	}
}
