package handlers

import (
	"burner-box-backend/internal/config"
	"burner-box-backend/internal/crypto"
	"burner-box-backend/internal/models"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type SignupRequest struct {
	Name             string `json:"name" validate:"required,min=2,max=255"`
	Email            string `json:"email" validate:"required,email"`
	Password         string `json:"password" validate:"required,min=8,max=128"`
	PublicKey        string `json:"public_key"`
	EncryptionScheme string `json:"encryption_scheme"` // "libsodium" | "pgp"
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// SignupOrganization handles organization registration
func SignupOrganization(c *fiber.Ctx) error {
	var req SignupRequest

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate required fields
	if req.Name == "" || req.Email == "" || req.Password == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Name, email, and password are required",
		})
	}

	if len(req.Name) > MaxNameLength {
		return c.Status(400).JSON(fiber.Map{
			"error": "Name too long",
		})
	}
	if len(req.Email) > MaxEmailLength {
		return c.Status(400).JSON(fiber.Map{
			"error": "Email too long",
		})
	}

	if len(req.Password) < 8 {
		return c.Status(400).JSON(fiber.Map{
			"error": "Password must be at least 8 characters",
		})
	}

	scheme := req.EncryptionScheme
	if scheme == "" {
		scheme = "libsodium"
	}
	if scheme != "libsodium" && scheme != "pgp" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid encryption_scheme: must be 'libsodium' or 'pgp'",
		})
	}

	// Check if email already exists
	var existing models.Organization
	result := models.DB.Where("email = ?", req.Email).First(&existing)
	if result.RowsAffected > 0 {
		log.Printf("AUTH_SIGNUP rejected: email already exists (%s)", req.Email)
		return c.Status(409).JSON(fiber.Map{
			"error": "An organization with this email already exists",
		})
	}

	// Hash the password
	hashedPassword, err := crypto.HashPassword(req.Password)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to process password",
		})
	}

	// Create organization
	org := models.Organization{
		Name:             req.Name,
		Email:            req.Email,
		PasswordHash:     hashedPassword,
		PublicKey:        req.PublicKey,
		EncryptionScheme: scheme,
	}

	if err := models.DB.Create(&org).Error; err != nil {
		log.Printf("AUTH_SIGNUP failed: DB create error: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to create organization",
		})
	}

	// Return success with submission URL
	log.Printf("AUTH_SIGNUP success: org=%s email=%s scheme=%s", org.ID, req.Email, scheme)
	return c.Status(201).JSON(fiber.Map{
		"message": "Organization created successfully",
		"organization": fiber.Map{
			"id":                org.ID,
			"name":              org.Name,
			"email":             org.Email,
			"submission_slug":   org.SubmissionSlug,
			"public_key":        org.PublicKey,
			"encryption_scheme": org.EncryptionScheme,
			"submission_url":    "/submit/" + org.SubmissionSlug,
		},
	})
}

// LoginOrganization handles organization login
func LoginOrganization(c *fiber.Ctx) error {
	var req LoginRequest

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if req.Email == "" || req.Password == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Find organization by email
	var org models.Organization
	result := models.DB.Where("email = ?", req.Email).First(&org)
	if result.Error != nil {
		log.Printf("AUTH_LOGIN rejected: org not found for email=%s", req.Email)
		return c.Status(401).JSON(fiber.Map{
			"error": "Invalid credentials",
		})
	}

	// Verify password
	match, err := crypto.VerifyPassword(req.Password, org.PasswordHash)
	if err != nil || !match {
		log.Printf("AUTH_LOGIN rejected: wrong password for org=%s", org.ID)
		return c.Status(401).JSON(fiber.Map{
			"error": "Invalid credentials",
		})
	}

	cfg := config.AppConfig

	// If 2FA is enabled, issue a short-lived pending token instead
	if org.TOTPEnabled {
		pendingToken, err := crypto.GeneratePendingToken(org.ID, org.Email, cfg.JWTSecret)
		if err != nil {
			log.Printf("AUTH_LOGIN failed: pending token gen error for org=%s: %v", org.ID, err)
			return c.Status(500).JSON(fiber.Map{
				"error": "Failed to generate token",
			})
		}
		log.Printf("AUTH_LOGIN 2FA required: org=%s", org.ID)
		return c.Status(200).JSON(fiber.Map{
			"requires_2fa":  true,
			"pending_token": pendingToken,
		})
	}

	// No 2FA — create stateful session and issue session-backed JWT
	token, session, err := createSessionAndToken(org.ID, org.Email)
	if err != nil {
		log.Printf("AUTH_LOGIN failed: session/JWT gen error for org=%s: %v", org.ID, err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to generate session",
		})
	}

	log.Printf("AUTH_LOGIN success: org=%s session=%s", org.ID, session.ID)
	return c.Status(200).JSON(fiber.Map{
		"message": "Login successful",
		"token":   token,
		"organization": fiber.Map{
			"id":                org.ID,
			"name":              org.Name,
			"email":             org.Email,
			"submission_slug":   org.SubmissionSlug,
			"totp_enabled":      org.TOTPEnabled,
			"encryption_scheme": org.EncryptionScheme,
			"public_key":        org.PublicKey,
		},
	})
}

// Login2FARequest is the body for the 2FA verification step
type Login2FARequest struct {
	PendingToken string `json:"pending_token"`
	Code         string `json:"code"`
}

// Login2FA verifies a TOTP code against a pending token and issues the real JWT
func Login2FA(c *fiber.Ctx) error {
	var req Login2FARequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if req.PendingToken == "" || req.Code == "" {
		return c.Status(401).JSON(fiber.Map{
			"error": "Invalid credentials",
		})
	}

	cfg := config.AppConfig

	// Validate the pending token
	claims, err := crypto.ValidatePendingToken(req.PendingToken, cfg.JWTSecret)
	if err != nil {
		log.Printf("AUTH_2FA rejected: invalid pending token: %v", err)
		return c.Status(401).JSON(fiber.Map{
			"error": "Invalid credentials",
		})
	}

	// Find organization
	orgID, err := uuid.Parse(claims.OrganizationID)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{
			"error": "Invalid credentials",
		})
	}

	var org models.Organization
	if err := models.DB.First(&org, "id = ?", orgID).Error; err != nil {
		return c.Status(401).JSON(fiber.Map{
			"error": "Invalid credentials",
		})
	}

	// Decrypt TOTP secret and validate the code
	secret, err := crypto.DecryptTOTPSecret(org.TOTPSecret, cfg.TOTPEncryptionKey)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{
			"error": "Invalid credentials",
		})
	}

	if !crypto.ValidateTOTPCode(secret, req.Code) {
		log.Printf("AUTH_2FA rejected: invalid TOTP code for org=%s", orgID)
		return c.Status(401).JSON(fiber.Map{
			"error": "Invalid credentials",
		})
	}

	// Issue the stateful session JWT
	token, session, err := createSessionAndToken(org.ID, org.Email)
	if err != nil {
		log.Printf("AUTH_2FA failed: session/JWT gen error for org=%s: %v", orgID, err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to generate session",
		})
	}

	log.Printf("AUTH_2FA success: org=%s session=%s", orgID, session.ID)
	return c.Status(200).JSON(fiber.Map{
		"message": "Login successful",
		"token":   token,
		"organization": fiber.Map{
			"id":                org.ID,
			"name":              org.Name,
			"email":             org.Email,
			"submission_slug":   org.SubmissionSlug,
			"totp_enabled":      org.TOTPEnabled,
			"encryption_scheme": org.EncryptionScheme,
			"public_key":        org.PublicKey,
		},
	})
}

// createSessionAndToken provision a database-backed session and returns the signed JWT
func createSessionAndToken(orgID uuid.UUID, email string) (string, *models.Session, error) {
	cfg := config.AppConfig
	sessionID := uuid.New()
	token, err := crypto.GenerateTokenWithSession(orgID, email, sessionID, cfg.JWTSecret)
	if err != nil {
		return "", nil, err
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
		return "", nil, err
	}

	return token, &session, nil
}

// ListActiveSessions returns all valid active sessions for the authenticated organization
func ListActiveSessions(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)
	currentSessionID, _ := c.Locals("sessionID").(string)

	var sessions []models.Session
	now := time.Now()
	if err := models.DB.Where("organization_id = ? AND expires_at > ?", orgID, now).
		Order("created_at desc").
		Find(&sessions).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to retrieve sessions",
		})
	}

	type SessionResponse struct {
		ID         uuid.UUID `json:"id"`
		CreatedAt  time.Time `json:"created_at"`
		LastSeenAt time.Time `json:"last_seen_at"`
		ExpiresAt  time.Time `json:"expires_at"`
		IsCurrent  bool      `json:"is_current"`
	}

	result := make([]SessionResponse, len(sessions))
	for i, s := range sessions {
		result[i] = SessionResponse{
			ID:         s.ID,
			CreatedAt:  s.CreatedAt,
			LastSeenAt: s.LastSeenAt,
			ExpiresAt:  s.ExpiresAt,
			IsCurrent:  s.ID.String() == currentSessionID,
		}
	}

	return c.JSON(fiber.Map{
		"sessions": result,
	})
}

// RevokeSession deletes a specific session by ID for the organization
func RevokeSession(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)
	sessionID := c.Params("id")

	targetUUID, err := uuid.Parse(sessionID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid session ID format",
		})
	}

	res := models.DB.Where("id = ? AND organization_id = ?", targetUUID, orgID).Delete(&models.Session{})
	if res.Error != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to revoke session",
		})
	}

	if res.RowsAffected == 0 {
		return c.Status(404).JSON(fiber.Map{
			"error": "Session not found",
		})
	}

	log.Printf("SESSION_REVOKE success: session=%s org=%s", sessionID, orgID)
	return c.JSON(fiber.Map{
		"message": "Session revoked successfully",
	})
}

// RevokeAllOtherSessions deletes all active sessions for the org except the caller's active session
func RevokeAllOtherSessions(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)
	currentSessionID, _ := c.Locals("sessionID").(string)

	currentUUID, err := uuid.Parse(currentSessionID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid current session",
		})
	}

	res := models.DB.Where("organization_id = ? AND id != ?", orgID, currentUUID).Delete(&models.Session{})
	if res.Error != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to revoke other sessions",
		})
	}

	log.Printf("SESSION_REVOKE_ALL success: org=%s revoked_count=%d preserved_current=%s", orgID, res.RowsAffected, currentSessionID)
	return c.JSON(fiber.Map{
		"message":       "All other sessions revoked successfully",
		"revoked_count": res.RowsAffected,
	})
}

// LogoutOrganization immediately revokes the current session
func LogoutOrganization(c *fiber.Ctx) error {
	currentSessionID, ok := c.Locals("sessionID").(string)
	if ok && currentSessionID != "" {
		models.DB.Where("id = ?", currentSessionID).Delete(&models.Session{})
		log.Printf("AUTH_LOGOUT success: session=%s", currentSessionID)
	}

	return c.JSON(fiber.Map{
		"message": "Logged out successfully",
	})
}

// GetOrganization returns organization details (placeholder for now)
func GetOrganization(c *fiber.Ctx) error {
	id := c.Params("id")

	orgID, err := uuid.Parse(id)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid organization ID",
		})
	}

	var org models.Organization
	result := models.DB.Preload("TeamMembers").First(&org, orgID)
	if result.Error != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Organization not found",
		})
	}

	return c.JSON(fiber.Map{
		"organization": org,
	})
}

type RotateKeyRequest struct {
	PublicKey        string `json:"public_key"`
	EncryptionScheme string `json:"encryption_scheme,omitempty"`
}

// RotatePublicKey updates the organization's public key and optionally its scheme.
func RotatePublicKey(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)

	var req RotateKeyRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if req.PublicKey == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "public_key is required",
		})
	}

	updates := map[string]interface{}{
		"public_key": req.PublicKey,
	}
	if req.EncryptionScheme != "" {
		if req.EncryptionScheme != "libsodium" && req.EncryptionScheme != "pgp" {
			return c.Status(400).JSON(fiber.Map{
				"error": "Invalid encryption_scheme: must be 'libsodium' or 'pgp'",
			})
		}
		updates["encryption_scheme"] = req.EncryptionScheme
	}

	if err := models.DB.Model(&models.Organization{}).
		Where("id = ?", orgID).
		Updates(updates).Error; err != nil {
		log.Printf("KEY_ROTATE failed: DB update error for org=%s: %v", orgID, err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to update public key",
		})
	}

	log.Printf("KEY_ROTATE success: org=%s scheme=%v", orgID, req.EncryptionScheme)
	return c.JSON(fiber.Map{
		"message": "Public key updated successfully. Remember to re-encrypt existing submissions client-side.",
	})
}

type DeadMansSwitchRequest struct {
	Enabled     bool   `json:"enabled"`
	TriggerDays int    `json:"trigger_days"`
	ActionType  string `json:"action_type"` // "email", "publish", "delete"
	Password    string `json:"password"`    // required when enabling
	TOTPCode    string `json:"totp_code"`   // required when enabling if TOTP is active
}

// GetDeadMansSwitch returns the dead man's switch config for the org.
func GetDeadMansSwitch(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)

	var dms models.DeadMansSwitch
	if err := models.DB.Where("organization_id = ?", orgID).First(&dms).Error; err != nil {
		// No config yet — return defaults
		return c.JSON(fiber.Map{
			"enabled":      false,
			"trigger_days": 30,
			"action_type":  "email",
		})
	}

	return c.JSON(fiber.Map{
		"enabled":       dms.Enabled,
		"trigger_days":  dms.TriggerDays,
		"action_type":   dms.ActionType,
		"last_login_at": dms.LastLoginAt,
		"triggered_at":  dms.TriggeredAt,
	})
}

// UpdateDeadMansSwitch creates or updates the dead man's switch config.
// Requires password confirmation.
func UpdateDeadMansSwitch(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)

	var req DeadMansSwitchRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if req.TriggerDays < 1 || req.TriggerDays > 365 {
		return c.Status(400).JSON(fiber.Map{
			"error": "Trigger days must be between 1 and 365",
		})
	}

	validActions := map[string]bool{"email": true, "publish": true, "delete": true}
	if !validActions[req.ActionType] {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid action type. Must be: email, publish, or delete",
		})
	}

	// Re-authentication: when enabling the dead man's switch, require password
	// and (if 2FA is active) TOTP code. This prevents an attacker who holds a
	// session token from silently enabling the switch on a victim's account.
	if req.Enabled {
		var org models.Organization
		if err := models.DB.Where("id = ?", orgID).First(&org).Error; err != nil {
			log.Printf("DMS_UPDATE re-auth failed: org lookup error for org=%s: %v", orgID, err)
			return c.Status(500).JSON(fiber.Map{"error": "Internal error"})
		}

		if req.Password == "" {
			return c.Status(401).JSON(fiber.Map{
				"error": "Password is required to enable the dead man's switch",
			})
		}

		ok, err := crypto.VerifyPassword(req.Password, org.PasswordHash)
		if err != nil || !ok {
			log.Printf("DMS_UPDATE re-auth rejected: invalid password for org=%s", orgID)
			return c.Status(401).JSON(fiber.Map{
				"error": "Invalid password",
			})
		}

		if org.TOTPEnabled {
			if req.TOTPCode == "" {
				return c.Status(401).JSON(fiber.Map{
					"error": "Two-factor code is required",
				})
			}
			plainSecret, err := crypto.DecryptTOTPSecret(org.TOTPSecret, config.AppConfig.TOTPEncryptionKey)
			if err != nil {
				log.Printf("DMS_UPDATE re-auth failed: TOTP decrypt error for org=%s: %v", orgID, err)
				return c.Status(500).JSON(fiber.Map{"error": "Internal error"})
			}
			if !crypto.ValidateTOTPCode(plainSecret, req.TOTPCode) {
				log.Printf("DMS_UPDATE re-auth rejected: invalid TOTP for org=%s", orgID)
				return c.Status(401).JSON(fiber.Map{
					"error": "Invalid two-factor code",
				})
			}
		}
	}

	var dms models.DeadMansSwitch
	result := models.DB.Where("organization_id = ?", orgID).First(&dms)

	if result.Error != nil {
		// Create new
		dms = models.DeadMansSwitch{
			OrganizationID: uuid.MustParse(orgID),
			Enabled:        req.Enabled,
			TriggerDays:    req.TriggerDays,
			ActionType:     req.ActionType,
			LastLoginAt:    time.Now(),
		}
		if err := models.DB.Create(&dms).Error; err != nil {
			log.Printf("DMS_UPDATE failed: DB create error for org=%s: %v", orgID, err)
			return c.Status(500).JSON(fiber.Map{
				"error": "Failed to save dead man's switch",
			})
		}
	} else {
		// Update existing
		updates := map[string]interface{}{
			"enabled":      req.Enabled,
			"trigger_days": req.TriggerDays,
			"action_type":  req.ActionType,
		}
		if err := models.DB.Model(&dms).Updates(updates).Error; err != nil {
			log.Printf("DMS_UPDATE failed: DB update error for org=%s: %v", orgID, err)
			return c.Status(500).JSON(fiber.Map{
				"error": "Failed to update dead man's switch",
			})
		}
	}

	log.Printf("DMS_UPDATE success: org=%s enabled=%v days=%d action=%s", orgID, req.Enabled, req.TriggerDays, req.ActionType)
	return c.JSON(fiber.Map{
		"message": "Dead man's switch updated",
	})
}

// CheckDeadManSwitches is a background task that checks all enabled dead man's
// switches and triggers actions when the login threshold is exceeded.
// Called periodically from main.go.
func CheckDeadManSwitches() {
	var switches []models.DeadMansSwitch
	models.DB.Where("enabled = true").Find(&switches)

	now := time.Now()
	for _, dms := range switches {
		daysSinceLogin := int(now.Sub(dms.LastLoginAt).Hours() / 24)
		if daysSinceLogin < dms.TriggerDays {
			continue
		}

		// Don't re-trigger if already triggered within this cycle
		if dms.TriggeredAt != nil && dms.TriggeredAt.After(dms.LastLoginAt) {
			continue
		}

		// Fetch org for email
		var org models.Organization
		if err := models.DB.First(&org, "id = ?", dms.OrganizationID).Error; err != nil {
			continue
		}

		log.Printf("DMS_TRIGGER: org=%s days_since_login=%d action=%s", org.ID, daysSinceLogin, dms.ActionType)

		switch dms.ActionType {
		case "publish":
			publishDMSTriggerStatement(org, daysSinceLogin)
		case "email":
			go SendDMSTriggerEmail(org, daysSinceLogin)
		case "delete":
			var subs []models.Submission
			models.DB.Where("organization_id = ?", org.ID).Find(&subs)
			for _, sub := range subs {
				var files []models.SubmissionFile
				models.DB.Where("submission_id = ?", sub.ID).Find(&files)
				for _, f := range files {
					os.Remove("uploads/" + f.StorageKey)
				}
				models.DB.Where("submission_id = ?", sub.ID).Delete(&models.SubmissionFile{})
				models.DB.Where("submission_id = ?", sub.ID).Delete(&models.Reply{})
				models.DB.Where("submission_id = ?", sub.ID).Delete(&models.SubmissionMessage{})
				models.DB.Where("submission_id = ?", sub.ID).Delete(&models.InternalNote{})
				models.DB.Where("submission_id = ?", sub.ID).Delete(&models.Activity{})
				models.DB.Delete(&sub)
			}
			log.Printf("DMS_TRIGGER delete: successfully wiped %d submissions and files for org=%s", len(subs), org.ID)
		default:
			log.Printf("DMS_TRIGGER unknown action: %s for org=%s", dms.ActionType, org.ID)
		}

		// Mark as triggered
		models.DB.Model(&dms).Update("triggered_at", now)
	}
}

// publishDMSTriggerStatement updates the warrant canary transparency record
// to publish the emergency notice when an organization's dead man's switch triggers.
func publishDMSTriggerStatement(org models.Organization, daysSinceLogin int) {
	triggerTime := time.Now().UTC().Format(time.RFC3339)
	entry := fmt.Sprintf("\n\n## ⚠️ Dead Man's Switch Triggered Alert\n\n- **Organization:** %s\n- **Organization ID:** `%s`\n- **Triggered Timestamp:** %s\n- **Inactivity Period:** %d days without login\n- **Notice:** The dead man's switch for this organization was triggered automatically due to lack of administrative check-in beyond the configured threshold.\n",
		org.Name, org.ID.String(), triggerTime, daysSinceLogin)

	canaryPaths := []string{"docs/WARRANT_CANARY.md", "../docs/WARRANT_CANARY.md"}
	canaryUpdated := false
	for _, path := range canaryPaths {
		if _, err := os.Stat(path); err == nil {
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
			if err == nil {
				if _, err := f.WriteString(entry); err == nil {
					canaryUpdated = true
				}
				f.Close()
			}
		}
	}

	appendDMSPublishLog(org.ID.String(), daysSinceLogin)

	if canaryUpdated {
		log.Printf("DMS_PUBLISH success: published alert to warrant canary for org=%s", org.ID)
	} else {
		log.Printf("DMS_PUBLISH: updated DMS_RELEASED.md log for org=%s", org.ID)
	}
}

// appendDMSPublishLog records which orgs had their dead man's switch triggered
// for the "publish" action. This writes to docs/DMS_RELEASED.md — a file that
// can be published as part of the warrant canary or transparency report.
//
// SECURITY: Only the org ID and trigger timestamp are recorded. No submission
// content or encrypted data is included — the server cannot decrypt it.
func appendDMSPublishLog(orgID string, daysSinceLogin int) {
	logPaths := []string{"docs/DMS_RELEASED.md", "../docs/DMS_RELEASED.md"}
	entry := fmt.Sprintf("- Org `%s` — DMS triggered on %s (%d days since last login)\n",
		orgID, time.Now().UTC().Format(time.RFC3339), daysSinceLogin)

	for _, logPath := range logPaths {
		dir := filepath.Dir(logPath)
		if _, err := os.Stat(dir); err == nil {
			f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				f.WriteString(entry)
				f.Close()
				log.Printf("DMS_PUBLISH appended: org=%s to=%s", orgID, logPath)
				return
			}
		}
	}
	log.Printf("DMS_PUBLISH notice: org=%s triggered (%d days since login)", orgID, daysSinceLogin)
}
