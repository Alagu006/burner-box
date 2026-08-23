package handlers

import (
	"burner-box-backend/internal/config"
	"burner-box-backend/internal/crypto"
	"burner-box-backend/internal/models"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type SignupRequest struct {
	Name      string `json:"name" validate:"required,min=2,max=255"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8,max=128"`
	PublicKey string `json:"public_key"` // NEW: Organization's public key for E2EE
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
		Name:         req.Name,
		Email:        req.Email,
		PasswordHash: hashedPassword,
		PublicKey:    req.PublicKey, // NEW
	}

	if err := models.DB.Create(&org).Error; err != nil {
		log.Printf("AUTH_SIGNUP failed: DB create error: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to create organization",
		})
	}

	// Return success with submission URL
	log.Printf("AUTH_SIGNUP success: org=%s email=%s", org.ID, req.Email)
	return c.Status(201).JSON(fiber.Map{
		"message": "Organization created successfully",
		"organization": fiber.Map{
			"id":              org.ID,
			"name":            org.Name,
			"email":           org.Email,
			"submission_slug": org.SubmissionSlug,
			"public_key":      org.PublicKey, // NEW
			"submission_url":  "/submit/" + org.SubmissionSlug,
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

	// No 2FA — issue full session JWT
	token, err := crypto.GenerateToken(org.ID, org.Email, cfg.JWTSecret)
	if err != nil {
		log.Printf("AUTH_LOGIN failed: JWT gen error for org=%s: %v", org.ID, err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to generate token",
		})
	}

	log.Printf("AUTH_LOGIN success: org=%s", org.ID)
	return c.Status(200).JSON(fiber.Map{
		"message": "Login successful",
		"token":   token,
		"organization": fiber.Map{
			"id":              org.ID,
			"name":            org.Name,
			"email":           org.Email,
			"submission_slug": org.SubmissionSlug,
			"totp_enabled":    org.TOTPEnabled,
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
		log.Printf("AUTH_2FA rejected: invalid pending token")
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

	// Issue the real session JWT
	token, err := crypto.GenerateToken(org.ID, org.Email, cfg.JWTSecret)
	if err != nil {
		log.Printf("AUTH_2FA failed: JWT gen error for org=%s: %v", orgID, err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to generate token",
		})
	}

	log.Printf("AUTH_2FA success: org=%s", orgID)
	return c.Status(200).JSON(fiber.Map{
		"message": "Login successful",
		"token":   token,
		"organization": fiber.Map{
			"id":              org.ID,
			"name":            org.Name,
			"email":           org.Email,
			"submission_slug": org.SubmissionSlug,
			"totp_enabled":    org.TOTPEnabled,
		},
	})
} // GetOrganization returns organization details (placeholder for now)
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
	PublicKey string `json:"public_key"`
}

// RotatePublicKey updates the organization's public key. The caller is
// responsible for re-encrypting any existing submissions client-side —
// the server only stores the new key.
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

	if err := models.DB.Model(&models.Organization{}).
		Where("id = ?", orgID).
		Update("public_key", req.PublicKey).Error; err != nil {
		log.Printf("KEY_ROTATE failed: DB update error for org=%s: %v", orgID, err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to update public key",
		})
	}

	log.Printf("KEY_ROTATE success: org=%s", orgID)
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
		"enabled":      dms.Enabled,
		"trigger_days": dms.TriggerDays,
		"action_type":  dms.ActionType,
		"last_login_at": dms.LastLoginAt,
		"triggered_at": dms.TriggeredAt,
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
		case "email":
			go SendDMSTriggerEmail(org, daysSinceLogin)
		case "publish":
			appendDMSPublishLog(org.ID.String(), daysSinceLogin)
		case "delete":
			log.Printf("DMS_TRIGGER delete: TODO — org=%s; destructive action not implemented", org.ID)
		}

		// Mark as triggered
		models.DB.Model(&dms).Update("triggered_at", now)
	}
}

// appendDMSPublishLog records which orgs had their dead man's switch triggered
// for the "publish" action. This writes to docs/DMS_RELEASED.md — a file that
// can be published as part of the warrant canary or transparency report.
//
// SECURITY: Only the org ID and trigger timestamp are recorded. No submission
// content or encrypted data is included — the server cannot decrypt it.
func appendDMSPublishLog(orgID string, daysSinceLogin int) {
	logPath := "docs/DMS_RELEASED.md"
	entry := fmt.Sprintf("- Org `%s` — DMS triggered on %s (%d days since last login)\n",
		orgID, time.Now().UTC().Format(time.RFC3339), daysSinceLogin)

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("DMS_PUBLISH failed: could not open %s: %v", logPath, err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(entry); err != nil {
		log.Printf("DMS_PUBLISH failed: write error: %v", err)
		return
	}
	log.Printf("DMS_PUBLISH appended: org=%s to=%s", orgID, logPath)
}
