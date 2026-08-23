package handlers

import (
	"burner-box-backend/internal/config"
	"burner-box-backend/internal/crypto"
	"burner-box-backend/internal/models"
	"log"

	"github.com/gofiber/fiber/v2"
)

type Setup2FAResponse struct {
	Secret    string `json:"secret"`
	QRCode    string `json:"qr_code"`
	ManualKey string `json:"manual_key"`
}

type Verify2FARequest struct {
	Code string `json:"code"`
}

// Setup2FA generates a new TOTP secret and QR code
func Setup2FA(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)
	email := c.Locals("email").(string)

	// Find organization
	var org models.Organization
	if err := models.DB.First(&org, "id = ?", orgID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Organization not found",
		})
	}

	// Generate TOTP secret
	secret, qrCode, err := crypto.GenerateTOTPSecret(org.Name, email)
	if err != nil {
		log.Printf("2FA_SETUP failed: TOTP gen error for org=%s: %v", orgID, err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to generate 2FA secret",
		})
	}

	// Store encrypted secret (temporarily until verified)
	encrypted, err := crypto.EncryptTOTPSecret(secret, config.AppConfig.TOTPEncryptionKey)
	if err != nil {
		log.Printf("2FA_SETUP failed: encrypt error for org=%s: %v", orgID, err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to encrypt 2FA secret",
		})
	}
	org.TOTPSecret = encrypted
	org.TOTPEnabled = false // Will be true after verification
	models.DB.Save(&org)

	log.Printf("2FA_SETUP success: org=%s (pending verification)", orgID)
	return c.JSON(Setup2FAResponse{
		Secret:    secret,
		QRCode:    qrCode,
		ManualKey: secret,
	})
}

// Verify2FA confirms the TOTP setup by checking a code
func Verify2FA(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)

	var req Verify2FARequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request",
		})
	}

	if req.Code == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Code is required",
		})
	}

	// Find organization
	var org models.Organization
	if err := models.DB.First(&org, "id = ?", orgID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Organization not found",
		})
	}

	// Validate the code
	secret, err := crypto.DecryptTOTPSecret(org.TOTPSecret, config.AppConfig.TOTPEncryptionKey)
	if err != nil {
		log.Printf("2FA_VERIFY failed: decrypt error for org=%s: %v", orgID, err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to decrypt 2FA secret",
		})
	}
	if !crypto.ValidateTOTPCode(secret, req.Code) {
		log.Printf("2FA_VERIFY rejected: invalid code for org=%s", orgID)
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid 2FA code",
		})
	}

	// Enable 2FA
	org.TOTPEnabled = true
	models.DB.Save(&org)

	log.Printf("2FA_VERIFY success: 2FA enabled for org=%s", orgID)
	return c.JSON(fiber.Map{
		"message": "2FA enabled successfully",
	})
}

// Disable2FA turns off 2FA (requires current 2FA code)
func Disable2FA(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)

	var req Verify2FARequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request",
		})
	}

	var org models.Organization
	if err := models.DB.First(&org, "id = ?", orgID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Organization not found",
		})
	}

	// Verify current code before disabling
	secret, err := crypto.DecryptTOTPSecret(org.TOTPSecret, config.AppConfig.TOTPEncryptionKey)
	if err != nil {
		log.Printf("2FA_DISABLE failed: decrypt error for org=%s: %v", orgID, err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to decrypt 2FA secret",
		})
	}
	if !crypto.ValidateTOTPCode(secret, req.Code) {
		log.Printf("2FA_DISABLE rejected: invalid code for org=%s", orgID)
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid 2FA code",
		})
	}

	org.TOTPEnabled = false
	org.TOTPSecret = ""
	models.DB.Save(&org)

	log.Printf("2FA_DISABLE success: org=%s", orgID)
	return c.JSON(fiber.Map{
		"message": "2FA disabled successfully",
	})
}

// Check2FAStatus returns whether 2FA is enabled
func Check2FAStatus(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)

	var org models.Organization
	if err := models.DB.First(&org, "id = ?", orgID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Organization not found",
		})
	}

	return c.JSON(fiber.Map{
		"totp_enabled": org.TOTPEnabled,
	})
}