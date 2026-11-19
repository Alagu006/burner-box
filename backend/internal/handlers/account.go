package handlers

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"burner-box-backend/internal/config"
	"burner-box-backend/internal/crypto"
	"burner-box-backend/internal/models"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

type DeleteAccountRequest struct {
	Password string `json:"password"`
	Code     string `json:"code,omitempty"`
	TOTPCode string `json:"totp_code,omitempty"`
}

// DeleteAccount permanently hard-deletes an organization and all associated data.
// Admin role only. Requires password verification and TOTP code (if 2FA is enabled).
func DeleteAccount(c *fiber.Ctx) error {
	orgID, ok := c.Locals("orgID").(string)
	if !ok || orgID == "" {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	role, _ := c.Locals("role").(string)
	if role != "admin" {
		return c.Status(http.StatusForbidden).JSON(fiber.Map{
			"error": "Only organization administrators can delete the account",
		})
	}

	var req DeleteAccountRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if strings.TrimSpace(req.Password) == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Password is required to delete your account",
		})
	}

	// Fetch organization record
	var org models.Organization
	if err := models.DB.Where("id = ?", orgID).First(&org).Error; err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": "Organization not found",
		})
	}

	// 1. Verify password
	valid, err := crypto.VerifyPassword(req.Password, org.PasswordHash)
	if err != nil || !valid {
		log.Printf("ACCOUNT_DELETE rejected: invalid password for org=%s", orgID)
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid password",
		})
	}

	// 2. Verify 2FA if enabled on the organization
	if org.TOTPEnabled {
		totpCode := strings.TrimSpace(req.TOTPCode)
		if totpCode == "" {
			totpCode = strings.TrimSpace(req.Code)
		}
		if totpCode == "" {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"error": "Two-factor authentication code is required",
			})
		}

		secret, err := crypto.DecryptTOTPSecret(org.TOTPSecret, config.AppConfig.TOTPEncryptionKey)
		if err != nil || !crypto.ValidateTOTPCode(secret, totpCode) {
			log.Printf("ACCOUNT_DELETE rejected: invalid TOTP code for org=%s", orgID)
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid two-factor authentication code",
			})
		}
	}

	// 3. Find all submissions for this org to delete files from disk
	var submissions []models.Submission
	models.DB.Where("organization_id = ?", org.ID).Find(&submissions)

	for _, sub := range submissions {
		var files []models.SubmissionFile
		models.DB.Where("submission_id = ?", sub.ID).Find(&files)
		for _, f := range files {
			if f.StorageKey != "" {
				filePath := filepath.Join("uploads", f.StorageKey)
				os.Remove(filePath)
			}
		}
		// Also remove directory on disk
		subDir := filepath.Join("uploads", "submissions", sub.ID.String())
		os.RemoveAll(subDir)
	}

	// 4. Hard-delete all associated database records atomically
	err = models.DB.Transaction(func(tx *gorm.DB) error {
		for _, sub := range submissions {
			if err := tx.Where("submission_id = ?", sub.ID).Delete(&models.SubmissionFile{}).Error; err != nil {
				return err
			}
			if err := tx.Where("submission_id = ?", sub.ID).Delete(&models.Reply{}).Error; err != nil {
				return err
			}
			if err := tx.Where("submission_id = ?", sub.ID).Delete(&models.SubmissionMessage{}).Error; err != nil {
				return err
			}
			if err := tx.Where("submission_id = ?", sub.ID).Delete(&models.InternalNote{}).Error; err != nil {
				return err
			}
			if err := tx.Where("submission_id = ?", sub.ID).Delete(&models.Activity{}).Error; err != nil {
				return err
			}
			if err := tx.Where("submission_id = ?", sub.ID).Delete(&models.MerkleLeaf{}).Error; err != nil {
				return err
			}
		}

		// Clean up any remaining records referencing organization_id directly
		if err := tx.Where("organization_id = ?", org.ID).Delete(&models.SubmissionMessage{}).Error; err != nil {
			return err
		}
		if err := tx.Where("organization_id = ?", org.ID).Delete(&models.InternalNote{}).Error; err != nil {
			return err
		}
		if err := tx.Where("organization_id = ?", org.ID).Delete(&models.Activity{}).Error; err != nil {
			return err
		}
		if err := tx.Where("organization_id = ?", org.ID).Delete(&models.MerkleLeaf{}).Error; err != nil {
			return err
		}
		if err := tx.Where("organization_id = ?", org.ID).Delete(&models.Submission{}).Error; err != nil {
			return err
		}

		// Merkle batches
		if err := tx.Where("organization_id = ?", org.ID).Delete(&models.MerkleBatch{}).Error; err != nil {
			return err
		}

		// Active sessions
		if err := tx.Where("organization_id = ?", org.ID).Delete(&models.Session{}).Error; err != nil {
			return err
		}

		// Team members
		if err := tx.Where("organization_id = ?", org.ID).Delete(&models.TeamMember{}).Error; err != nil {
			return err
		}

		// Dead man's switch
		if err := tx.Where("organization_id = ?", org.ID).Delete(&models.DeadMansSwitch{}).Error; err != nil {
			return err
		}

		// Organization itself
		if err := tx.Delete(&org).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		log.Printf("ACCOUNT_DELETE failed for org=%s: %v", orgID, err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete account",
		})
	}

	log.Printf("ACCOUNT_DELETED: org=%s", orgID)
	return c.JSON(fiber.Map{
		"message": "Account and all associated data permanently deleted",
	})
}
