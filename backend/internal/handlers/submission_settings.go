package handlers

import (
	"burner-box-backend/internal/models"
	"time"

	"github.com/gofiber/fiber/v2"
)

// GetSubmissionSettings returns the current submission portal settings (JWT required).
func GetSubmissionSettings(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)

	var org models.Organization
	if err := models.DB.Where("id = ?", orgID).First(&org).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Organization not found",
		})
	}

	resp := fiber.Map{
		"submission_slug": org.SubmissionSlug,
	}

	if org.SubmissionDeadline != nil {
		resp["deadline"] = org.SubmissionDeadline.Format(time.RFC3339)
	}

	return c.JSON(resp)
}

// UpdateSubmissionSettings updates the submission portal settings (JWT required).
func UpdateSubmissionSettings(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)

	var req struct {
		Deadline *string `json:"deadline"` // RFC3339 string, or null/empty to clear
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request",
		})
	}

	var org models.Organization
	if err := models.DB.Where("id = ?", orgID).First(&org).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Organization not found",
		})
	}

	if req.Deadline != nil && *req.Deadline != "" {
		parsed, err := time.Parse(time.RFC3339, *req.Deadline)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{
				"error": "Invalid deadline format. Use RFC3339 (e.g. 2026-12-31T23:59:59Z)",
			})
		}
		if parsed.Before(time.Now()) {
			return c.Status(400).JSON(fiber.Map{
				"error": "Deadline must be in the future",
			})
		}
		org.SubmissionDeadline = &parsed
	} else {
		org.SubmissionDeadline = nil
	}

	models.DB.Save(&org)

	resp := fiber.Map{
		"message": "Submission settings updated",
	}

	if org.SubmissionDeadline != nil {
		resp["deadline"] = org.SubmissionDeadline.Format(time.RFC3339)
	}

	return c.JSON(resp)
}
