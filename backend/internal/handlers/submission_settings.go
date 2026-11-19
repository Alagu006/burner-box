package handlers

import (
	"encoding/json"
	"strings"
	"time"

	"burner-box-backend/internal/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
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

type CustomField struct {
	ID        string   `json:"id"`
	Label     string   `json:"label"`
	FieldType string   `json:"field_type"` // "text" | "select" | "textarea"
	Options   []string `json:"options,omitempty"`
	Required  bool     `json:"required"`
}

type CustomizationSettingsRequest struct {
	WelcomeMessage string        `json:"welcome_message"`
	LogoURL        string        `json:"logo_url"`
	CustomFields   []CustomField `json:"custom_fields"`
}

// GetCustomizationSettings returns the organization's public page customization settings
func GetCustomizationSettings(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)

	var org models.Organization
	if err := models.DB.Select("welcome_message", "logo_url", "custom_fields").
		Where("id = ?", orgID).First(&org).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Organization not found",
		})
	}

	var customFields []CustomField
	if org.CustomFields != "" {
		_ = json.Unmarshal([]byte(org.CustomFields), &customFields)
	}
	if customFields == nil {
		customFields = []CustomField{}
	}

	return c.JSON(fiber.Map{
		"welcome_message": org.WelcomeMessage,
		"logo_url":        org.LogoURL,
		"custom_fields":   customFields,
	})
}

// UpdateCustomizationSettings updates the organization's public page customization settings
func UpdateCustomizationSettings(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)

	var req CustomizationSettingsRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if len(req.WelcomeMessage) > 1000 {
		return c.Status(400).JSON(fiber.Map{
			"error": "Welcome message too long (max 1000 characters)",
		})
	}

	logoURL := strings.TrimSpace(req.LogoURL)
	if logoURL != "" {
		if len(logoURL) > 2048 {
			return c.Status(400).JSON(fiber.Map{
				"error": "Logo URL too long (max 2048 characters)",
			})
		}
		if !strings.HasPrefix(logoURL, "http://") && !strings.HasPrefix(logoURL, "https://") {
			return c.Status(400).JSON(fiber.Map{
				"error": "Logo URL must start with http:// or https://",
			})
		}
	}

	// Validate custom fields
	for i := range req.CustomFields {
		field := &req.CustomFields[i]
		if strings.TrimSpace(field.ID) == "" {
			field.ID = uuid.New().String()
		}
		field.Label = strings.TrimSpace(field.Label)
		if field.Label == "" {
			return c.Status(400).JSON(fiber.Map{
				"error": "Custom field label is required",
			})
		}
		if len(field.Label) > 255 {
			return c.Status(400).JSON(fiber.Map{
				"error": "Custom field label too long (max 255 characters)",
			})
		}
		if field.FieldType != "text" && field.FieldType != "select" && field.FieldType != "textarea" {
			return c.Status(400).JSON(fiber.Map{
				"error": "Invalid custom field type: must be 'text', 'select', or 'textarea'",
			})
		}
		if field.FieldType == "select" && len(field.Options) == 0 {
			return c.Status(400).JSON(fiber.Map{
				"error": "Select field must have at least one option",
			})
		}
	}

	customFieldsBytes, err := json.Marshal(req.CustomFields)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to process custom fields",
		})
	}

	updates := map[string]interface{}{
		"welcome_message": req.WelcomeMessage,
		"logo_url":        logoURL,
		"custom_fields":   string(customFieldsBytes),
	}

	if err := models.DB.Model(&models.Organization{}).Where("id = ?", orgID).Updates(updates).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to update customization settings",
		})
	}

	return c.JSON(fiber.Map{
		"message":         "Customization settings updated successfully",
		"welcome_message": req.WelcomeMessage,
		"logo_url":        logoURL,
		"custom_fields":   req.CustomFields,
	})
}
