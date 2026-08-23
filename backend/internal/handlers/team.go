package handlers

import (
	"log"
	"time"

	"burner-box-backend/internal/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type InviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"` // "admin", "responder", "reader"
}

// InviteTeamMember invites a new member to the organization
func InviteTeamMember(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)

	var req InviteRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request",
		})
	}

	// Validate role
	validRoles := map[string]bool{"admin": true, "responder": true, "reader": true}
	if !validRoles[req.Role] {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid role. Use: admin, responder, or reader",
		})
	}

	if req.Role == "" {
		req.Role = "reader"
	}

	// Check if already invited
	var existing models.TeamMember
	result := models.DB.Where("organization_id = ? AND email = ?", orgID, req.Email).First(&existing)
	if result.RowsAffected > 0 {
		return c.Status(409).JSON(fiber.Map{
			"error": "This email has already been invited",
		})
	}

	// Create invitation
	orgUUID, _ := uuid.Parse(orgID)
	member := models.TeamMember{
		OrganizationID: orgUUID,
		Email:          req.Email,
		Role:           req.Role,
		InvitedAt:      time.Now(),
	}

	if err := models.DB.Create(&member).Error; err != nil {
		log.Printf("TEAM_INVITE failed: DB create error org=%s: %v", orgID, err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to invite member",
		})
	}

	log.Printf("TEAM_INVITE success: org=%s role=%s", orgID, req.Role)
	return c.Status(201).JSON(fiber.Map{
		"message": "Team member invited successfully",
		"member":  member,
	})
}

// ListTeamMembers returns all team members for the organization
func ListTeamMembers(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)

	var members []models.TeamMember
	if err := models.DB.Where("organization_id = ?", orgID).Find(&members).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to fetch team members",
		})
	}

	return c.JSON(fiber.Map{
		"members": members,
		"count":   len(members),
	})
}

// RemoveTeamMember removes a team member
func RemoveTeamMember(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)
	memberID := c.Params("id")

	// Delete member (only if belongs to this org)
	result := models.DB.Where("id = ? AND organization_id = ?", memberID, orgID).Delete(&models.TeamMember{})
	if result.RowsAffected == 0 {
		return c.Status(404).JSON(fiber.Map{
			"error": "Team member not found",
		})
	}

	log.Printf("TEAM_REMOVE success: org=%s member=%s", orgID, memberID)
	return c.JSON(fiber.Map{
		"message": "Team member removed",
	})
}