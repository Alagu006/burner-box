package handlers

import (
	"burner-box-backend/internal/models"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// AssignSubmission assigns or unassigns a team member to a submission.
// PUT /dashboard/submissions/:id/assign  { "assigned_to": "uuid" | null }
func AssignSubmission(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)
	actorEmail, _ := c.Locals("email").(string)
	actorRole, _ := c.Locals("role").(string)
	submissionID := c.Params("id")

	var req struct {
		AssignedTo *string `json:"assigned_to"` // UUID string or null
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	var submission models.Submission
	if err := models.DB.Where("id = ? AND organization_id = ?", submissionID, orgID).
		First(&submission).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Submission not found"})
	}

	var assigneeEmail string

	if req.AssignedTo != nil && *req.AssignedTo != "" {
		parsed, err := uuid.Parse(*req.AssignedTo)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid assigned_to UUID"})
		}

		// Verify the team member belongs to this org
		var member models.TeamMember
		if err := models.DB.Where("id = ? AND organization_id = ?", parsed, orgID).
			First(&member).Error; err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Team member not found"})
		}

		submission.AssignedTo = &parsed
		assigneeEmail = member.Email
	} else {
		submission.AssignedTo = nil
		assigneeEmail = "nobody"
	}

	models.DB.Save(&submission)

	// Log activity
	logActivity(submission.ID, submission.OrganizationID, actorEmail, actorRole,
		"assignment", "assigned to "+assigneeEmail)

	log.Printf("ASSIGN success: submission=%s assignee=%s", submissionID, assigneeEmail)
	return c.JSON(fiber.Map{
		"message":     "Assignment updated",
		"assigned_to": submission.AssignedTo,
	})
}
