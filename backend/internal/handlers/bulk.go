package handlers

import (
	"burner-box-backend/internal/models"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// BulkUpdateStatus marks multiple submissions with the same status.
// POST /dashboard/submissions/bulk/status  { "ids": ["uuid", ...], "status": "read" }
func BulkUpdateStatus(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)
	actorEmail, _ := c.Locals("email").(string)
	actorRole, _ := c.Locals("role").(string)

	var req struct {
		IDs    []string `json:"ids"`
		Status string   `json:"status"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	if len(req.IDs) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No submission IDs provided"})
	}

	validStatuses := map[string]bool{"unread": true, "read": true, "actioned": true, "flagged": true, "archived": true}
	if !validStatuses[req.Status] {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid status"})
	}

	parsedIDs := make([]uuid.UUID, 0, len(req.IDs))
	for _, idStr := range req.IDs {
		if id, err := uuid.Parse(idStr); err == nil {
			parsedIDs = append(parsedIDs, id)
		}
	}

	result := models.DB.Model(&models.Submission{}).
		Where("id IN ? AND organization_id = ?", parsedIDs, orgID).
		Update("status", req.Status)

	// Log activity for each submission
	for _, id := range parsedIDs {
		logActivity(id, uuid.MustParse(orgID), actorEmail, actorRole,
			"status_change", "bulk → "+req.Status)
	}

	log.Printf("BULK_STATUS success: count=%d status=%s", result.RowsAffected, req.Status)
	return c.JSON(fiber.Map{
		"message": "Status updated",
		"count":   result.RowsAffected,
	})
}

// BulkAssign assigns multiple submissions to a team member.
// POST /dashboard/submissions/bulk/assign  { "ids": ["uuid", ...], "assigned_to": "uuid" | null }
func BulkAssign(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)
	actorEmail, _ := c.Locals("email").(string)
	actorRole, _ := c.Locals("role").(string)

	var req struct {
		IDs        []string `json:"ids"`
		AssignedTo *string  `json:"assigned_to"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	if len(req.IDs) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No submission IDs provided"})
	}

	parsedIDs := make([]uuid.UUID, 0, len(req.IDs))
	for _, idStr := range req.IDs {
		if id, err := uuid.Parse(idStr); err == nil {
			parsedIDs = append(parsedIDs, id)
		}
	}

	var assigneePtr *uuid.UUID
	assigneeEmail := "nobody"
	if req.AssignedTo != nil && *req.AssignedTo != "" {
		parsed, err := uuid.Parse(*req.AssignedTo)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid assigned_to UUID"})
		}
		// Verify team member
		var member models.TeamMember
		if err := models.DB.Where("id = ? AND organization_id = ?", parsed, orgID).
			First(&member).Error; err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Team member not found"})
		}
		assigneePtr = &parsed
		assigneeEmail = member.Email
	}

	result := models.DB.Model(&models.Submission{}).
		Where("id IN ? AND organization_id = ?", parsedIDs, orgID).
		Update("assigned_to", assigneePtr)

	for _, id := range parsedIDs {
		logActivity(id, uuid.MustParse(orgID), actorEmail, actorRole,
			"assignment", "bulk assigned to "+assigneeEmail)
	}

	log.Printf("BULK_ASSIGN success: count=%d assignee=%s", result.RowsAffected, assigneeEmail)
	return c.JSON(fiber.Map{
		"message": "Assignments updated",
		"count":   result.RowsAffected,
	})
}
