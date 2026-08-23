package middleware

import (
	"log"

	"burner-box-backend/internal/models"

	"github.com/gofiber/fiber/v2"
)

// Role hierarchy: admin > responder > reader
var roleLevel = map[string]int{
	"reader":    1,
	"responder": 2,
	"admin":     3,
}

// RequireRole returns middleware that enforces a minimum role level.
// The caller's role is resolved by Protected() and stored in c.Locals("role").
//
// Permission matrix:
//
//	reader:    view submissions, view thread, view files
//	responder: + reply, update status, assign, set priority, add notes, bulk actions, export
//	admin:     + invite/remove team members, rotate keys, manage submission settings
func RequireRole(minRole string) fiber.Handler {
	minLevel, ok := roleLevel[minRole]
	if !ok {
		log.Fatalf("RequireRole called with invalid role: %s", minRole)
	}

	return func(c *fiber.Ctx) error {
		role, _ := c.Locals("role").(string)
		if role == "" {
			role = "reader"
		}

		level, ok := roleLevel[role]
		if !ok || level < minLevel {
			log.Printf("RBAC rejected: role=%s required=%s path=%s", role, minRole, c.Path())
			return c.Status(403).JSON(fiber.Map{
				"error": "Insufficient permissions",
			})
		}

		return c.Next()
	}
}

// ResolveRole must run after Protected(). It determines the caller's role:
//   - If the JWT email matches the org's email → "admin" (org owner)
//   - Otherwise, look up the TeamMember record for this org+email
//   - If no record found → "reader" (safe default, denies writes)
//
// The resolved role is stored in c.Locals("role").
func ResolveRole() fiber.Handler {
	return func(c *fiber.Ctx) error {
		orgID, _ := c.Locals("orgID").(string)
		email, _ := c.Locals("email").(string)

		if orgID == "" || email == "" {
			c.Locals("role", "reader")
			return c.Next()
		}

		// Check if this is the org owner (email matches org email)
		var org models.Organization
		if err := models.DB.Select("email").Where("id = ?", orgID).First(&org).Error; err == nil {
			if org.Email == email {
				c.Locals("role", "admin")
				return c.Next()
			}
		}

		// Look up team member record
		var member models.TeamMember
		if err := models.DB.Where("organization_id = ? AND email = ?", orgID, email).
			First(&member).Error; err == nil {
			c.Locals("role", member.Role)
			return c.Next()
		}

		// No record found → default to reader (deny writes)
		c.Locals("role", "reader")
		return c.Next()
	}
}
