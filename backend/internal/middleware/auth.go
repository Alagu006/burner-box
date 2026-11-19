package middleware

import (
	"log"
	"strings"
	"time"

	"burner-box-backend/internal/config"
	"burner-box-backend/internal/crypto"
	"burner-box-backend/internal/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// Protected checks for a valid JWT token and verifies that the embedded session
// row exists in the database, is not expired, and has not been revoked.
func Protected() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			log.Printf("AUTH_GUARD rejected: no Authorization header path=%s", c.Path())
			return c.Status(401).JSON(fiber.Map{
				"error": "Missing authorization header",
			})
		}

		// Check Bearer prefix
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			log.Printf("AUTH_GUARD rejected: bad format path=%s", c.Path())
			return c.Status(401).JSON(fiber.Map{
				"error": "Invalid authorization format. Use: Bearer <token>",
			})
		}

		tokenString := parts[1]

		// 1. Validate JWT signature and structure
		claims, err := crypto.ValidateToken(tokenString, config.AppConfig.JWTSecret)
		if err != nil {
			log.Printf("AUTH_GUARD rejected: invalid token path=%s err=%v", c.Path(), err)
			return c.Status(401).JSON(fiber.Map{
				"error": "Invalid or expired token",
			})
		}

		// 2. Validate Session ID claim
		if claims.SessionID == "" {
			log.Printf("AUTH_GUARD rejected: token missing session_id claim path=%s", c.Path())
			return c.Status(401).JSON(fiber.Map{
				"error": "Invalid or revoked session",
			})
		}

		sessionUUID, err := uuid.Parse(claims.SessionID)
		if err != nil {
			log.Printf("AUTH_GUARD rejected: invalid session_id uuid=%s", claims.SessionID)
			return c.Status(401).JSON(fiber.Map{
				"error": "Invalid or revoked session",
			})
		}

		// 3. Database session validation (ensures instant revocation is honored)
		var session models.Session
		if err := models.DB.Where("id = ? AND organization_id = ?", sessionUUID, claims.OrganizationID).First(&session).Error; err != nil {
			log.Printf("AUTH_GUARD rejected: session not found in DB or revoked session=%s org=%s", claims.SessionID, claims.OrganizationID)
			return c.Status(401).JSON(fiber.Map{
				"error": "Session has been revoked or expired",
			})
		}

		// 4. Check session expiration
		now := time.Now()
		if session.ExpiresAt.Before(now) {
			log.Printf("AUTH_GUARD rejected: session expired session=%s expires_at=%v", claims.SessionID, session.ExpiresAt)
			return c.Status(401).JSON(fiber.Map{
				"error": "Session has expired",
			})
		}

		// 5. Verify token hash (prevents token collision/forgery)
		tokenHash := crypto.HashToken(tokenString)
		if session.TokenHash != "" && session.TokenHash != tokenHash {
			log.Printf("AUTH_GUARD rejected: session token hash mismatch session=%s", claims.SessionID)
			return c.Status(401).JSON(fiber.Map{
				"error": "Invalid session token",
			})
		}

		// 6. Update LastSeenAt (no IP, no User-Agent, privacy-preserving)
		models.DB.Model(&models.Session{}).Where("id = ?", session.ID).Update("last_seen_at", now)

		// Store claims and session info in context for handlers to use
		c.Locals("orgID", claims.OrganizationID)
		c.Locals("email", claims.Email)
		c.Locals("sessionID", session.ID.String())

		return c.Next()
	}
}
