package middleware

import (
	"log"
	"strings"

	"burner-box-backend/internal/config"
	"burner-box-backend/internal/crypto"

	"github.com/gofiber/fiber/v2"
)

// Protected checks for a valid JWT token
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

		// Validate token
		claims, err := crypto.ValidateToken(tokenString, config.AppConfig.JWTSecret)
		if err != nil {
			log.Printf("AUTH_GUARD rejected: invalid token path=%s", c.Path())
			return c.Status(401).JSON(fiber.Map{
				"error": "Invalid or expired token",
			})
		}

		// Store claims in context for handlers to use
		c.Locals("orgID", claims.OrganizationID)
		c.Locals("email", claims.Email)

		return c.Next()
	}
}