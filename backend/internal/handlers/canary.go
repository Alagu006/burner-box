package handlers

import (
	"log"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// GetCanary serves the warrant canary content as JSON.
// The canary is a plain markdown file that is read at request time,
// so updating docs/WARRANT_CANARY.md immediately reflects in the API.
func GetCanary(c *fiber.Ctx) error {
	content, err := os.ReadFile("docs/WARRANT_CANARY.md")
	if err != nil {
		// Try relative to the backend directory (for dev with different cwd)
		content, err = os.ReadFile("../docs/WARRANT_CANARY.md")
		if err != nil {
			log.Printf("CANARY failed: file not found at docs/WARRANT_CANARY.md or ../docs/WARRANT_CANARY.md")
			return c.Status(500).JSON(fiber.Map{
				"error": "Canary file not available",
			})
		}
	}

	// Extract "Last updated:" date from the markdown
	lastUpdate := "unknown"
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "**Last updated:**") {
			lastUpdate = strings.TrimPrefix(trimmed, "**Last updated:**")
			lastUpdate = strings.TrimSpace(lastUpdate)
			break
		}
	}

	return c.Status(200).JSON(fiber.Map{
		"last_updated": lastUpdate,
		"content":      string(content),
	})
}
