package handlers

import (
	"burner-box-backend/internal/models"
	"os"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

// ---- Admin Dashboard (super-admin only, separate auth path) ----

// GetAdminStats returns aggregate platform-wide statistics.
// Requires the SUPER_ADMIN_TOKEN header to authenticate — this is a separate
// auth path from normal org login. No per-org or per-submission drill-down
// is exposed, so one org's data cannot be observed by another.
func GetAdminStats(c *fiber.Ctx) error {
	token := c.Get("X-Admin-Token")
	requiredToken := os.Getenv("SUPER_ADMIN_TOKEN")
	if requiredToken == "" || token != requiredToken {
		return c.Status(403).JSON(fiber.Map{"error": "Invalid admin token"})
	}

	var orgCount int64
	var submissionCount int64
	var roomCount int64

	models.DB.Model(&models.Organization{}).Count(&orgCount)
	models.DB.Model(&models.Submission{}).Count(&submissionCount)
	models.DB.Model(&models.Room{}).Where("expires_at > ? AND destroyed_at IS NULL", time.Now()).Count(&roomCount)

	return c.JSON(fiber.Map{
		"total_orgs":        orgCount,
		"total_submissions": submissionCount,
		"active_rooms":      roomCount,
	})
}

// ---- Public Stats (unauthenticated, delayed/cached) ----

type cachedStats struct {
	data      fiber.Map
	updatedAt time.Time
}

var (
	publicStatsCache cachedStats
	publicStatsMu    sync.RWMutex
)

// GetPublicStats returns aggregate platform statistics, unauthenticated.
// Data is cached in-memory and refreshed hourly, so it cannot be used to
// infer individual submission timing.
func GetPublicStats(c *fiber.Ctx) error {
	publicStatsMu.RLock()
	cache := publicStatsCache
	publicStatsMu.RUnlock()

	// Return cached data if fresh (< 1 hour old)
	if cache.data != nil && time.Since(cache.updatedAt) < time.Hour {
		return c.JSON(cache.data)
	}

	// Refresh cache
	var orgCount int64
	var submissionCount int64
	var roomCount int64

	models.DB.Model(&models.Organization{}).Count(&orgCount)
	models.DB.Model(&models.Submission{}).Count(&submissionCount)
	models.DB.Model(&models.Room{}).Where("expires_at > ? AND destroyed_at IS NULL", time.Now()).Count(&roomCount)

	data := fiber.Map{
		"total_orgs":        orgCount,
		"total_submissions": submissionCount,
		"active_rooms":      roomCount,
		"note":              "Aggregated counts, updated hourly. No per-org data is exposed.",
	}

	publicStatsMu.Lock()
	publicStatsCache = cachedStats{data: data, updatedAt: time.Now()}
	publicStatsMu.Unlock()

	return c.JSON(data)
}
