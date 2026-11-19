package main

import (
	"burner-box-backend/internal/config"
	"burner-box-backend/internal/handlers"
	"burner-box-backend/internal/middleware"
	"burner-box-backend/internal/models"
	"context"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/websocket/v2"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Connect to PostgreSQL database
	models.ConnectDatabase(cfg.DatabaseURL)

	// Start background cleanup for expired ephemeral rooms
	go handlers.CleanupExpiredRooms()

	// Start background room lifecycle workers (tombstone janitor & reconciler)
	handlers.StartRoomLifecycleWorkers()

	// Start background retention cleanup for submissions (hourly)
	go handlers.CleanupRetainedSubmissions()

	// Load or generate proof-of-submission Ed25519 key
	handlers.LoadOrGenerateProofKey()

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:               "BurnerBox",
		ServerHeader:          "BurnerBox",
		DisableStartupMessage: false,
		StrictRouting:         false,
		CaseSensitive:         false,
	})

	// ---- SECURITY MIDDLEWARE ----

	// Build CSP with production WebSocket URL if API_URL is set
	cspWS := "ws://localhost:8080 ws://127.0.0.1:8080"
	if cfg.APIURL != "" {
		wsURL := "wss://" + strings.TrimPrefix(cfg.APIURL, "https://")
		wsURL = strings.TrimPrefix(wsURL, "http://")
		cspWS = wsURL
	}

	app.Use(helmet.New(helmet.Config{
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "DENY",
		ReferrerPolicy:        "no-referrer",
		ContentSecurityPolicy: "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' " + cspWS + "; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
	}))

	// Tor Onion-Location header: when configured, instructs Tor Browser to switch
	// to the onion hidden service for complete end-to-end transport IP concealment.
	if onionLocation := os.Getenv("ONION_LOCATION"); onionLocation != "" {
		app.Use(func(c *fiber.Ctx) error {
			c.Set("Onion-Location", onionLocation)
			return c.Next()
		})
	}
	app.Use(cors.New(cors.Config{
		AllowOrigins: cfg.CORSOrigins,
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET, POST, PUT, DELETE, OPTIONS",
	}))
	app.Use(logger.New(logger.Config{
		Format: "[${time}] ${method} ${path} - ${status}\n",
	}))

	// Global Rate Limiting
	app.Use(limiter.New(limiter.Config{
		Max:        100,
		Expiration: 60 * time.Second,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many requests. Please try again later.",
			})
		},
	}))

	// ---- ROUTES ----

	// Health check (public)
	app.Get("/api/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "alive",
			"message": "BurnerBox API with PostgreSQL",
			"version": "0.1.0",
		})
	})

	// API v1 group
	api := app.Group("/api/v1")

	// ==========================================
	// PUBLIC ROUTES (No Auth Required)
	// ==========================================

	// Warrant canary (public, read-only)
	api.Get("/canary", handlers.GetCanary)

	// Proof of submission public key & registry (for independent verification)
	api.Get("/proof-key", handlers.GetProofPublicKey)
	api.Get("/proof-keys", handlers.GetAllProofKeys)
	api.Get("/proof-keys/:id", handlers.GetProofKeyByIdentifier)

	// Public platform statistics (unauthenticated, hourly-cached)
	api.Get("/stats", handlers.GetPublicStats)

	// Super-admin dashboard (separate auth path, not reachable via normal org login)
	api.Get("/admin/stats", handlers.GetAdminStats)

	// Auth routes
	auth := api.Group("/auth")
	signupLimiter := middleware.NewAuthRateLimiter(5, time.Hour)
	auth.Post("/signup", middleware.RateLimitSignup(signupLimiter), handlers.SignupOrganization)

	// Auth rate limiter: 5 attempts per 15 minutes per IP+email
	authLimiter := middleware.NewAuthRateLimiter(5, 15*time.Minute)
	auth.Post("/login", middleware.RateLimitLogin(authLimiter), handlers.LoginOrganization)
	auth.Post("/login/2fa", middleware.RateLimit2FA(authLimiter), handlers.Login2FA)
	auth.Post("/logout", middleware.Protected(), handlers.LogoutOrganization)

	// Organization public profile
	org := api.Group("/org")
	org.Get("/:id", handlers.GetOrganization)

	// Ephemeral secure rooms (public, no auth)
	rooms := api.Group("/rooms")
	rooms.Post("/", handlers.CreateRoom)
	rooms.Get("/:code", handlers.GetRoomStatus)
	rooms.Delete("/:code", handlers.DestroyRoom)
	rooms.Get("/:code/messages", handlers.GetRecentRoomMessages)
	rooms.Post("/:code/files", handlers.UploadRoomFile)
	rooms.Get("/:code/files/:file_id", handlers.DownloadRoomFile)

	// WebSocket upgrades (must be registered before 404 catch-all)
	app.Use("/api/v1/rooms/:code/ws", websocket.New(handlers.JoinRoom))
	app.Use("/api/v1/submit/:slug/status/:anonymous_name/ws", websocket.New(handlers.JoinStatusStream))

	// Anonymous submission & portal verification routes
	submit := api.Group("/submit")
	submit.Get("/:slug/public-key", handlers.GetOrganizationPublicKey)
	submit.Post("/:slug", handlers.SubmitAnonymousTip)
	submit.Get("/:slug/merkle-roots", handlers.GetPortalMerkleRoots)
	submit.Get("/:slug/proof/:id", handlers.GetSubmissionInclusionProof)
	submit.Get("/inclusion-proof", handlers.GetSubmissionInclusionProof)

	// Portal public routes alias
	portal := api.Group("/portal")
	portal.Get("/:slug/merkle-roots", handlers.GetPortalMerkleRoots)

	// Replies lookup: rate-limited (30/15min/IP) to prevent anonymous name enumeration
	repliesLimiter := middleware.NewAuthRateLimiter(30, 15*time.Minute)
	submit.Get("/replies", middleware.RateLimitReplies(repliesLimiter), handlers.CheckForReplies)

	// ==========================================
	// PROTECTED ROUTES (JWT Required + Role Resolution)
	// ==========================================

	protected := api.Group("/dashboard")
	protected.Use(middleware.Protected())
	protected.Use(middleware.ResolveRole()) // Resolves caller role → c.Locals("role")

	// Dashboard home (all roles)
	protected.Get("/", func(c *fiber.Ctx) error {
		orgID := c.Locals("orgID")
		email := c.Locals("email")
		role := c.Locals("role")
		return c.JSON(fiber.Map{
			"message": "Welcome to your dashboard",
			"org_id":  orgID,
			"email":   email,
			"role":    role,
		})
	})

	// Session management routes (all authenticated roles can manage their sessions)
	sessions := protected.Group("/sessions")
	sessions.Get("/", handlers.ListActiveSessions)
	sessions.Delete("/:id", handlers.RevokeSession)
	sessions.Delete("/", handlers.RevokeAllOtherSessions)

	// 2FA routes (all roles)
	twofa := protected.Group("/2fa")
	twofa.Post("/setup", handlers.Setup2FA)
	twofa.Post("/verify", handlers.Verify2FA)
	twofa.Post("/disable", handlers.Disable2FA)
	twofa.Get("/status", handlers.Check2FAStatus)

	// === ADMIN ONLY ===
	adminRole := middleware.RequireRole("admin")

	// Key rotation
	protected.Put("/public-key", adminRole, handlers.RotatePublicKey)

	// Public portal customization & settings
	protected.Get("/customization", adminRole, handlers.GetCustomizationSettings)
	protected.Put("/customization", adminRole, handlers.UpdateCustomizationSettings)

	// Submission portal settings (deadline)
	protected.Get("/submission-settings", adminRole, handlers.GetSubmissionSettings)
	protected.Put("/submission-settings", adminRole, handlers.UpdateSubmissionSettings)

	// Dead man's switch
	protected.Get("/dead-mans-switch", adminRole, handlers.GetDeadMansSwitch)
	protected.Put("/dead-mans-switch", adminRole, handlers.UpdateDeadMansSwitch)

	// Retention policy settings
	protected.Get("/retention", adminRole, handlers.GetRetentionSettings)
	protected.Put("/retention", adminRole, handlers.UpdateRetentionSettings)

	// Notification settings (webhook + email)
	protected.Get("/notifications", adminRole, handlers.GetNotificationSettings)
	protected.Put("/notifications", adminRole, handlers.UpdateNotificationSettings)

	// Team routes
	team := protected.Group("/team", adminRole)
	team.Post("/invite", handlers.InviteTeamMember)
	team.Get("/", handlers.ListTeamMembers)
	team.Delete("/:id", handlers.RemoveTeamMember)

	// Account deletion (admin only, requires password + 2FA verification)
	protected.Delete("/account", adminRole, handlers.DeleteAccount)

	// === RESPONDER+ (responder or admin) ===
	responderRole := middleware.RequireRole("responder")

	// Submission management routes (GET operations allowed for all authenticated roles including reader)
	submissions := protected.Group("/submissions")
	submissions.Get("/", handlers.GetOrganizationSubmissions)
	submissions.Get("/:id", handlers.GetSubmission)
	submissions.Put("/:id", responderRole, handlers.UpdateSubmissionStatus)
	submissions.Put("/:id/assign", responderRole, handlers.AssignSubmission)
	submissions.Post("/:id/reply", responderRole, handlers.ReplyToSubmission)

	// File routes for submissions
	submissions.Post("/:id/files", responderRole, handlers.UploadSubmissionFile)
	submissions.Get("/:id/files", handlers.GetSubmissionFiles)
	submissions.Get("/:id/files/:fileId", handlers.DownloadSubmissionFile)

	submissions.Post("/:id/notes", responderRole, handlers.AddInternalNote)
	submissions.Get("/:id/notes", handlers.GetInternalNotes)
	submissions.Get("/:id/activity", handlers.GetSubmissionActivity)

	// Thread messages
	submissions.Get("/:id/messages", handlers.GetThreadMessages)
	submissions.Post("/:id/messages", responderRole, handlers.AddThreadMessageFromOrg)

	// Bulk actions
	submissions.Post("/bulk/status", responderRole, handlers.BulkUpdateStatus)
	submissions.Post("/bulk/assign", responderRole, handlers.BulkAssign)

	// Export
	submissions.Post("/export", responderRole, handlers.ExportSubmissions)

	// Public thread routes (submitter follow-ups, no auth)
	thread := api.Group("/thread")
	thread.Get("/", handlers.GetThreadFromSubmitter)
	thread.Post("/", handlers.AddThreadMessageFromSubmitter)

	// ==========================================
	// 404 CATCH-ALL (Must be last)
	// ==========================================
	app.Use(func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Endpoint not found",
		})
	})

	// ==========================================
	// PRINT ALL REGISTERED ROUTES (Debug)
	// ==========================================
	log.Println("📋 Registered Routes:")
	for _, route := range app.GetRoutes() {
		log.Printf("  [%s] %s", route.Method, route.Path)
	}

	// ==========================================
	// START SERVER
	// ==========================================
	port := cfg.Port
	if port == "" {
		port = "8080"
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := app.Listen(":" + port); err != nil {
			log.Fatalf("Server startup failed: %v", err)
		}
	}()

	// Background: check dead man's switches every hour
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		for range ticker.C {
			handlers.CheckDeadManSwitches()
		}
	}()

	// Background: seal open Merkle batches hourly
	go handlers.StartMerkleBatchSealer(1 * time.Hour)

	log.Printf("🚀 BurnerBox running on http://localhost:%s", port)
	log.Printf("📋 Health: http://localhost:%s/api/health", port)
	log.Printf("🗄️  Database connected successfully")

	<-quit
	log.Println("🛑 Shutting down server gracefully...")

	_, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := app.Shutdown(); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("✅ Server stopped safely")
}
