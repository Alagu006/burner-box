package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"burner-box-backend/internal/middleware"

	"github.com/gofiber/fiber/v2"
)

func TestRateLimit_AuthLogin_BlocksAfterMaxAttempts(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()

	// 5 attempts per 15 minutes limiter for login
	loginLimiter := middleware.NewAuthRateLimiter(5, 15*time.Minute)
	app.Post("/api/v1/auth/login", middleware.RateLimitLogin(loginLimiter), func(c *fiber.Ctx) error {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
	})

	loginReq := map[string]string{
		"email":    "target@company.test",
		"password": "WrongPasswordAttempt",
	}
	body, _ := json.Marshal(loginReq)

	// First 5 attempts should pass through to the handler (returning 401)
	for i := 1; i <= 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, 5000)
		if err != nil {
			t.Fatalf("Attempt %d failed: %v", i, err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Attempt %d: expected 401 Unauthorized from handler, got %d", i, resp.StatusCode)
		}
	}

	// 6th attempt MUST be blocked by rate limiter with 429 Too Many Requests
	req6 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req6.Header.Set("Content-Type", "application/json")

	resp6, err := app.Test(req6, 5000)
	if err != nil {
		t.Fatalf("6th request failed: %v", err)
	}

	if resp6.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("SECURITY VIOLATION: Expected 429 Too Many Requests on 6th failed login attempt, got %d", resp6.StatusCode)
	}
}

func TestRateLimit_SubmitReplies_BlocksAfterMaxAttempts(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()

	// 30 requests per 15 minutes limiter for CheckForReplies
	repliesLimiter := middleware.NewAuthRateLimiter(30, 15*time.Minute)
	app.Get("/api/v1/submit/replies", middleware.RateLimitReplies(repliesLimiter), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "unread", "replies": []string{}})
	})

	// First 30 lookups should succeed (HTTP 200)
	for i := 1; i <= 30; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/submit/replies?name=Purple+Falcon-1234", nil)
		resp, err := app.Test(req, 5000)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Request %d: expected 200 OK, got %d", i, resp.StatusCode)
		}
	}

	// 31st lookup MUST be blocked with 429
	req31 := httptest.NewRequest(http.MethodGet, "/api/v1/submit/replies?name=Purple+Falcon-1234", nil)
	resp31, err := app.Test(req31, 5000)
	if err != nil {
		t.Fatalf("31st request failed: %v", err)
	}

	if resp31.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("SECURITY VIOLATION: Expected 429 Too Many Requests on 31st lookup to prevent name enumeration, got %d", resp31.StatusCode)
	}
}

func TestRateLimit_2FA_BlocksAfterMaxAttempts(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()

	twofaLimiter := middleware.NewAuthRateLimiter(5, 15*time.Minute)
	app.Post("/api/v1/auth/login/2fa", middleware.RateLimit2FA(twofaLimiter), func(c *fiber.Ctx) error {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid 2FA code"})
	})

	reqBody := map[string]string{
		"pending_token": "valid.mock.pending.jwt.token",
		"code":          "999999",
	}
	body, _ := json.Marshal(reqBody)

	// First 5 attempts return 401 from handler
	for i := 1; i <= 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/2fa", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, 5000)
		if err != nil {
			t.Fatalf("2FA attempt %d failed: %v", i, err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("2FA attempt %d: expected 401, got %d", i, resp.StatusCode)
		}
	}

	// 6th attempt blocked with 429
	req6 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/2fa", bytes.NewReader(body))
	req6.Header.Set("Content-Type", "application/json")

	resp6, err := app.Test(req6, 5000)
	if err != nil {
		t.Fatalf("6th 2FA request failed: %v", err)
	}

	if resp6.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("SECURITY VIOLATION: Expected 429 on 6th 2FA attempt, got %d", resp6.StatusCode)
	}
}

func TestRateLimit_AuthSignup_BlocksAfterMaxAttempts(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()

	// 5 signups per hour limiter
	signupLimiter := middleware.NewAuthRateLimiter(5, time.Hour)
	app.Post("/api/v1/auth/signup", middleware.RateLimitSignup(signupLimiter), func(c *fiber.Ctx) error {
		return c.Status(http.StatusCreated).JSON(fiber.Map{"message": "Organization registered successfully"})
	})

	signupReq := map[string]string{
		"name":       "Test Org",
		"email":      "test-signup@org.test",
		"password":   "SecurePassword123!",
		"public_key": "some-public-key",
	}
	body, _ := json.Marshal(signupReq)

	// First 5 attempts should pass through to the handler (returning 201)
	for i := 1; i <= 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, 5000)
		if err != nil {
			t.Fatalf("Signup attempt %d failed: %v", i, err)
		}
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("Signup attempt %d: expected 201 Created from handler, got %d", i, resp.StatusCode)
		}
	}

	// 6th attempt MUST be blocked by rate limiter with 429 Too Many Requests
	req6 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(body))
	req6.Header.Set("Content-Type", "application/json")

	resp6, err := app.Test(req6, 5000)
	if err != nil {
		t.Fatalf("6th signup request failed: %v", err)
	}

	if resp6.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("SECURITY VIOLATION: Expected 429 Too Many Requests on 6th signup attempt, got %d", resp6.StatusCode)
	}
}
