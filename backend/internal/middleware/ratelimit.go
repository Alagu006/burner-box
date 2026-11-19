package middleware

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

type authRateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	limit    int
	window   time.Duration
}

// NewAuthRateLimiter creates a rate limiter that tracks attempts per key.
// Keys should be "ip:email" to rate-limit per IP+email combination.
func NewAuthRateLimiter(limit int, window time.Duration) *authRateLimiter {
	rl := &authRateLimiter{
		attempts: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
	go rl.cleanup()
	return rl
}

func (rl *authRateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, times := range rl.attempts {
			valid := filterRecent(times, now, rl.window)
			if len(valid) == 0 {
				delete(rl.attempts, key)
			} else {
				rl.attempts[key] = valid
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *authRateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	times := rl.attempts[key]
	valid := filterRecent(times, now, rl.window)

	if len(valid) >= rl.limit {
		rl.attempts[key] = valid
		return false
	}

	rl.attempts[key] = append(valid, now)
	return true
}

func filterRecent(times []time.Time, now time.Time, window time.Duration) []time.Time {
	valid := make([]time.Time, 0, len(times))
	for _, t := range times {
		if now.Sub(t) <= window {
			valid = append(valid, t)
		}
	}
	return valid
}

type loginBody struct {
	Email string `json:"email"`
}

type pendingTokenBody struct {
	PendingToken string `json:"pending_token"`
}

func extractEmailFromBody(c *fiber.Ctx) string {
	raw := c.Body()
	if len(raw) == 0 {
		return ""
	}
	var body loginBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return ""
	}
	return body.Email
}

func extractPendingTokenEmail(c *fiber.Ctx) string {
	raw := c.Body()
	if len(raw) == 0 {
		return ""
	}
	var body pendingTokenBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return ""
	}
	// We can't decode the JWT here, so use the pending token itself as part of the key
	// alongside the IP. This still prevents brute-force per IP.
	if body.PendingToken == "" {
		return ""
	}
	return body.PendingToken
}

// RateLimitLogin limits login attempts per IP+email (5 per 15 minutes)
func RateLimitLogin(rl *authRateLimiter) fiber.Handler {
	return func(c *fiber.Ctx) error {
		email := extractEmailFromBody(c)
		ip := c.IP()
		key := ip + ":" + email

		if !rl.allow(key) {
			log.Printf("RATELIMIT_LOGIN blocked")
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many requests. Please try again later.",
			})
		}
		return c.Next()
	}
}

// RateLimit2FA limits 2FA verification attempts per IP+pending token (5 per 15 minutes)
func RateLimit2FA(rl *authRateLimiter) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := extractPendingTokenEmail(c)
		ip := c.IP()
		key := ip + ":2fa:" + token

		if !rl.allow(key) {
			log.Printf("RATELIMIT_2FA blocked")
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many requests. Please try again later.",
			})
		}
		return c.Next()
	}
}

// RateLimitReplies limits CheckForReplies lookups per IP (30 per 15 minutes).
// This is an unauthenticated endpoint — without rate limiting an attacker
// could enumerate anonymous names to discover submissions.
func RateLimitReplies(rl *authRateLimiter) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ip := c.IP()
		key := ip + ":replies"

		if !rl.allow(key) {
			log.Printf("RATELIMIT_REPLIES blocked")
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many requests. Please try again later.",
			})
		}
		return c.Next()
	}
}

// RateLimitSignup limits organization signups per IP (5 per hour).
// Protects against automated account creation and spam while preserving privacy (no IP logging).
func RateLimitSignup(rl *authRateLimiter) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ip := c.IP()
		key := ip + ":signup"

		if !rl.allow(key) {
			log.Printf("RATELIMIT_SIGNUP blocked")
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many requests. Please try again later.",
			})
		}
		return c.Next()
	}
}
