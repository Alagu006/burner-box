package handlers

import (
	"burner-box-backend/internal/models"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// ---- Configurable retention cleanup ----

// CleanupRetainedSubmissions deletes submissions older than the org's configured
// RetentionDays, along with all associated files, notes, replies, thread messages,
// and activity. Runs hourly via a background goroutine started from main.
//
// SECURITY: This logs only counts, never message content or submitter identity.
func CleanupRetainedSubmissions() {
	for {
		var orgs []models.Organization
		models.DB.Where("retention_days IS NOT NULL AND retention_days > 0").Find(&orgs)

		now := time.Now()
		for _, org := range orgs {
			if org.RetentionDays == nil || *org.RetentionDays <= 0 {
				continue
			}

			cutoff := now.AddDate(0, 0, -*org.RetentionDays)
			var count int64

			// Find submissions older than cutoff
			var oldSubmissions []models.Submission
			models.DB.Where("organization_id = ? AND created_at < ?", org.ID, cutoff).Find(&oldSubmissions)

			if len(oldSubmissions) == 0 {
				continue
			}

			for _, sub := range oldSubmissions {
				// Delete associated files from disk
				var files []models.SubmissionFile
				models.DB.Where("submission_id = ?", sub.ID).Find(&files)
				for _, f := range files {
					os.Remove("uploads/" + f.StorageKey)
				}

				// Cascade delete: files, replies, messages, notes, activity
				models.DB.Where("submission_id = ?", sub.ID).Delete(&models.SubmissionFile{})
				models.DB.Where("submission_id = ?", sub.ID).Delete(&models.Reply{})
				models.DB.Where("submission_id = ?", sub.ID).Delete(&models.SubmissionMessage{})
				models.DB.Where("submission_id = ?", sub.ID).Delete(&models.InternalNote{})
				models.DB.Where("submission_id = ?", sub.ID).Delete(&models.Activity{})
				models.DB.Delete(&sub)
				count++
			}

			log.Printf("RETENTION_CLEANUP: org=%s retention_days=%d deleted=%d", org.ID, *org.RetentionDays, count)
		}

		time.Sleep(1 * time.Hour)
	}
}

// ---- Retention settings API ----

type retentionRequest struct {
	RetentionDays *int `json:"retention_days"` // nil = indefinite
}

// GetRetentionSettings returns the org's current retention policy.
func GetRetentionSettings(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)

	var org models.Organization
	if err := models.DB.Where("id = ?", orgID).First(&org).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Organization not found"})
	}

	resp := fiber.Map{
		"retention_days": org.RetentionDays, // nil = indefinite
	}
	return c.JSON(resp)
}

// UpdateRetentionSettings sets the org's retention policy.
func UpdateRetentionSettings(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)

	var req retentionRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Validate: nil = indefinite, 1-3650 days (10 years max)
	if req.RetentionDays != nil && (*req.RetentionDays < 1 || *req.RetentionDays > 3650) {
		return c.Status(400).JSON(fiber.Map{
			"error": "Retention must be 1-3650 days, or null for indefinite",
		})
	}

	var org models.Organization
	if err := models.DB.Where("id = ?", orgID).First(&org).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Organization not found"})
	}

	org.RetentionDays = req.RetentionDays
	models.DB.Save(&org)

	log.Printf("RETENTION_UPDATE: org=%s days=%v", orgID, req.RetentionDays)
	return c.JSON(fiber.Map{
		"message":         "Retention policy updated",
		"retention_days":  org.RetentionDays,
	})
}

// ---- Webhook notifications ----

// isPrivateIP checks if a hostname resolves to a private/internal IP range.
// This prevents SSRF attacks where a webhook URL points at internal services.
func isPrivateIP(host string) bool {
	// First check if it's an IP literal
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified()
	}

	// Resolve hostname
	ips, err := net.LookupIP(host)
	if err != nil {
		// DNS resolution failure — reject to be safe
		return true
	}

	for _, ip := range ips {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return true
		}
	}
	return false
}

// validateWebhookURL validates a URL is not pointing at private/internal IPs.
func validateWebhookURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return err
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fiber.NewError(fiber.StatusBadRequest, "Webhook URL must use http or https")
	}

	if parsed.Host == "" {
		return fiber.NewError(fiber.StatusBadRequest, "Webhook URL must have a host")
	}

	// Strip port for IP check
	host := parsed.Hostname()
	if isPrivateIP(host) {
		return fiber.NewError(fiber.StatusBadRequest, "Webhook URL must not point at private/internal IP ranges")
	}

	return nil
}

// SendWebhookNotification dispatches a metadata-only webhook when a new submission arrives.
// The payload contains ONLY: submission_id, timestamp, portal_slug. No message content.
//
// SECURITY: The server cannot decrypt submission content and should not try.
// Webhook payloads are intentionally minimal to avoid any risk of content leakage.
func SendWebhookNotification(orgID string, submissionID string, slug string) {
	var org models.Organization
	if err := models.DB.Where("id = ?", orgID).First(&org).Error; err != nil {
		return
	}
	if org.WebhookURL == "" {
		return
	}

	// Validate URL on every send (defense-in-depth against race conditions)
	if err := validateWebhookURL(org.WebhookURL); err != nil {
		log.Printf("WEBHOOK skipped: org=%s invalid URL: %v", orgID, err)
		return
	}

	payload := `{"submission_id":"` + submissionID + `","timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `","portal_slug":"` + slug + `"}`

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(org.WebhookURL, "application/json", strings.NewReader(payload))
	if err != nil {
		log.Printf("WEBHOOK failed: org=%s url=%s err=%v", orgID, org.WebhookURL, err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("WEBHOOK rejected: org=%s status=%d", orgID, resp.StatusCode)
	}
}

// ---- Email notifications ----

// SendEmailNotification sends a metadata-only email when a new submission arrives.
//
// SECURITY: This is a deliberate scope limit. We NEVER send submission content
// or encrypted blobs via email — email is not a trusted channel for this data.
// The email contains only a link for the org to log in and check the dashboard.
//
// Requires SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS env vars. If not configured,
// this is a no-op (no error, no log — silently skipped).
func SendEmailNotification(orgID string, submissionID string, slug string) {
	var org models.Organization
	if err := models.DB.Where("id = ?", orgID).First(&org).Error; err != nil {
		return
	}
	if org.NotificationEmail == "" {
		return
	}

	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")

	// If SMTP is not configured, silently skip — this is a valid deployment choice
	if smtpHost == "" || smtpPort == "" {
		return
	}

	// Build the dashboard link — metadata only, never content
	apiURL := os.Getenv("API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:8080"
	}
	// Strip /api/v1 suffix if present to get the frontend URL
	frontendURL := strings.TrimSuffix(apiURL, "/api/v1")
	frontendURL = strings.TrimSuffix(frontendURL, "/api")
	dashboardLink := frontendURL + "/dashboard/submissions"

	subject := "New anonymous submission received"
	body := "A new anonymous submission has been received on your portal (" + slug + ").\n\n" +
		"Log in to view: " + dashboardLink + "\n\n" +
		"Submission ID: " + submissionID + "\n" +
		"This is an automated notification. No submission content is included in this email."

	addr := net.JoinHostPort(smtpHost, smtpPort)
	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)

	from := mail.Address{Name: "BurnerBox", Address: smtpUser}
	toAddresses := []string{org.NotificationEmail}

	msg := "From: " + from.String() + "\r\n" +
		"To: " + org.NotificationEmail + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		body + "\r\n"

	err := smtp.SendMail(addr, auth, from.Address, toAddresses, []byte(msg))
	if err != nil {
		log.Printf("EMAIL failed: org=%s err=%v", orgID, err)
		return
	}
	log.Printf("EMAIL sent: org=%s to=%s", orgID, org.NotificationEmail)
}

// SendDMSTriggerEmail sends a dead man's switch trigger notification to the
// org's notification email. This is called when the DMS background checker
// determines that the org has been inactive beyond its threshold.
//
// SECURITY: Email is metadata-only — it never contains submission content or
// encrypted data. It is a notification that the switch has fired, not a data
// release mechanism.
func SendDMSTriggerEmail(org models.Organization, daysSinceLogin int) {
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")
	if smtpHost == "" || smtpPort == "" {
		return
	}
	if org.NotificationEmail == "" {
		return
	}

	apiURL := os.Getenv("API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:8080"
	}
	frontendURL := strings.TrimSuffix(apiURL, "/api/v1")
	frontendURL = strings.TrimSuffix(frontendURL, "/api")

	subject := "BurnerBox: Dead man's switch triggered"
	body := "Your dead man's switch has been triggered.\n\n" +
		"You have not logged in for " + fmt.Sprintf("%d days", daysSinceLogin) + ".\n\n" +
		"The action configured for your dead man's switch (" + "see dashboard" + ") has been executed.\n\n" +
		"Log in to manage your account: " + frontendURL + "/login\n\n" +
		"This is an automated notification. No submission content is included in this email."

	addr := net.JoinHostPort(smtpHost, smtpPort)
	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
	from := mail.Address{Name: "BurnerBox", Address: smtpUser}
	toAddresses := []string{org.NotificationEmail}

	msg := "From: " + from.String() + "\r\n" +
		"To: " + org.NotificationEmail + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		body + "\r\n"

	err := smtp.SendMail(addr, auth, from.Address, toAddresses, []byte(msg))
	if err != nil {
		log.Printf("DMS_EMAIL failed: org=%s err=%v", org.ID, err)
		return
	}
	log.Printf("DMS_EMAIL sent: org=%s to=%s", org.ID, org.NotificationEmail)
}

// ---- Webhook/Email settings API ----

type notificationSettingsRequest struct {
	WebhookURL        string `json:"webhook_url"`        // empty = disable
	NotificationEmail string `json:"notification_email"` // empty = disable
}

// GetNotificationSettings returns the org's notification configuration.
func GetNotificationSettings(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)

	var org models.Organization
	if err := models.DB.Where("id = ?", orgID).First(&org).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Organization not found"})
	}

	return c.JSON(fiber.Map{
		"webhook_url":        org.WebhookURL,
		"notification_email": org.NotificationEmail,
	})
}

// UpdateNotificationSettings sets the org's webhook URL and/or notification email.
func UpdateNotificationSettings(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)

	var req notificationSettingsRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	var org models.Organization
	if err := models.DB.Where("id = ?", orgID).First(&org).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Organization not found"})
	}

	// Validate webhook URL if provided
	if req.WebhookURL != "" {
		if err := validateWebhookURL(req.WebhookURL); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
	}

	org.WebhookURL = req.WebhookURL
	org.NotificationEmail = req.NotificationEmail
	models.DB.Save(&org)

	log.Printf("NOTIFICATION_UPDATE: org=%s webhook=%v email=%v", orgID, req.WebhookURL != "", req.NotificationEmail != "")
	return c.JSON(fiber.Map{
		"message":            "Notification settings updated",
		"webhook_url":        org.WebhookURL,
		"notification_email": org.NotificationEmail,
	})
}
