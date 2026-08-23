package handlers

import (
	"burner-box-backend/internal/models"
	"strings"

	"github.com/gofiber/fiber/v2"
)

const MaxThreadMessageLength = 10000

// GetThreadMessages returns all thread messages for a submission (dashboard, JWT required).
// Messages are returned in chronological order alongside legacy Replies.
func GetThreadMessages(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)
	submissionID := c.Params("id")

	var submission models.Submission
	if err := models.DB.Where("id = ? AND organization_id = ?", submissionID, orgID).
		First(&submission).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Submission not found",
		})
	}

	// Fetch legacy replies (may be empty for new submissions)
	var replies []models.Reply
	models.DB.Where("submission_id = ?", submission.ID).
		Order("created_at ASC").
		Find(&replies)

	// Fetch thread messages
	var messages []models.SubmissionMessage
	models.DB.Where("submission_id = ?", submission.ID).
		Order("created_at ASC").
		Find(&messages)

	// Merge into a single timeline, tagged by type
	type timelineEntry struct {
		ID             string `json:"id"`
		SenderType     string `json:"sender_type"`
		EncryptedText  string `json:"encrypted_text"`
		EncryptionMeta string `json:"encryption_meta"`
		MessageText    string `json:"message_text"`
		CreatedAt      string `json:"created_at"`
		Source         string `json:"source"` // "reply" or "thread"
	}

	var timeline []timelineEntry

	for _, r := range replies {
		timeline = append(timeline, timelineEntry{
			ID:             r.ID.String(),
			SenderType:     "org",
			EncryptedText:  r.EncryptedMessage,
			EncryptionMeta: r.EncryptionMeta,
			MessageText:    r.MessageText,
			CreatedAt:      r.CreatedAt.Format("2006-01-02T15:04:05Z"),
			Source:         "reply",
		})
	}

	for _, m := range messages {
		timeline = append(timeline, timelineEntry{
			ID:             m.ID.String(),
			SenderType:     m.SenderType,
			EncryptedText:  m.EncryptedText,
			EncryptionMeta: m.EncryptionMeta,
			MessageText:    m.MessageText,
			CreatedAt:      m.CreatedAt.Format("2006-01-02T15:04:05Z"),
			Source:         "thread",
		})
	}

	return c.JSON(fiber.Map{
		"submission_id": submission.ID,
		"timeline":      timeline,
	})
}

// AddThreadMessageFromOrg adds an organization-authored message to a thread (JWT required).
func AddThreadMessageFromOrg(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)
	submissionID := c.Params("id")

	var req struct {
		EncryptedText  string `json:"encrypted_text"`
		EncryptionMeta string `json:"encryption_meta"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request",
		})
	}

	if strings.TrimSpace(req.EncryptedText) == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Message cannot be empty",
		})
	}

	if len(req.EncryptedText) > MaxThreadMessageLength {
		return c.Status(400).JSON(fiber.Map{
			"error": "Message too long",
		})
	}

	var submission models.Submission
	if err := models.DB.Where("id = ? AND organization_id = ?", submissionID, orgID).
		First(&submission).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Submission not found",
		})
	}

	var org models.Organization
	if err := models.DB.Where("id = ?", orgID).First(&org).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Internal error",
		})
	}

	msg := models.SubmissionMessage{
		SubmissionID:   submission.ID,
		AnonymousName:  org.ID.String(), // Org identifier (not an anonymous name)
		SenderType:     "org",
		EncryptedText:  req.EncryptedText,
		EncryptionMeta: req.EncryptionMeta,
		OrganizationID: org.ID,
	}

	if err := models.DB.Create(&msg).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to save message",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Thread message added",
		"msg_id":  msg.ID,
	})
}

// GetThreadFromSubmitter returns thread messages to the anonymous submitter (public, reply-key auth).
// Query params: name=<anonymous_name>&submission_id=<uuid>
func GetThreadFromSubmitter(c *fiber.Ctx) error {
	anonymousName := c.Query("name")
	submissionID := c.Query("submission_id")

	if anonymousName == "" || submissionID == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Anonymous name and submission_id are required",
		})
	}

	var submission models.Submission
	if err := models.DB.Where("id = ?", submissionID).
		First(&submission).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Submission not found",
		})
	}

	if submission.AnonymousName != anonymousName {
		return c.Status(403).JSON(fiber.Map{
			"error": "Name does not match submission",
		})
	}

	var replies []models.Reply
	models.DB.Where("submission_id = ?", submission.ID).
		Order("created_at ASC").
		Find(&replies)

	var messages []models.SubmissionMessage
	models.DB.Where("submission_id = ?", submission.ID).
		Order("created_at ASC").
		Find(&messages)

	type timelineEntry struct {
		ID             string `json:"id"`
		SenderType     string `json:"sender_type"`
		EncryptedText  string `json:"encrypted_text"`
		EncryptionMeta string `json:"encryption_meta"`
		MessageText    string `json:"message_text"`
		CreatedAt      string `json:"created_at"`
		Source         string `json:"source"`
	}

	var timeline []timelineEntry

	for _, r := range replies {
		timeline = append(timeline, timelineEntry{
			ID:             r.ID.String(),
			SenderType:     "org",
			EncryptedText:  r.EncryptedMessage,
			EncryptionMeta: r.EncryptionMeta,
			MessageText:    r.MessageText,
			CreatedAt:      r.CreatedAt.Format("2006-01-02T15:04:05Z"),
			Source:         "reply",
		})
	}

	for _, m := range messages {
		timeline = append(timeline, timelineEntry{
			ID:             m.ID.String(),
			SenderType:     m.SenderType,
			EncryptedText:  m.EncryptedText,
			EncryptionMeta: m.EncryptionMeta,
			MessageText:    m.MessageText,
			CreatedAt:      m.CreatedAt.Format("2006-01-02T15:04:05Z"),
			Source:         "thread",
		})
	}

	return c.JSON(fiber.Map{
		"submission_id": submission.ID,
		"timeline":      timeline,
		"reply_key":     submission.ReplyPublicKey,
	})
}

// AddThreadMessageFromSubmitter adds a follow-up message from the anonymous submitter (public).
// The submitter provides their anonymous name and submission_id to prove identity.
func AddThreadMessageFromSubmitter(c *fiber.Ctx) error {
	type ThreadMsgRequest struct {
		AnonymousName  string `json:"anonymous_name"`
		SubmissionID   string `json:"submission_id"`
		EncryptedText  string `json:"encrypted_text"`
		EncryptionMeta string `json:"encryption_meta"`
	}

	var req ThreadMsgRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request",
		})
	}

	if req.AnonymousName == "" || req.SubmissionID == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Anonymous name and submission_id are required",
		})
	}

	if strings.TrimSpace(req.EncryptedText) == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Message cannot be empty",
		})
	}

	if len(req.EncryptedText) > MaxThreadMessageLength {
		return c.Status(400).JSON(fiber.Map{
			"error": "Message too long",
		})
	}

	var submission models.Submission
	if err := models.DB.Where("id = ?", req.SubmissionID).
		First(&submission).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Submission not found",
		})
	}

	if submission.AnonymousName != req.AnonymousName {
		return c.Status(403).JSON(fiber.Map{
			"error": "Name does not match submission",
		})
	}

	msg := models.SubmissionMessage{
		SubmissionID:   submission.ID,
		AnonymousName:  req.AnonymousName,
		SenderType:     "submitter",
		EncryptedText:  req.EncryptedText,
		EncryptionMeta: req.EncryptionMeta,
		OrganizationID: submission.OrganizationID,
	}

	if err := models.DB.Create(&msg).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to save message",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Thread message added",
		"msg_id":  msg.ID,
	})
}
