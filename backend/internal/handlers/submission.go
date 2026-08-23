package handlers

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"burner-box-backend/internal/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type SubmissionRequest struct {
	MessageText      string `json:"message_text"`
	ReplyPublicKey   string `json:"reply_public_key,omitempty"`
	EncryptedMessage string `json:"encrypted_message,omitempty"`
	EncryptionMeta   string `json:"encryption_meta,omitempty"`
}

type UpdateSubmissionRequest struct {
	Status        string `json:"status,omitempty"`
	Priority      string `json:"priority,omitempty"`
	InternalNotes string `json:"internal_notes,omitempty"`
}

// GetOrganizationPublicKey returns the public key for a submission slug
// NO AUTH REQUIRED - needed by submitters to encrypt
func GetOrganizationPublicKey(c *fiber.Ctx) error {
	slug := c.Params("slug")
	if slug == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Submission slug is required",
		})
	}

	var org models.Organization
	if err := models.DB.Select("public_key", "name", "submission_slug", "submission_deadline").
		Where("submission_slug = ?", slug).
		First(&org).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Organization not found",
		})
	}

	if org.PublicKey == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "This organization has not enabled encrypted submissions",
		})
	}

	resp := fiber.Map{
		"organization_name": org.Name,
		"public_key":        org.PublicKey,
	}

	if org.SubmissionDeadline != nil {
		resp["deadline"] = org.SubmissionDeadline.Format(time.RFC3339)
		if org.SubmissionDeadline.Before(time.Now()) {
			resp["closed"] = true
		}
	}

	return c.JSON(resp)
}

// SubmitAnonymousTip handles anonymous tip submission with optional files
// NO AUTH REQUIRED - this is the public endpoint
func SubmitAnonymousTip(c *fiber.Ctx) error {
	slug := c.Params("slug")
	if slug == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Submission slug is required",
		})
	}

	// Find organization by submission slug
	var org models.Organization
	result := models.DB.Where("submission_slug = ?", slug).First(&org)
	if result.Error != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Submission portal not found. Please check the URL.",
		})
	}

	// Check submission deadline
	if org.SubmissionDeadline != nil && org.SubmissionDeadline.Before(time.Now()) {
		return c.Status(403).JSON(fiber.Map{
			"error": "This submission portal is closed.",
		})
	}

	// Parse form data (supports both multipart and JSON)
	messageText := c.FormValue("message_text")
	replyPublicKey := c.FormValue("reply_public_key")
	encryptedMessage := c.FormValue("encrypted_message")
	encryptionMeta := c.FormValue("encryption_meta")

	// If no form values, try parsing JSON body
	if messageText == "" && encryptedMessage == "" {
		var req SubmissionRequest
		if err := c.BodyParser(&req); err == nil {
			messageText = req.MessageText
			replyPublicKey = req.ReplyPublicKey
			encryptedMessage = req.EncryptedMessage
			encryptionMeta = req.EncryptionMeta
		}
	}

	// Validate that we have a message (encrypted or plaintext)
	if strings.TrimSpace(messageText) == "" && strings.TrimSpace(encryptedMessage) == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Message cannot be empty",
		})
	}

	// Enforce server-side encryption requirement: when the org has a public key,
	// plaintext submissions must be rejected. The server never stores plaintext
	// for orgs that have enabled E2EE.
	if org.PublicKey != "" && strings.TrimSpace(encryptedMessage) == "" {
		log.Printf("SUBMIT_TIP rejected: org=%s has public key but received plaintext", org.ID)
		return c.Status(400).JSON(fiber.Map{
			"error": "This organization requires encrypted submissions. Please encrypt your message before sending.",
		})
	}

	// Enforce input length limits
	if len(messageText) > MaxMessageLength {
		return c.Status(400).JSON(fiber.Map{
			"error": "Message too long",
		})
	}
	if len(encryptedMessage) > MaxEncryptedLength {
		return c.Status(400).JSON(fiber.Map{
			"error": "Encrypted message too long",
		})
	}
	if len(encryptionMeta) > MaxEncryptionMetaLen {
		return c.Status(400).JSON(fiber.Map{
			"error": "Encryption metadata too long",
		})
	}
	if len(replyPublicKey) > MaxReplyPublicKeysLen {
		return c.Status(400).JSON(fiber.Map{
			"error": "Reply public key too long",
		})
	}

	// Generate anonymous name
	anonymousName := models.GenerateAnonymousName()

	// Create submission
	submission := models.Submission{
		OrganizationID:   org.ID,
		AnonymousName:    anonymousName,
		MessageText:      messageText,      // Empty for encrypted submissions
		EncryptedMessage: encryptedMessage, // Ciphertext (base64)
		EncryptionMeta:   encryptionMeta,   // JSON with nonce, encryptedKey, etc.
		ReplyPublicKey:   replyPublicKey,
		HasReplyKey:      replyPublicKey != "",
		Status:           "unread",
	}

	if err := models.DB.Create(&submission).Error; err != nil {
		log.Printf("SUBMIT_TIP failed: DB create error: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to save submission",
		})
	}

	// Handle file uploads (if any) — with magic-byte validation,
	// image metadata stripping, and server-side encryption.
	uploadedFiles := []FileUploadResponse{}

	form, err := c.MultipartForm()
	if err == nil && form != nil {
		files := form.File["files"]

		for _, file := range files {
			// Validate file size
			if file.Size > MaxFileSize {
				continue
			}

			// Validate file type by extension
			ext := strings.ToLower(filepath.Ext(file.Filename))
			if !strings.Contains(AllowedTypes, ext) {
				continue
			}

			// Process: validate magic bytes, strip image metadata, encrypt, write to disk
			storageKey, fileEncKey, procErr := processAndEncryptFile(submission.ID.String(), file, ext)
			if procErr != nil {
				log.Printf("processAndEncryptFile failed (submission %s): %v", submission.ID, procErr)
				continue
			}

			// Detect the MIME type from the encrypted file for the DB record
			fullPath := filepath.Join("uploads", storageKey)
			rawForMime, _ := os.ReadFile(fullPath)
			detectedMIME := http.DetectContentType(rawForMime)
			if idx := strings.IndexByte(detectedMIME, ';'); idx >= 0 {
				detectedMIME = strings.TrimSpace(detectedMIME[:idx])
			}

			// Create file record
			submissionFile := models.SubmissionFile{
				SubmissionID:      submission.ID,
				FileName:          file.Filename,
				FileSize:          file.Size,
				StorageKey:        storageKey,
				MimeType:          detectedMIME,
				FileEncryptionKey: fileEncKey,
			}

			if err := models.DB.Create(&submissionFile).Error; err != nil {
				log.Printf("Failed to save file metadata: %v", err)
				os.Remove(fullPath)
				continue
			}

			uploadedFiles = append(uploadedFiles, FileUploadResponse{
				FileID:   submissionFile.ID.String(),
				FileName: submissionFile.FileName,
				FileSize: submissionFile.FileSize,
				MimeType: submissionFile.MimeType,
			})
		}
	}

	// Update submission with file info
	if len(uploadedFiles) > 0 {
		models.DB.Model(&submission).Updates(map[string]interface{}{
			"has_files":  true,
			"file_count": len(uploadedFiles),
		})
	}

	// Build reply hint
	var replyHint string
	if replyPublicKey != "" {
		replyHint = "Your anonymous identity is: " + anonymousName +
			". Save this name to check for replies. Return to the same URL and enter this name."
	}

	log.Printf("SUBMIT_TIP success: anon=%s files=%d encrypted=%v", anonymousName, len(uploadedFiles), encryptedMessage != "")

	// Dispatch notifications (metadata only — never message content)
	go SendWebhookNotification(org.ID.String(), submission.ID.String(), slug)
	go SendEmailNotification(org.ID.String(), submission.ID.String(), slug)

	resp := fiber.Map{
		"message":        "Submission received successfully",
		"anonymous_name": anonymousName,
		"submission_id":  submission.ID,
		"reply_hint":     replyHint,
		"has_reply_key":  replyPublicKey != "",
		"is_encrypted":   encryptedMessage != "",
		"files_uploaded": len(uploadedFiles),
		"files":          uploadedFiles,
	}

	// Generate proof of submission if server key is available
	if proof := GenerateProofOfSubmission(submission.ID.String(), encryptedMessage); proof != nil {
		resp["proof"] = proof
	}

	return c.Status(201).JSON(resp)
}

// GetOrganizationSubmissions returns submissions for the organization with optional filters.
// Query params: assigned_to_me=true, priority=high, status=unread, sort=created_at|priority|status, order=asc|desc
func GetOrganizationSubmissions(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)
	email, _ := c.Locals("email").(string)

	query := models.DB.Where("organization_id = ?", orgID)

	// Filter: assigned to me
	if c.Query("assigned_to_me") == "true" {
		var member models.TeamMember
		if err := models.DB.Where("organization_id = ? AND email = ?", orgID, email).
			First(&member).Error; err == nil {
			query = query.Where("assigned_to = ?", member.ID)
		} else {
			// No team member record — return nothing assigned to "me"
			query = query.Where("1 = 0")
		}
	}

	// Filter: priority
	if p := c.Query("priority"); p != "" {
		validPriorities := map[string]bool{"low": true, "normal": true, "high": true, "urgent": true}
		if validPriorities[p] {
			query = query.Where("priority = ?", p)
		}
	}

	// Filter: status
	if s := c.Query("status"); s != "" {
		validStatuses := map[string]bool{"unread": true, "read": true, "actioned": true, "flagged": true, "archived": true}
		if validStatuses[s] {
			query = query.Where("status = ?", s)
		}
	}

	// Sort
	sortField := c.Query("sort", "created_at")
	validSorts := map[string]bool{"created_at": true, "priority": true, "status": true, "updated_at": true}
	if !validSorts[sortField] {
		sortField = "created_at"
	}
	sortOrder := c.Query("order", "desc")
	if sortOrder != "asc" {
		sortOrder = "desc"
	}

	// Custom sort for priority: urgent > high > normal > low
	if sortField == "priority" {
		query = query.Order("CASE priority WHEN 'urgent' THEN 1 WHEN 'high' THEN 2 WHEN 'normal' THEN 3 WHEN 'low' THEN 4 ELSE 5 END " + sortOrder)
	} else {
		query = query.Order(sortField + " " + sortOrder)
	}

	var submissions []models.Submission
	if err := query.Find(&submissions).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to fetch submissions",
		})
	}

	return c.JSON(fiber.Map{
		"submissions": submissions,
		"count":       len(submissions),
	})
}

// GetSubmission returns a single submission by ID
func GetSubmission(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)
	submissionID := c.Params("id")

	var submission models.Submission
	if err := models.DB.Where("id = ? AND organization_id = ?", submissionID, orgID).
		First(&submission).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Submission not found",
		})
	}

	// Get associated files
	var files []models.SubmissionFile
	models.DB.Where("submission_id = ?", submissionID).Find(&files)

	// Get replies
	var replies []models.Reply
	models.DB.Where("submission_id = ?", submissionID).Find(&replies)

	return c.JSON(fiber.Map{
		"submission": submission,
		"files":      files,
		"replies":    replies,
	})
}

// UpdateSubmissionStatus updates the status, priority, and/or notes of a submission
func UpdateSubmissionStatus(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)
	actorEmail, _ := c.Locals("email").(string)
	actorRole, _ := c.Locals("role").(string)
	submissionID := c.Params("id")

	var req UpdateSubmissionRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request",
		})
	}

	var submission models.Submission
	if err := models.DB.Where("id = ? AND organization_id = ?", submissionID, orgID).
		First(&submission).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Submission not found",
		})
	}

	orgUUID := submission.OrganizationID

	// Update status if provided
	if req.Status != "" {
		validStatuses := map[string]bool{"unread": true, "read": true, "actioned": true, "flagged": true, "archived": true}
		if !validStatuses[req.Status] {
			return c.Status(400).JSON(fiber.Map{
				"error": "Invalid status. Use: unread, read, actioned, flagged, or archived",
			})
		}
		if submission.Status != req.Status {
			oldStatus := submission.Status
			submission.Status = req.Status
			logActivity(submission.ID, orgUUID, actorEmail, actorRole,
				"status_change", "status: "+oldStatus+" → "+req.Status)
		}
	}

	// Update priority if provided
	if req.Priority != "" {
		validPriorities := map[string]bool{"low": true, "normal": true, "high": true, "urgent": true}
		if !validPriorities[req.Priority] {
			return c.Status(400).JSON(fiber.Map{
				"error": "Invalid priority. Use: low, normal, high, or urgent",
			})
		}
		if submission.Priority != req.Priority {
			oldPriority := submission.Priority
			submission.Priority = req.Priority
			logActivity(submission.ID, orgUUID, actorEmail, actorRole,
				"priority_change", "priority: "+oldPriority+" → "+req.Priority)
		}
	}

	// Update internal notes if provided
	if req.InternalNotes != "" {
		if len(req.InternalNotes) > MaxNoteLength {
			return c.Status(400).JSON(fiber.Map{
				"error": "Internal notes too long",
			})
		}
		submission.InternalNotes = req.InternalNotes
	}

	models.DB.Save(&submission)

	// Push status change to any WebSocket listeners (submitter check-replies page)
	PushStatusChange(submissionID, submission.Status)

	log.Printf("UPDATE_STATUS success: submission=%s status=%s priority=%s", submissionID, submission.Status, submission.Priority)
	return c.JSON(fiber.Map{
		"message":    "Submission updated",
		"submission": submission,
	})
}

// AddInternalNote adds a private threaded note visible only to the organization team
func AddInternalNote(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)
	actorEmail, _ := c.Locals("email").(string)
	actorRole, _ := c.Locals("role").(string)
	submissionID := c.Params("id")

	type NoteRequest struct {
		Note         string  `json:"note"`
		ParentNoteID *string `json:"parent_note_id,omitempty"` // UUID string or null
	}

	var req NoteRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request",
		})
	}

	if strings.TrimSpace(req.Note) == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Note cannot be empty",
		})
	}

	if len(req.Note) > MaxNoteLength {
		return c.Status(400).JSON(fiber.Map{
			"error": "Note too long",
		})
	}

	var submission models.Submission
	if err := models.DB.Where("id = ? AND organization_id = ?", submissionID, orgID).
		First(&submission).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Submission not found",
		})
	}

	orgUUID := submission.OrganizationID
	depth := 0

	note := models.InternalNote{
		SubmissionID:   submission.ID,
		OrganizationID: orgUUID,
		AuthorEmail:    actorEmail,
		AuthorRole:     actorRole,
		Content:        strings.TrimSpace(req.Note),
	}

	// Thread reply: validate parent exists and compute depth
	if req.ParentNoteID != nil && *req.ParentNoteID != "" {
		parsed, err := uuid.Parse(*req.ParentNoteID)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid parent_note_id"})
		}

		var parent models.InternalNote
		if err := models.DB.Where("id = ? AND submission_id = ?", parsed, submission.ID).
			First(&parent).Error; err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Parent note not found"})
		}

		note.ParentNoteID = &parsed
		depth = parent.Depth + 1
		if depth > 5 {
			depth = 5 // Cap nesting depth
		}
		note.Depth = depth
	}

	if err := models.DB.Create(&note).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save note"})
	}

	logActivity(submission.ID, orgUUID, actorEmail, actorRole, "note_added", "note by "+actorEmail)

	log.Printf("ADD_NOTE success: submission=%s depth=%d", submissionID, depth)
	return c.JSON(fiber.Map{
		"message": "Note added",
		"note":    note,
	})
}

// GetInternalNotes returns all threaded notes for a submission (dashboard, JWT required)
func GetInternalNotes(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)
	submissionID := c.Params("id")

	var submission models.Submission
	if err := models.DB.Where("id = ? AND organization_id = ?", submissionID, orgID).
		First(&submission).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Submission not found"})
	}

	var notes []models.InternalNote
	models.DB.Where("submission_id = ?", submission.ID).
		Order("created_at ASC").
		Find(&notes)

	return c.JSON(fiber.Map{
		"notes": notes,
	})
}

// GetSubmissionActivity returns the activity timeline for a submission (dashboard, JWT required)
func GetSubmissionActivity(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)
	submissionID := c.Params("id")

	var submission models.Submission
	if err := models.DB.Where("id = ? AND organization_id = ?", submissionID, orgID).
		First(&submission).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Submission not found"})
	}

	var activities []models.Activity
	models.DB.Where("submission_id = ?", submission.ID).
		Order("created_at DESC").
		Limit(100).
		Find(&activities)

	return c.JSON(fiber.Map{
		"activities": activities,
	})
}

// ReplyToSubmission allows an organization to reply (encrypted with submitter's public key)
func ReplyToSubmission(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)
	actorEmail, _ := c.Locals("email").(string)
	actorRole, _ := c.Locals("role").(string)
	submissionID := c.Params("id")

	type ReplyRequest struct {
		MessageText      string `json:"message_text"`
		EncryptedMessage string `json:"encrypted_message"`
		EncryptionMeta   string `json:"encryption_meta"`
	}

	var req ReplyRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request",
		})
	}

	// Enforce input length limits
	if len(req.MessageText) > MaxReplyMessageLen {
		return c.Status(400).JSON(fiber.Map{
			"error": "Reply message too long",
		})
	}
	if len(req.EncryptedMessage) > MaxEncryptedLength {
		return c.Status(400).JSON(fiber.Map{
			"error": "Encrypted reply too long",
		})
	}
	if len(req.EncryptionMeta) > MaxEncryptionMetaLen {
		return c.Status(400).JSON(fiber.Map{
			"error": "Encryption metadata too long",
		})
	}

	// Find submission
	var submission models.Submission
	if err := models.DB.Where("id = ? AND organization_id = ?", submissionID, orgID).
		First(&submission).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Submission not found",
		})
	}

	// Check if submitter provided a public key for replies
	if submission.ReplyPublicKey == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Submitter did not enable replies for this submission",
		})
	}

	// When reply key exists, require encrypted payload — reject plaintext
	if submission.HasReplyKey {
		if strings.TrimSpace(req.EncryptedMessage) == "" || strings.TrimSpace(req.EncryptionMeta) == "" {
			return c.Status(400).JSON(fiber.Map{
				"error": "This submission has a reply key. Replies must be encrypted (provide encrypted_message + encryption_meta).",
			})
		}
	}

	// Create reply
	reply := models.Reply{
		SubmissionID:     submission.ID,
		EncryptedMessage: req.EncryptedMessage,
		EncryptionMeta:   req.EncryptionMeta,
		MessageText:      req.MessageText,
		CreatedAt:        time.Now(),
	}

	if err := models.DB.Create(&reply).Error; err != nil {
		log.Printf("REPLY failed: DB create error: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to save reply",
		})
	}

	logActivity(submission.ID, submission.OrganizationID, actorEmail, actorRole,
		"reply_sent", "reply by "+actorEmail)

	log.Printf("REPLY success: submission=%s encrypted=%v", submissionID, req.EncryptedMessage != "")
	return c.Status(201).JSON(fiber.Map{
		"message": "Reply sent successfully",
		"reply":   reply,
	})
}

// CheckForReplies allows a submitter to check for replies using their anonymous name
func CheckForReplies(c *fiber.Ctx) error {
	anonymousName := c.Query("name")
	if anonymousName == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Anonymous name is required",
		})
	}

	// Find submission by anonymous name
	var submission models.Submission
	if err := models.DB.Where("anonymous_name = ?", anonymousName).
		First(&submission).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "No submission found with that name. Check your anonymous identity.",
		})
	}

	// Get replies
	var replies []models.Reply
	models.DB.Where("submission_id = ?", submission.ID).
		Order("created_at ASC").
		Find(&replies)

	// Get slug for status WebSocket URL
	var org models.Organization
	slug := ""
	if err := models.DB.Where("id = ?", submission.OrganizationID).First(&org).Error; err == nil {
		slug = org.SubmissionSlug
	}

	return c.JSON(fiber.Map{
		"submission_id":  submission.ID,
		"anonymous_name": submission.AnonymousName,
		"slug":           slug,
		"status":         submission.Status,
		"reply_count":    len(replies),
		"replies":        replies,
	})
}

