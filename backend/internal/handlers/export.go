package handlers

import (
	"burner-box-backend/internal/models"
	"encoding/base64"
	"encoding/json"
	"log"

	"github.com/gofiber/fiber/v2"
)

// ExportSubmissions returns submission data for client-side password-protected zip creation.
// The server never decrypts — the browser handles decryption using its stored private key.
// POST /dashboard/submissions/export  { "ids": ["uuid", ...] }
func ExportSubmissions(c *fiber.Ctx) error {
	orgID := c.Locals("orgID").(string)

	var req struct {
		IDs []string `json:"ids"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	if len(req.IDs) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No submission IDs provided"})
	}

	type ExportReply struct {
		EncryptedMessage string `json:"encrypted_message"`
		EncryptionMeta   string `json:"encryption_meta"`
		MessageText      string `json:"message_text"`
		CreatedAt        string `json:"created_at"`
	}

	type ExportNote struct {
		Content      string `json:"content"`
		AuthorEmail  string `json:"author_email"`
		AuthorRole   string `json:"author_role"`
		ParentNoteID string `json:"parent_note_id,omitempty"`
		CreatedAt    string `json:"created_at"`
	}

	type ExportThreadMsg struct {
		SenderType     string `json:"sender_type"`
		EncryptedText  string `json:"encrypted_text"`
		EncryptionMeta string `json:"encryption_meta"`
		MessageText    string `json:"message_text"`
		CreatedAt      string `json:"created_at"`
	}

	type ExportFile struct {
		FileName   string `json:"file_name"`
		FileSize   int64  `json:"file_size"`
		MimeType   string `json:"mime_type"`
		StorageKey string `json:"storage_key"`
		// Client encryption metadata (if file was client-side encrypted)
		ClientEncMeta string `json:"client_encryption_meta,omitempty"`
	}

	type ExportSubmission struct {
		ID               string            `json:"id"`
		AnonymousName    string            `json:"anonymous_name"`
		EncryptedMessage string            `json:"encrypted_message"`
		EncryptionMeta   string            `json:"encryption_meta"`
		MessageText      string            `json:"message_text"`
		Status           string            `json:"status"`
		Priority         string            `json:"priority"`
		CreatedAt        string            `json:"created_at"`
		UpdatedAt        string            `json:"updated_at"`
		Replies          []ExportReply     `json:"replies"`
		Notes            []ExportNote      `json:"notes"`
		Thread           []ExportThreadMsg `json:"thread"`
		Files            []ExportFile      `json:"files"`
	}

	var exports []ExportSubmission

	for _, idStr := range req.IDs {
		var sub models.Submission
		if err := models.DB.Where("id = ? AND organization_id = ?", idStr, orgID).
			First(&sub).Error; err != nil {
			continue
		}

		exp := ExportSubmission{
			ID:               sub.ID.String(),
			AnonymousName:    sub.AnonymousName,
			EncryptedMessage: sub.EncryptedMessage,
			EncryptionMeta:   sub.EncryptionMeta,
			MessageText:      sub.MessageText,
			Status:           sub.Status,
			Priority:         sub.Priority,
			CreatedAt:        sub.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:        sub.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		}

		// Replies
		var replies []models.Reply
		models.DB.Where("submission_id = ?", sub.ID).Order("created_at ASC").Find(&replies)
		for _, r := range replies {
			exp.Replies = append(exp.Replies, ExportReply{
				EncryptedMessage: r.EncryptedMessage,
				EncryptionMeta:   r.EncryptionMeta,
				MessageText:      r.MessageText,
				CreatedAt:        r.CreatedAt.Format("2006-01-02T15:04:05Z"),
			})
		}

		// Internal notes
		var notes []models.InternalNote
		models.DB.Where("submission_id = ?", sub.ID).Order("created_at ASC").Find(&notes)
		for _, n := range notes {
			note := ExportNote{
				Content:     n.Content,
				AuthorEmail: n.AuthorEmail,
				AuthorRole:  n.AuthorRole,
				CreatedAt:   n.CreatedAt.Format("2006-01-02T15:04:05Z"),
			}
			if n.ParentNoteID != nil {
				note.ParentNoteID = n.ParentNoteID.String()
			}
			exp.Notes = append(exp.Notes, note)
		}

		// Thread messages
		var threadMsgs []models.SubmissionMessage
		models.DB.Where("submission_id = ?", sub.ID).Order("created_at ASC").Find(&threadMsgs)
		for _, m := range threadMsgs {
			exp.Thread = append(exp.Thread, ExportThreadMsg{
				SenderType:     m.SenderType,
				EncryptedText:  m.EncryptedText,
				EncryptionMeta: m.EncryptionMeta,
				MessageText:    m.MessageText,
				CreatedAt:      m.CreatedAt.Format("2006-01-02T15:04:05Z"),
			})
		}

		// Files — include storage key so the frontend can download them
		var files []models.SubmissionFile
		models.DB.Where("submission_id = ?", sub.ID).Find(&files)
		for _, f := range files {
			exp.Files = append(exp.Files, ExportFile{
				FileName:   f.FileName,
				FileSize:   f.FileSize,
				MimeType:   f.MimeType,
				StorageKey: f.StorageKey,
			})
		}

		exports = append(exports, exp)
	}

	// Log export activity
	log.Printf("EXPORT success: org=%s count=%d", orgID, len(exports))

	// Return as base64-encoded JSON so the frontend can embed it in the zip
	jsonData, _ := json.Marshal(exports)
	encoded := base64.StdEncoding.EncodeToString(jsonData)

	return c.JSON(fiber.Map{
		"count":     len(exports),
		"data_json": encoded,
	})
}
