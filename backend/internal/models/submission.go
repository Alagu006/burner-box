package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Submission represents an anonymous tip submitted to an organization
type Submission struct {
	ID             uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	OrganizationID uuid.UUID `gorm:"type:uuid;not null;index" json:"organization_id"`
	AnonymousName  string    `gorm:"size:100;not null" json:"anonymous_name"`

	// E2EE fields (encrypted content stored as base64)
	EncryptedMessage string `gorm:"type:text" json:"encrypted_message"` // Encrypted message content
	EncryptionMeta   string `gorm:"type:text" json:"encryption_meta"`   // JSON string with nonce, encryptedKey, boxNonce, senderPublicKey

	// Legacy field (kept for backward compatibility, will be empty for E2EE submissions)
	MessageText string `gorm:"type:text" json:"message_text"`

	// Reply key info
	ReplyPublicKey string `gorm:"type:text" json:"reply_public_key,omitempty"` // Public key — safe to expose
	HasReplyKey    bool   `gorm:"default:false" json:"has_reply_key"`          // Boolean flag

	// File info
	HasFiles  bool `gorm:"default:false" json:"has_files"`
	FileCount int  `gorm:"default:0" json:"file_count"`

	// Status & priority
	Status   string `gorm:"size:20;default:'unread'" json:"status"`   // unread, read, actioned, flagged, archived
	Priority string `gorm:"size:20;default:'normal'" json:"priority"` // low, normal, high, urgent

	// Assignment
	AssignedTo    *uuid.UUID `gorm:"type:uuid" json:"assigned_to,omitempty"` // Team member ID, nullable
	InternalNotes string     `gorm:"type:text" json:"internal_notes"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relationships
	Organization Organization `gorm:"foreignKey:OrganizationID" json:"-"`
	Assignee     *TeamMember  `gorm:"foreignKey:AssignedTo" json:"assignee,omitempty"`
}

// SubmissionFile represents a file attached to a submission (encrypted)
type SubmissionFile struct {
	ID           uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	SubmissionID uuid.UUID `gorm:"type:uuid;not null;index" json:"submission_id"`
	FileName     string    `gorm:"size:255;not null" json:"file_name"`
	FileSize     int64     `json:"file_size"`
	StorageKey   string    `gorm:"size:500;not null" json:"-"` // R2/local storage key (not exposed)
	MimeType     string    `gorm:"size:100" json:"mime_type"`

	// E2EE metadata for the file
	EncryptionMeta string `gorm:"type:text" json:"encryption_meta"` // JSON with nonce, encryptedKey, boxNonce, senderPublicKey

	// Server-side encryption: base64-encoded nonce used to derive per-file key from FILE_ENCRYPTION_KEY.
	// This protects against raw disk compromise but is NOT a substitute for client-side E2EE,
	// since the server holds the master key and can decrypt.
	FileEncryptionKey string `gorm:"size:200" json:"-"`

	CreatedAt time.Time `json:"created_at"`
}

// Reply represents an organization's reply to a submission
type Reply struct {
	ID           uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	SubmissionID uuid.UUID `gorm:"type:uuid;not null;index" json:"submission_id"`

	// Encrypted reply (encrypted with submitter's public key if they provided one)
	EncryptedMessage string `gorm:"type:text" json:"encrypted_message"`
	EncryptionMeta   string `gorm:"type:text" json:"encryption_meta"`

	// Legacy plaintext field (for non-encrypted replies)
	MessageText string `gorm:"type:text" json:"message_text"`

	CreatedAt time.Time `json:"created_at"`
}

// SubmissionMessage represents a follow-up message in a submission thread.
// Messages use the same E2EE path as Replies (encrypted with the submitter's reply key).
type SubmissionMessage struct {
	ID             uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	SubmissionID   uuid.UUID `gorm:"type:uuid;not null;index" json:"submission_id"`
	AnonymousName  string    `gorm:"size:100;not null" json:"anonymous_name"` // Who sent it
	SenderType     string    `gorm:"size:20;not null" json:"sender_type"`     // "submitter" or "org"
	EncryptedText  string    `gorm:"type:text" json:"encrypted_text"`
	EncryptionMeta string    `gorm:"type:text" json:"encryption_meta"`
	MessageText    string    `gorm:"type:text" json:"message_text"` // Legacy plaintext
	CreatedAt      time.Time `json:"created_at"`

	Organization   Organization `gorm:"foreignKey:OrganizationID" json:"-"`
	OrganizationID uuid.UUID    `gorm:"type:uuid;not null" json:"organization_id"`
}

// BeforeCreate hooks for UUID generation
func (s *Submission) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}

func (f *SubmissionFile) BeforeCreate(tx *gorm.DB) error {
	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}
	return nil
}

func (r *Reply) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}

func (m *SubmissionMessage) BeforeCreate(tx *gorm.DB) error {
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	return nil
}

// InternalNote is a threaded internal note on a submission.
// Supports tree structure via ParentNoteID (nil = root note).
type InternalNote struct {
	ID             uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	SubmissionID   uuid.UUID  `gorm:"type:uuid;not null;index" json:"submission_id"`
	OrganizationID uuid.UUID  `gorm:"type:uuid;not null" json:"organization_id"`
	AuthorEmail    string     `gorm:"size:255;not null" json:"author_email"`
	AuthorRole     string     `gorm:"size:50;not null" json:"author_role"`
	Content        string     `gorm:"type:text;not null" json:"content"`
	ParentNoteID   *uuid.UUID `gorm:"type:uuid" json:"parent_note_id,omitempty"`
	Depth          int        `gorm:"default:0" json:"depth"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

func (n *InternalNote) BeforeCreate(tx *gorm.DB) error {
	if n.ID == uuid.Nil {
		n.ID = uuid.New()
	}
	return nil
}

// Activity records a mutation event on a submission (actor + action + timestamp).
// Never stores submission content — only metadata about what happened.
type Activity struct {
	ID             uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	SubmissionID   uuid.UUID `gorm:"type:uuid;not null;index" json:"submission_id"`
	OrganizationID uuid.UUID `gorm:"type:uuid;not null" json:"organization_id"`
	ActorEmail     string    `gorm:"size:255;not null" json:"actor_email"`
	ActorRole      string    `gorm:"size:50;not null" json:"actor_role"`
	ActionType     string    `gorm:"size:50;not null" json:"action_type"` // status_change, assignment, note_added, reply_sent, thread_message
	Detail         string    `gorm:"type:text" json:"detail"`             // e.g. "status: unread → read", "assigned to alice@example.com"
	CreatedAt      time.Time `json:"created_at"`
}

func (a *Activity) BeforeCreate(tx *gorm.DB) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	return nil
}

// Helper method to check if submission is encrypted
func (s *Submission) IsEncrypted() bool {
	return s.EncryptedMessage != "" && s.EncryptionMeta != ""
}

// Helper method to get decrypted preview (for list display, will be empty if encrypted)
func (s *Submission) GetPreview() string {
	if s.IsEncrypted() {
		return "[Encrypted] — Requires decryption key"
	}
	if len(s.MessageText) > 80 {
		return s.MessageText[:80]
	}
	return s.MessageText
}
