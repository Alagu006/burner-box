package models

import (
	"time"

	"github.com/google/uuid"
)

// Session represents an active authenticated organization session.
// Strictly avoids storing IP addresses or User-Agent fingerprints (per docs/PRIVACY.md).
type Session struct {
	ID             uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	OrganizationID uuid.UUID `gorm:"type:uuid;not null;index" json:"organization_id"`
	TokenHash      string    `gorm:"size:64;not null;index" json:"-"` // SHA-256 hex of the raw JWT (raw token is never stored)
	CreatedAt      time.Time `json:"created_at"`
	LastSeenAt     time.Time `json:"last_seen_at"`
	ExpiresAt      time.Time `gorm:"index" json:"expires_at"`
}
