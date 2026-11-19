package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// MerkleBatch represents an append-only batch of submissions for an organization.
// While open, new submissions are appended as leaves.
// When sealed, the Merkle root is computed, signed with the server's Ed25519 key, and published.
type MerkleBatch struct {
	ID             uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	OrganizationID uuid.UUID  `gorm:"type:uuid;not null;index" json:"organization_id"`
	BatchNumber    int        `gorm:"not null" json:"batch_number"`
	Status         string     `gorm:"size:20;default:'open'" json:"status"` // "open" | "sealed"
	RootHash       string     `gorm:"size:64" json:"root_hash,omitempty"`
	Signature      string     `gorm:"type:text" json:"signature,omitempty"`
	KeyFingerprint string     `gorm:"size:32" json:"key_fingerprint,omitempty"`
	LeafCount      int        `gorm:"default:0" json:"leaf_count"`
	SealedAt       *time.Time `json:"sealed_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`

	Leaves []MerkleLeaf `gorm:"foreignKey:BatchID" json:"leaves,omitempty"`
}

// MerkleLeaf represents a single submission's leaf entry in a Merkle batch.
type MerkleLeaf struct {
	ID             uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	BatchID        uuid.UUID `gorm:"type:uuid;not null;index" json:"batch_id"`
	OrganizationID uuid.UUID `gorm:"type:uuid;not null;index" json:"organization_id"`
	SubmissionID   uuid.UUID `gorm:"type:uuid;not null;uniqueIndex" json:"submission_id"`
	LeafIndex      int       `gorm:"not null" json:"leaf_index"`
	LeafHash       string    `gorm:"size:64;not null" json:"leaf_hash"`
	CreatedAt      time.Time `json:"created_at"`
}

// TableName overrides GORM's default pluralization
func (MerkleBatch) TableName() string {
	return "merkle_batches"
}

func (MerkleLeaf) TableName() string {
	return "merkle_leaves"
}

// BeforeCreate hooks for UUID generation
func (b *MerkleBatch) BeforeCreate(tx *gorm.DB) error {
	if b.ID == uuid.Nil {
		b.ID = uuid.New()
	}
	return nil
}

func (l *MerkleLeaf) BeforeCreate(tx *gorm.DB) error {
	if l.ID == uuid.Nil {
		l.ID = uuid.New()
	}
	return nil
}
