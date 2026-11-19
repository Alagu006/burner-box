package models

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Room represents an ephemeral secure room with optional password protection
type Room struct {
	ID               uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	RoomCode         string     `gorm:"size:32;uniqueIndex;not null" json:"room_code"`
	PasswordHash     string     `gorm:"type:text" json:"-"`
	CreatorTokenHash string     `gorm:"type:varchar(64);not null;default:''" json:"-"`
	MaxParticipants  int        `gorm:"default:10" json:"max_participants"`
	ExpiresAt        time.Time  `gorm:"not null" json:"expires_at"`
	DestroyedAt      *time.Time `json:"destroyed_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// RoomMessage represents a single message in an ephemeral room
type RoomMessage struct {
	ID               uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	RoomCode         string     `gorm:"size:32;index;not null" json:"room_code"`
	SenderTag        string     `gorm:"size:50;not null" json:"sender_tag"`
	EncryptedMessage string     `gorm:"type:text;not null" json:"encrypted_message"`
	EncryptionMeta   string     `gorm:"type:text" json:"encryption_meta"`
	SelfDestructAt   *time.Time `json:"self_destruct_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// RoomFile represents an encrypted file attachment in a room
type RoomFile struct {
	ID             uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	RoomCode       string     `gorm:"size:32;index;not null" json:"room_code"`
	SenderTag      string     `gorm:"size:50;not null" json:"sender_tag"`
	OriginalName   string     `gorm:"size:255;not null" json:"original_name"`
	MimeType       string     `gorm:"size:127" json:"mime_type"`
	FileSize       int64      `gorm:"not null" json:"file_size"`
	EncryptedData  []byte     `gorm:"type:bytea;not null" json:"-"`
	EncryptionMeta string     `gorm:"type:text" json:"encryption_meta"`
	SelfDestructAt *time.Time `json:"self_destruct_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// RoomReaction represents an encrypted emoji reaction on a message
type RoomReaction struct {
	ID             uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	RoomCode       string    `gorm:"size:32;index;not null" json:"room_code"`
	MessageID      uuid.UUID `gorm:"type:uuid;index;not null" json:"message_id"`
	SenderTag      string    `gorm:"size:50;not null" json:"sender_tag"`
	EncryptedEmoji string    `gorm:"type:text;not null" json:"encrypted_emoji"`
	EncryptionMeta string    `gorm:"type:text" json:"encryption_meta"`
	CreatedAt      time.Time `json:"created_at"`
}

// GenerateRoomCode creates a cryptographically random room code (16 hex chars)
func GenerateRoomCode() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate room code: %w", err)
	}
	return fmt.Sprintf("%x", b), nil
}

// GenerateSenderTag creates an anonymous display name (adjective-noun)
func GenerateSenderTag() string {
	adjectives := []string{
		"quiet", "brave", "swift", "calm", "wise", "bold", "clear", "free",
		"safe", "true", "pure", "kind", "warm", "cool", "sharp", "bright",
		"deep", "fresh", "grand", "light", "lone", "noble", "prime", "proud",
	}
	nouns := []string{
		"river", "mountain", "forest", "ocean", "falcon", "harbor", "summit",
		"valley", "lantern", "bridge", "canyon", "garden", "island", "meadow",
		"pebble", "ridge", "shadow", "timber", "willow", "zenith", "comet",
		"dragon", "eagle", "heron", "jasper", "onyx", "phoenix", "raven",
	}

	adjIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(adjectives))))
	nounIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(nouns))))

	return fmt.Sprintf("%s-%s", adjectives[adjIndex.Int64()], nouns[nounIndex.Int64()])
}

func (r *Room) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}

func (m *RoomMessage) BeforeCreate(tx *gorm.DB) error {
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	return nil
}

func (f *RoomFile) BeforeCreate(tx *gorm.DB) error {
	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}
	return nil
}

func (r *RoomReaction) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}

// IsExpired returns true if the room's expiry time has passed
func (r *Room) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

// IsDestroyed returns true if the room has been explicitly destroyed
func (r *Room) IsDestroyed() bool {
	return r.DestroyedAt != nil
}
