package models

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Organization represents a registered organization
type Organization struct {
	ID             uuid.UUID    `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Name           string       `gorm:"size:255;not null" json:"name"`
	Email          string       `gorm:"size:255;uniqueIndex;not null" json:"email"`
	PasswordHash   string       `gorm:"not null" json:"-"`
	PublicKey      string       `gorm:"type:text" json:"public_key"` // Organization's public key for E2EE
	SubmissionSlug string       `gorm:"size:64;uniqueIndex;not null" json:"submission_slug"`
	WelcomeMessage string       `gorm:"size:1000" json:"welcome_message"`
	IsVerified     bool         `gorm:"default:false" json:"is_verified"`
	TOTPSecret     string       `gorm:"size:255" json:"-"`
	TOTPEnabled    bool         `gorm:"default:false" json:"totp_enabled"`
	SubmissionDeadline *time.Time `gorm:"type:timestamptz" json:"submission_deadline,omitempty"` // nil = always open

	// Configurable retention: auto-delete submissions older than N days.
	// nil = indefinite (never auto-delete). Background job runs hourly.
	RetentionDays *int `gorm:"type:int" json:"retention_days,omitempty"`

	// Webhook URL for new-submission notifications (metadata only: ID, timestamp, slug).
	// Must not point at private/internal IP ranges (SSRF protection enforced server-side).
	WebhookURL string `gorm:"size:2048" json:"webhook_url,omitempty"`

	// Notification email for new-submission alerts (metadata only, never message content).
	// Email is a deliberate scope limit — we never send encrypted blobs over email.
	NotificationEmail string `gorm:"size:255" json:"notification_email,omitempty"`

	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
	TeamMembers    []TeamMember `gorm:"foreignKey:OrganizationID" json:"team_members,omitempty"`
}

// TeamMember represents a team member
type TeamMember struct {
	ID             uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	OrganizationID uuid.UUID  `gorm:"type:uuid;not null;index" json:"organization_id"`
	Email          string     `gorm:"size:255;not null" json:"email"`
	Role           string     `gorm:"size:50;default:'reader'" json:"role"`
	InvitedAt      time.Time  `json:"invited_at"`
	AcceptedAt     *time.Time `json:"accepted_at,omitempty"`
}

// DeadMansSwitch configures a per-org dead man's switch.
// When enabled, if the org doesn't log in within TriggerDays,
// the configured Action is executed (e.g. send an email).
// The EncryptedConfig is stored encrypted with the org's public key.
type DeadMansSwitch struct {
	ID             uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	OrganizationID uuid.UUID `gorm:"type:uuid;not null;uniqueIndex" json:"organization_id"`
	Enabled        bool      `gorm:"default:false" json:"enabled"`
	TriggerDays    int       `gorm:"default:30" json:"trigger_days"` // Days without login before trigger
	ActionType     string    `gorm:"size:50;default:'email'" json:"action_type"` // "email", "publish", "delete"
	EncryptedConfig string  `gorm:"type:text" json:"-"` // JSON encrypted with org's public key
	LastLoginAt    time.Time `json:"last_login_at"`      // Last time org logged in
	TriggeredAt    *time.Time `json:"triggered_at,omitempty"` // When the switch last triggered
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// BeforeCreate generates ID and submission slug
func (org *Organization) BeforeCreate(tx *gorm.DB) error {
	if org.ID == uuid.Nil {
		org.ID = uuid.New()
	}
	if org.SubmissionSlug == "" {
		org.SubmissionSlug = generateSubmissionSlug()
	}
	return nil
}

// generateSubmissionSlug creates a unique, hard-to-guess URL slug
// Uses crypto/rand for true randomness to avoid collisions
func generateSubmissionSlug() string {
	adjectives := []string{
		"quiet", "brave", "swift", "calm", "wise", "bold", "clear", "free",
		"safe", "true", "pure", "kind", "warm", "cool", "sharp", "bright",
		"deep", "fresh", "grand", "light", "lone", "noble", "prime", "proud",
	}
	nouns := []string{
		"river", "mountain", "forest", "ocean", "falcon", "harbor", "summit",
		"valley", "lantern", "bridge", "canyon", "garden", "island", "meadow",
		"pebble", "ridge", "shadow", "timber", "willow", "zenith", "comet",
		"dragon", "eagle", "falcon", "heron", "jasper", "onyx", "phoenix",
	}

	// Get cryptographically random indices
	adjIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(adjectives))))
	nounIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(nouns))))
	numIndex, _ := rand.Int(rand.Reader, big.NewInt(9999))

	adj := adjectives[adjIndex.Int64()]
	noun := nouns[nounIndex.Int64()]
	num := numIndex.Int64()

	return fmt.Sprintf("%s-%s-%d", adj, noun, num)
}

// GenerateAnonymousName creates a friendly anonymous identity for submitters.
// Entropy: 64 adjectives × 64 animals × 36^4 suffix ≈ 34 billion combinations (~35 bits).
func GenerateAnonymousName() string {
	adjectives := []string{
		"Purple", "Green", "Blue", "Red", "Orange", "Silver", "Golden", "Crimson",
		"Indigo", "Teal", "Amber", "Jade", "Coral", "Olive", "Plum", "Navy",
		"Crimson", "Scarlet", "Ivory", "Onyx", "Copper", "Bronze", "Chrome", "Steel",
		"Ember", "Frost", "Glacier", "Moss", "Cedar", "Pebble", "Dusk", "Dawn",
		"Storm", "Gale", "Mist", "Fog", "Haze", "Cloud", "Rain", "Snow",
		"Flame", "Spark", "Blaze", "Ash", "Soot", "Char", "Coal", "Cinder",
		"Silk", "Velvet", "Cotton", "Linen", "Felt", "Suede", "Denim", "Tweed",
		"Sage", "Basil", "Clover", "Fern", "Reed", "Thorn", "Vine", "Root",
	}
	animals := []string{
		"Dolphin", "Eagle", "Tiger", "Panda", "Fox", "Owl", "Wolf", "Bear",
		"Hawk", "Lynx", "Falcon", "Otter", "Crane", "Robin", "Raven", "Deer",
		"Swan", "Heron", "Wren", "Jay", "Finch", "Martin", "Swift", "Kite",
		"Badger", "Marten", "Weasel", "Mink", "Hare", "Hedgehog", "Moose", "Elk",
		"Puma", "Lynx", "Jaguar", "Leopard", "Cheetah", "Panther", "Cougar", "Bobcat",
		"Salmon", "Trout", "Pike", "Perch", "Bass", "Carp", "Roach", "Dace",
		"Ant", "Bee", "Crab", "Wasp", "Moth", "Flea", "Mite", "Slug",
		"Tern", "Gull", "Duck", "Goose", "Swan", "Pigeon", "Dove", "Lark",
	}

	colorIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(adjectives))))
	animalIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(animals))))

	// Append a 4-character random suffix (A-Z, 0-9) for ~21 bits extra entropy
	suffix := make([]byte, 4)
	for i := range suffix {
		n, _ := rand.Int(rand.Reader, big.NewInt(36))
		if n.Int64() < 10 {
			suffix[i] = byte('0' + n.Int64())
		} else {
			suffix[i] = byte('A' + n.Int64() - 10)
		}
	}

	return fmt.Sprintf("%s %s-%s", adjectives[colorIdx.Int64()], animals[animalIdx.Int64()], string(suffix))
}