package handlers

import (
	"burner-box-backend/internal/crypto"
	"burner-box-backend/internal/models"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	maxRoomExpiryDays = 7
	maxRoomExpiry     = time.Duration(maxRoomExpiryDays) * 24 * time.Hour
)

type CreateRoomRequest struct {
	Password       string `json:"password"`
	ExpiryDuration string `json:"expiry_duration"` // e.g. "24h", "72h", "168h" (max 168h = 7 days)
}

type CreateRoomResponse struct {
	RoomCode     string    `json:"room_code"`
	JoinURL      string    `json:"join_url"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatorToken string    `json:"creator_token,omitempty"`
}

type RoomStatusResponse struct {
	Exists    bool       `json:"exists"`
	Expired   bool       `json:"expired"`
	Destroyed bool       `json:"destroyed"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// CreateRoom creates a new ephemeral room with a cryptographically secure creator capability token
func CreateRoom(c *fiber.Ctx) error {
	var req CreateRoomRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Parse expiry duration (default 24h, max 7 days)
	duration, err := time.ParseDuration(req.ExpiryDuration)
	if err != nil || duration <= 0 {
		duration = 24 * time.Hour
	}
	if duration > maxRoomExpiry {
		duration = maxRoomExpiry
	}

	// Generate room code
	roomCode, err := models.GenerateRoomCode()
	if err != nil {
		log.Printf("Failed to generate room code: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to create room",
		})
	}

	// Generate cryptographically secure 256-bit creator token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		log.Printf("Failed to generate creator token: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to create room",
		})
	}
	creatorToken := "bb_rt_" + hex.EncodeToString(tokenBytes)
	tokenHashBytes := sha256.Sum256([]byte(creatorToken))
	creatorTokenHash := hex.EncodeToString(tokenHashBytes[:])

	// Hash password if provided (rooms can be unprotected)
	var passwordHash string
	if req.Password != "" {
		passwordHash, err = crypto.HashPassword(req.Password)
		if err != nil {
			log.Printf("Failed to hash room password: %v", err)
			return c.Status(500).JSON(fiber.Map{
				"error": "Failed to create room",
			})
		}
	}

	room := models.Room{
		RoomCode:         roomCode,
		PasswordHash:     passwordHash,
		CreatorTokenHash: creatorTokenHash,
		MaxParticipants:  10,
		ExpiresAt:        time.Now().Add(duration),
	}

	if err := models.DB.Create(&room).Error; err != nil {
		log.Printf("Failed to create room: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to create room",
		})
	}

	// Build join URL — use the request's host
	proto := "http"
	if c.Get("X-Forwarded-Proto") == "https" || c.Get("X-Forwarded-SSL") == "1" {
		proto = "https"
	}
	joinURL := proto + "://" + c.Hostname() + "/rooms/" + roomCode

	log.Printf("ROOM_CREATE success: code=%s expiry=%v", roomCode, duration)
	return c.Status(201).JSON(CreateRoomResponse{
		RoomCode:     roomCode,
		JoinURL:      joinURL,
		ExpiresAt:    room.ExpiresAt,
		CreatorToken: creatorToken,
	})
}

// GetRoomStatus returns whether a room exists without leaking any data or tokens
func GetRoomStatus(c *fiber.Ctx) error {
	code := c.Params("code")
	if code == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Room code is required",
		})
	}

	var room models.Room
	if err := models.DB.Where("room_code = ?", code).First(&room).Error; err != nil {
		// Room not found — return generic "not found" without confirming existence
		return c.Status(200).JSON(RoomStatusResponse{
			Exists: false,
		})
	}

	return c.Status(200).JSON(RoomStatusResponse{
		Exists:    true,
		Expired:   room.IsExpired(),
		Destroyed: room.IsDestroyed(),
		ExpiresAt: &room.ExpiresAt,
	})
}

// extractCreatorToken extracts the creator token from Authorization or X-Room-Creator-Token header
func extractCreatorToken(c *fiber.Ctx) string {
	authHeader := c.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if token != "" {
			return token
		}
	}
	if customHeader := strings.TrimSpace(c.Get("X-Room-Creator-Token")); customHeader != "" {
		return customHeader
	}
	return ""
}

// Mutex to serialize local deletion transactions and prevent driver deadlocks in SQLite test environments
var roomDeletionMu sync.Mutex

// DestroyRoom deletes a room and all its cascades in a deterministic row-locked transaction
func DestroyRoom(c *fiber.Ctx) error {
	code := c.Params("code")
	if code == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Room code is required",
		})
	}

	// 1. Extract creator token from header
	rawToken := extractCreatorToken(c)
	if rawToken == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Creator authorization token required",
		})
	}

	roomDeletionMu.Lock()
	defer roomDeletionMu.Unlock()

	// 2. Begin database transaction
	tx := models.DB.Begin()
	if tx.Error != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}
	defer tx.Rollback()

	// 3. Fetch and lock room row exclusively with SELECT ... FOR UPDATE
	var room models.Room
	err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("room_code = ?", code).
		First(&room).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Room was not found, or was already deleted by a preceding concurrent transaction!
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Room not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	// 4. Verify legacy room status under row lock (fail closed)
	if strings.TrimSpace(room.CreatorTokenHash) == "" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "This room cannot be manually deleted (legacy room or unmanaged)",
		})
	}

	// 5. Verify creator token in constant time under row lock
	presentedHash := sha256.Sum256([]byte(rawToken))
	presentedHex := hex.EncodeToString(presentedHash[:])
	if subtle.ConstantTimeCompare([]byte(presentedHex), []byte(room.CreatorTokenHash)) != 1 {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Invalid creator authorization token",
		})
	}

	// 6. Cascading deletions within transaction
	if err := tx.Where("room_code = ?", code).Delete(&models.RoomFile{}).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete room files",
		})
	}
	if err := tx.Where("room_code = ?", code).Delete(&models.RoomReaction{}).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete room reactions",
		})
	}
	if err := tx.Where("room_code = ?", code).Delete(&models.RoomMessage{}).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete room messages",
		})
	}

	// 7. Hard-delete room record and verify RowsAffected
	delRes := tx.Where("id = ?", room.ID).Delete(&models.Room{})
	if delRes.Error != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete room record",
		})
	}
	if delRes.RowsAffected != 1 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Room no longer available",
		})
	}

	// 8. Commit database transaction
	if err := tx.Commit().Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database commit failed",
		})
	}

	// 9. Post-commit local WebSocket invalidation (generation-safe)
	CloseRoomHubAtomic(room.RoomCode, room.ID, "destroyed")

	// 10. Multi-instance invalidation via LISTEN/NOTIFY (best-effort if PostgreSQL)
	if models.DB != nil && models.DB.Dialector != nil && models.DB.Dialector.Name() == "postgres" {
		payload, _ := json.Marshal(map[string]string{
			"code": room.RoomCode,
			"id":   room.ID.String(),
		})
		models.DB.Exec("NOTIFY bb_room_events, ?", string(payload))
	}

	log.Printf("Room destroyed: %s (id: %s)", code, room.ID)
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Room destroyed successfully",
	})
}

// PurgeExpiredRoomsAt executes a single cleanup cycle, hard-deleting self-destructed messages and expired rooms
func PurgeExpiredRoomsAt(now time.Time) error {
	// 1. Delete messages past their SelfDestructAt (independent of room expiry)
	if err := models.DB.Where("self_destruct_at IS NOT NULL AND self_destruct_at < ?", now).Delete(&models.RoomMessage{}).Error; err != nil {
		log.Printf("Cleanup: failed to delete self-destructed messages: %v", err)
	}

	// 2. Delete self-destructed room files
	CleanupRoomFiles()

	// 3. Hard-delete expired rooms and cascade their remaining messages
	var expiredRooms []models.Room
	if err := models.DB.Where("expires_at < ?", now).Find(&expiredRooms).Error; err != nil {
		log.Printf("Cleanup: failed to query expired rooms: %v", err)
		return err
	}

	for _, room := range expiredRooms {
		err := models.DB.Transaction(func(tx *gorm.DB) error {
			if err := tx.Where("room_code = ?", room.RoomCode).Delete(&models.RoomFile{}).Error; err != nil {
				return err
			}
			if err := tx.Where("room_code = ?", room.RoomCode).Delete(&models.RoomReaction{}).Error; err != nil {
				return err
			}
			if err := tx.Where("room_code = ?", room.RoomCode).Delete(&models.RoomMessage{}).Error; err != nil {
				return err
			}
			if err := tx.Delete(&room).Error; err != nil {
				return err
			}
			return nil
		})

		if err != nil {
			log.Printf("Cleanup: failed to delete expired room %s: %v", room.RoomCode, err)
		} else {
			log.Printf("Cleanup: deleted expired room %s", room.RoomCode)
			CloseRoomHubAtomic(room.RoomCode, room.ID, "expired")
		}
	}
	return nil
}

// CleanupExpiredRooms hard-deletes expired rooms, their messages, files, and self-destructed messages.
// Runs every 60 seconds as a background goroutine started from main.
func CleanupExpiredRooms() {
	for {
		PurgeExpiredRoomsAt(time.Now())
		time.Sleep(1 * time.Minute)
	}
}
