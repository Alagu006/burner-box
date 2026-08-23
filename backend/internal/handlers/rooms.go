package handlers

import (
	"burner-box-backend/internal/crypto"
	"burner-box-backend/internal/models"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
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
	RoomCode string `json:"room_code"`
	JoinURL  string `json:"join_url"`
	ExpiresAt time.Time `json:"expires_at"`
}

type RoomStatusResponse struct {
	Exists    bool       `json:"exists"`
	Expired   bool       `json:"expired"`
	Destroyed bool       `json:"destroyed"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// CreateRoom creates a new ephemeral room (public, no auth)
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
		RoomCode:        roomCode,
		PasswordHash:    passwordHash,
		MaxParticipants: 10,
		ExpiresAt:       time.Now().Add(duration),
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
		RoomCode:  roomCode,
		JoinURL:   joinURL,
		ExpiresAt: room.ExpiresAt,
	})
}

// GetRoomStatus returns whether a room exists without leaking any data
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

// DestroyRoom deletes a room and all its messages in a single transaction
func DestroyRoom(c *fiber.Ctx) error {
	code := c.Params("code")
	if code == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Room code is required",
		})
	}

	var room models.Room
	if err := models.DB.Where("room_code = ?", code).First(&room).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Room not found",
		})
	}

	// Delete room, all messages, and all files in a single transaction
	err := models.DB.Transaction(func(tx *gorm.DB) error {
		// Delete all files for this room
		if err := tx.Where("room_code = ?", code).Delete(&models.RoomFile{}).Error; err != nil {
			return err
		}
		// Delete all reactions for this room
		if err := tx.Where("room_code = ?", code).Delete(&models.RoomReaction{}).Error; err != nil {
			return err
		}
		// Delete all messages for this room
		if err := tx.Where("room_code = ?", code).Delete(&models.RoomMessage{}).Error; err != nil {
			return err
		}
		// Delete the room itself
		if err := tx.Delete(&room).Error; err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		log.Printf("Failed to destroy room %s: %v", code, err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to destroy room",
		})
	}

	log.Printf("Room destroyed: %s", code)
	return c.Status(200).JSON(fiber.Map{
		"message": "Room destroyed successfully",
	})
}

// CleanupExpiredRooms hard-deletes expired rooms, their messages, files, and self-destructed messages.
// Runs every 60 seconds as a background goroutine started from main.
func CleanupExpiredRooms() {
	for {
		now := time.Now()

		// 1. Delete messages past their SelfDestructAt (independent of room expiry)
		if err := models.DB.Where("self_destruct_at IS NOT NULL AND self_destruct_at < ?", now).Delete(&models.RoomMessage{}).Error; err != nil {
			log.Printf("Cleanup: failed to delete self-destructed messages: %v", err)
		}

		// 2. Delete self-destructed room files
		CleanupRoomFiles()

		// 2. Hard-delete expired rooms and cascade their remaining messages
		var expiredRooms []models.Room
		if err := models.DB.Where("expires_at < ?", now).Find(&expiredRooms).Error; err != nil {
			log.Printf("Cleanup: failed to query expired rooms: %v", err)
			time.Sleep(1 * time.Minute)
			continue
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
			}
		}

		time.Sleep(1 * time.Minute)
	}
}
