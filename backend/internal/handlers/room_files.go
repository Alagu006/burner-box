package handlers

import (
	"burner-box-backend/internal/models"
	"io"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
)

const (
	maxRoomFileSize    = 10 << 20 // 10 MB
	maxRoomFileCount   = 50       // per room
	roomFileMimeLength = 127
)

// UploadRoomFile handles encrypted file upload to a room via multipart form.
// The file is already encrypted client-side with the room's shared symmetric key.
func UploadRoomFile(c *fiber.Ctx) error {
	code := c.Params("code")
	if code == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Room code required"})
	}

	// Verify room exists and is alive
	var room models.Room
	if err := models.DB.Where("room_code = ?", code).First(&room).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Room not found"})
	}
	if room.IsExpired() || room.IsDestroyed() {
		return c.Status(410).JSON(fiber.Map{"error": "Room is no longer available"})
	}

	// Check file count limit
	var count int64
	models.DB.Model(&models.RoomFile{}).Where("room_code = ?", code).Count(&count)
	if count >= int64(maxRoomFileCount) {
		return c.Status(400).JSON(fiber.Map{"error": "Room file limit reached"})
	}

	// Read encrypted file from multipart form
	fileHeader, err := c.FormFile("file")
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "File required"})
	}
	if fileHeader.Size > maxRoomFileSize {
		return c.Status(400).JSON(fiber.Map{"error": "File too large (max 10 MB)"})
	}

	src, err := fileHeader.Open()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to read file"})
	}
	defer src.Close()

	encryptedData, err := io.ReadAll(src)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to read file"})
	}

	senderTag := c.FormValue("sender_tag")
	if senderTag == "" {
		senderTag = "unknown"
	}
	originalName := fileHeader.Filename
	mimeType := fileHeader.Header.Get("Content-Type")
	if len(mimeType) > roomFileMimeLength {
		mimeType = mimeType[:roomFileMimeLength]
	}
	encryptionMeta := c.FormValue("encryption_meta")

	// Parse optional self-destruct time
	var selfDestructAt *time.Time
	if sdStr := c.FormValue("self_destruct_at"); sdStr != "" {
		if t, err := time.Parse(time.RFC3339, sdStr); err == nil {
			selfDestructAt = &t
		}
	}

	roomFile := models.RoomFile{
		RoomCode:       code,
		SenderTag:      senderTag,
		OriginalName:   originalName,
		MimeType:       mimeType,
		FileSize:       fileHeader.Size,
		EncryptedData:  encryptedData,
		EncryptionMeta: encryptionMeta,
		SelfDestructAt: selfDestructAt,
	}

	if err := models.DB.Create(&roomFile).Error; err != nil {
		log.Printf("Room %s: failed to persist file: %v", code, err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to store file"})
	}

	log.Printf("ROOM_FILE_UPLOAD: room=%s file=%s size=%d", code, roomFile.ID.String(), fileHeader.Size)

	return c.Status(201).JSON(fiber.Map{
		"file_id":      roomFile.ID.String(),
		"original_name": originalName,
		"mime_type":    mimeType,
		"file_size":    fileHeader.Size,
		"sender_tag":   senderTag,
		"created_at":   roomFile.CreatedAt.Format(time.RFC3339),
	})
}

// DownloadRoomFile returns the encrypted file blob.
// The client decrypts with the room's shared symmetric key.
func DownloadRoomFile(c *fiber.Ctx) error {
	code := c.Params("code")
	fileID := c.Params("file_id")
	if code == "" || fileID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Room code and file ID required"})
	}

	// Verify room exists and is alive
	var room models.Room
	if err := models.DB.Where("room_code = ?", code).First(&room).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Room not found"})
	}
	if room.IsExpired() || room.IsDestroyed() {
		return c.Status(410).JSON(fiber.Map{"error": "Room is no longer available"})
	}

	var roomFile models.RoomFile
	if err := models.DB.Where("id = ? AND room_code = ?", fileID, code).First(&roomFile).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "File not found"})
	}

	// Check if self-destructed
	if roomFile.SelfDestructAt != nil && time.Now().After(*roomFile.SelfDestructAt) {
		// Hard-delete and return 410
		models.DB.Delete(&roomFile)
		return c.Status(410).JSON(fiber.Map{"error": "File has self-destructed"})
	}

	c.Set("Content-Type", "application/octet-stream")
	c.Set("Content-Disposition", "attachment; filename=\"encrypted\"")
	c.Set("X-File-Meta", roomFile.EncryptionMeta)
	c.Set("X-Original-Name", roomFile.OriginalName)
	c.Set("X-Mime-Type", roomFile.MimeType)
	c.Set("X-Sender-Tag", roomFile.SenderTag)

	return c.Send(roomFile.EncryptedData)
}

// CleanupRoomFiles removes self-destructed and expired room files.
// Called from CleanupExpiredRooms.
func CleanupRoomFiles() {
	now := time.Now()

	// Delete self-destructed files
	if err := models.DB.Where("self_destruct_at IS NOT NULL AND self_destruct_at < ?", now).Delete(&models.RoomFile{}).Error; err != nil {
		log.Printf("Cleanup: failed to delete self-destructed room files: %v", err)
	}

	// Delete files belonging to expired rooms
	if err := models.DB.Where("room_code IN (SELECT room_code FROM rooms WHERE expires_at < ?)", now).Delete(&models.RoomFile{}).Error; err != nil {
		log.Printf("Cleanup: failed to delete expired room files: %v", err)
	}
}
