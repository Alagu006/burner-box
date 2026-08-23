package handlers

import (
	"bytes"
	"fmt"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"burner-box-backend/internal/config"
	"burner-box-backend/internal/crypto"
	"burner-box-backend/internal/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

const (
	MaxFileSize  = 10 * 1024 * 1024 // 10MB max per file
	AllowedTypes = ".jpg,.jpeg,.png,.gif,.pdf,.txt,.doc,.docx,.mp4,.mp3,.zip"

	// Input length limits — enforced server-side to prevent abuse and
	// keep the database reasonable.
	MaxMessageLength      = 50000 // plaintext message_text
	MaxEncryptedLength    = 50000 // encrypted_message (base64 ciphertext)
	MaxEncryptionMetaLen  = 50000 // encryption_meta JSON blob
	MaxReplyPublicKeysLen = 10000 // reply_public_key (NaCl box public key)
	MaxNoteLength         = 50000 // internal notes
	MaxReplyMessageLen    = 50000 // reply message_text
	MaxNameLength         = 255   // org name
	MaxEmailLength        = 255   // email
)

// mimeToExt maps MIME types detected by http.DetectContentType to canonical extensions
var mimeToExt = map[string]string{
	"image/jpeg":  ".jpeg",
	"image/png":   ".png",
	"image/gif":   ".gif",
	"application/pdf": ".pdf",
	"text/plain":      ".txt",
	"application/msword":          ".doc",
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
	"video/mp4":   ".mp4",
	"audio/mpeg":  ".mp3",
	"application/zip": ".zip",
}

type FileUploadResponse struct {
	FileID   string `json:"file_id"`
	FileName string `json:"file_name"`
	FileSize int64  `json:"file_size"`
	MimeType string `json:"mime_type"`
}

// validateFileType reads the first 512 bytes of raw, sniffs the content type
// via http.DetectContentType, and returns an error if the detected type does
// not match the claimed file extension.
func validateFileType(raw []byte, ext string) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("empty file")
	}

	detected := http.DetectContentType(raw[:min(512, len(raw))])
	detected = strings.ToLower(detected)
	// Strip parameters like "; charset=utf-8"
	if idx := strings.IndexByte(detected, ';'); idx >= 0 {
		detected = strings.TrimSpace(detected[:idx])
	}

	expectedExt, ok := mimeToExt[detected]
	if !ok {
		return "", fmt.Errorf("unrecognised file content type %q", detected)
	}

	// Normalize extension for comparison
	normExt := strings.ToLower(ext)
	if normExt == ".jpg" {
		normExt = ".jpeg"
	}
	if expectedExt == ".jpg" {
		expectedExt = ".jpeg"
	}

	if normExt != expectedExt {
		return "", fmt.Errorf("file content type %q does not match extension %s", detected, ext)
	}

	return detected, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// stripImageMetadata re-encodes an image to strip EXIF, GPS, device info,
// and any other embedded metadata.  This is a privacy-critical step for a
// whistleblowing platform — re-encoding is the only reliable way to remove
// ALL metadata.
//
// Supported formats: JPEG, PNG, GIF.
// Trade-offs: JPEG quality is preserved at 95; GIF animation is lost;
// PNG ancillary chunks (including EXIF-if-present) are dropped.
func stripImageMetadata(data []byte, mimeType string) ([]byte, error) {
	var img image.Image
	var err error

	reader := bytes.NewReader(data)

	switch mimeType {
	case "image/jpeg":
		img, err = jpeg.Decode(reader)
	case "image/png":
		img, err = png.Decode(reader)
	case "image/gif":
		img, err = gif.Decode(reader)
	default:
		return data, nil
	}

	if err != nil {
		return data, fmt.Errorf("decode for metadata stripping: %w", err)
	}

	var buf bytes.Buffer
	switch mimeType {
	case "image/jpeg":
		err = jpeg.Encode(&buf, img, &jpeg.Options{Quality: 95})
	case "image/png":
		err = png.Encode(&buf, img)
	case "image/gif":
		err = gif.Encode(&buf, img, nil)
	}
	if err != nil {
		return data, fmt.Errorf("re-encode for metadata stripping: %w", err)
	}

	return buf.Bytes(), nil
}

// processAndEncryptFile reads the uploaded file, validates its type via magic
// bytes, strips image metadata if applicable, encrypts with a server-held key,
// and writes the result to disk.  Returns the storage key, the DB-level
// file-encryption nonce, and any error.
func processAndEncryptFile(submissionID string, file *multipart.FileHeader, ext string) (storageKey, fileEncryptionKey string, err error) {
	src, err := file.Open()
	if err != nil {
		return "", "", fmt.Errorf("open uploaded file: %w", err)
	}
	defer src.Close()

	raw := make([]byte, file.Size)
	n, readErr := src.Read(raw)
	if readErr != nil && int64(n) != file.Size {
		return "", "", fmt.Errorf("read uploaded file: %w", readErr)
	}
	raw = raw[:n]

	// 1) Magic-byte validation
	mimeType, valErr := validateFileType(raw, ext)
	if valErr != nil {
		return "", "", fmt.Errorf("file type validation: %w", valErr)
	}

	// 2) Strip image metadata for privacy-critical formats
	switch mimeType {
	case "image/jpeg", "image/png", "image/gif":
		stripped, stripErr := stripImageMetadata(raw, mimeType)
		if stripErr != nil {
			log.Printf("metadata stripping failed for submission %s: %v (saving original)", submissionID, stripErr)
		} else {
			raw = stripped
		}
	}

	// 3) Server-side AES-256-GCM encryption
	cfg := config.AppConfig
	nonce, ciphertext, encErr := crypto.EncryptFile(cfg.FileEncryptionKey, raw)
	if encErr != nil {
		return "", "", fmt.Errorf("encrypt file: %w", encErr)
	}

	// Write encrypted file to disk
	storageKey = fmt.Sprintf("submissions/%s/%s-%s%s",
		submissionID,
		uuid.New().String(),
		time.Now().Format("20060102-150405"),
		ext,
	)

	uploadDir := filepath.Join("uploads", "submissions", submissionID)
	if mkdirErr := os.MkdirAll(uploadDir, 0755); mkdirErr != nil {
		return "", "", fmt.Errorf("create upload directory: %w", mkdirErr)
	}

	fullPath := filepath.Join("uploads", storageKey)
	if writeErr := os.WriteFile(fullPath, ciphertext, 0644); writeErr != nil {
		return "", "", fmt.Errorf("write encrypted file: %w", writeErr)
	}

	return storageKey, nonce, nil
}

// UploadSubmissionFile handles file upload for a submission (org side)
// AUTH REQUIRED - organization team members only
func UploadSubmissionFile(c *fiber.Ctx) error {
	submissionID := c.Params("id")
	orgID := c.Locals("orgID").(string)

	// Verify submission belongs to this org
	var submission models.Submission
	if err := models.DB.Where("id = ? AND organization_id = ?", submissionID, orgID).
		First(&submission).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Submission not found",
		})
	}

	// Parse uploaded file
	file, err := c.FormFile("file")
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "No file uploaded. Use form field name 'file'.",
		})
	}

	// Validate file size
	if file.Size > MaxFileSize {
		return c.Status(400).JSON(fiber.Map{
			"error": fmt.Sprintf("File too large. Max size: %d MB", MaxFileSize/(1024*1024)),
		})
	}

	// Validate file type by extension
	ext := strings.ToLower(filepath.Ext(file.Filename))
	if !strings.Contains(AllowedTypes, ext) {
		return c.Status(400).JSON(fiber.Map{
			"error": "File type not allowed. Allowed types: " + AllowedTypes,
		})
	}

	// Process: validate magic bytes, strip image metadata, encrypt, write to disk
	storageKey, fileEncKey, procErr := processAndEncryptFile(submissionID, file, ext)
	if procErr != nil {
		log.Printf("processAndEncryptFile failed: %v", procErr)
		return c.Status(400).JSON(fiber.Map{
			"error": "File processing failed",
		})
	}

	// Detect the MIME type from the file on disk for the DB record
	fullPath := filepath.Join("uploads", storageKey)
	rawForMime, _ := os.ReadFile(fullPath)
	detectedMIME := http.DetectContentType(rawForMime)
	if idx := strings.IndexByte(detectedMIME, ';'); idx >= 0 {
		detectedMIME = strings.TrimSpace(detectedMIME[:idx])
	}

	// Accept client-side E2EE metadata (optional form field).
	// When present, the file was encrypted in the browser before upload;
	// the server stores it as-is and returns it on download so the client
	// can perform the second decryption layer.
	clientEncMeta := c.FormValue("client_encryption_meta")

	// Create file record in database
	submissionFile := models.SubmissionFile{
		SubmissionID:      submission.ID,
		FileName:          file.Filename,
		FileSize:          file.Size,
		StorageKey:        storageKey,
		MimeType:          detectedMIME,
		FileEncryptionKey: fileEncKey,
		EncryptionMeta:    clientEncMeta,
	}

	if err := models.DB.Create(&submissionFile).Error; err != nil {
		log.Printf("Failed to save file metadata: %v", err)
		os.Remove(fullPath)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to save file metadata",
		})
	}

	// Update submission file count
	fileCount := len(GetSubmissionFilesHelper(submission.ID))
	models.DB.Model(&submission).Updates(map[string]interface{}{
		"has_files":  true,
		"file_count": fileCount,
	})

	return c.Status(201).JSON(fiber.Map{
		"message": "File uploaded successfully",
		"file": FileUploadResponse{
			FileID:   submissionFile.ID.String(),
			FileName: submissionFile.FileName,
			FileSize: submissionFile.FileSize,
			MimeType: submissionFile.MimeType,
		},
	})
}

// GetSubmissionFiles returns all files for a submission
// AUTH REQUIRED - organization team members only
func GetSubmissionFiles(c *fiber.Ctx) error {
	submissionID := c.Params("id")
	orgID := c.Locals("orgID").(string)

	// Verify submission belongs to org
	var submission models.Submission
	if err := models.DB.Where("id = ? AND organization_id = ?", submissionID, orgID).
		First(&submission).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Submission not found",
		})
	}

	files := GetSubmissionFilesHelper(submission.ID)

	return c.JSON(fiber.Map{
		"files": files,
		"count": len(files),
	})
}

// DownloadSubmissionFile downloads a specific file, decrypting it if it was
// server-encrypted.  AUTH REQUIRED - organization team members only.
func DownloadSubmissionFile(c *fiber.Ctx) error {
	submissionID := c.Params("id")
	fileID := c.Params("fileId")
	orgID := c.Locals("orgID").(string)

	// Verify submission belongs to org
	var submission models.Submission
	if err := models.DB.Where("id = ? AND organization_id = ?", submissionID, orgID).
		First(&submission).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Submission not found",
		})
	}

	// Find file
	var file models.SubmissionFile
	if err := models.DB.Where("id = ? AND submission_id = ?", fileID, submission.ID).
		First(&file).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "File not found",
		})
	}

	// Read encrypted file from disk
	fullPath := filepath.Join("uploads", file.StorageKey)
	ciphertext, err := os.ReadFile(fullPath)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "File not found on server",
		})
	}

	// Decrypt if the file was server-encrypted
	var plaintext []byte
	if file.FileEncryptionKey != "" {
		cfg := config.AppConfig
		decrypted, decErr := crypto.DecryptFile(cfg.FileEncryptionKey, file.FileEncryptionKey, ciphertext)
		if decErr != nil {
			log.Printf("Failed to decrypt file %s: %v", file.StorageKey, decErr)
			return c.Status(500).JSON(fiber.Map{
				"error": "Failed to decrypt file",
			})
		}
		plaintext = decrypted
	} else {
		// Legacy unencrypted file
		plaintext = ciphertext
	}

	// Serve the decrypted content
	c.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, file.FileName))
	if file.MimeType != "" {
		c.Set("Content-Type", file.MimeType)
	}
	// Return client-side E2EE metadata so the browser can perform
	// the second decryption layer. Empty string means no client encryption.
	c.Set("X-Client-Encryption-Meta", file.EncryptionMeta)
	return c.Send(plaintext)
}

// DeleteSubmissionFile deletes a file from a submission
// AUTH REQUIRED - organization team members only (admin role)
func DeleteSubmissionFile(c *fiber.Ctx) error {
	submissionID := c.Params("id")
	fileID := c.Params("fileId")
	orgID := c.Locals("orgID").(string)

	// Verify submission belongs to org
	var submission models.Submission
	if err := models.DB.Where("id = ? AND organization_id = ?", submissionID, orgID).
		First(&submission).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Submission not found",
		})
	}

	// Find file
	var file models.SubmissionFile
	if err := models.DB.Where("id = ? AND submission_id = ?", fileID, submission.ID).
		First(&file).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "File not found",
		})
	}

	// Delete from disk
	fullPath := filepath.Join("uploads", file.StorageKey)
	if err := os.Remove(fullPath); err != nil {
		log.Printf("Failed to delete file from disk: %v", err)
	}

	// Delete from database
	if err := models.DB.Delete(&file).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to delete file record",
		})
	}

	// Update submission file count
	fileCount := len(GetSubmissionFilesHelper(submission.ID))
	hasFiles := fileCount > 0
	models.DB.Model(&submission).Updates(map[string]interface{}{
		"has_files":  hasFiles,
		"file_count": fileCount,
	})

	return c.JSON(fiber.Map{
		"message": "File deleted successfully",
	})
}

// GetSubmissionFilesHelper returns files for a submission ID
// Helper function used by multiple handlers
func GetSubmissionFilesHelper(submissionID uuid.UUID) []models.SubmissionFile {
	var files []models.SubmissionFile
	models.DB.Where("submission_id = ?", submissionID).Find(&files)
	return files
}
