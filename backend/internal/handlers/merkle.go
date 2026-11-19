package handlers

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"burner-box-backend/internal/crypto"
	"burner-box-backend/internal/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var merkleMutex sync.Mutex

// AddSubmissionToMerkleBatch appends a submission's content hash as a leaf to the organization's open batch.
func AddSubmissionToMerkleBatch(orgID, submissionID uuid.UUID, payloadHashHex string) (*models.MerkleLeaf, *models.MerkleBatch, error) {
	merkleMutex.Lock()
	defer merkleMutex.Unlock()

	var batch models.MerkleBatch
	err := models.DB.Where("organization_id = ? AND status = ?", orgID, "open").First(&batch).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			// Find max batch_number
			var maxBatchNumber int
			models.DB.Model(&models.MerkleBatch{}).
				Where("organization_id = ?", orgID).
				Select("COALESCE(MAX(batch_number), 0)").
				Scan(&maxBatchNumber)

			batch = models.MerkleBatch{
				OrganizationID: orgID,
				BatchNumber:    maxBatchNumber + 1,
				Status:         "open",
				LeafCount:      0,
			}
			if createErr := models.DB.Create(&batch).Error; createErr != nil {
				return nil, nil, fmt.Errorf("failed to create new merkle batch: %w", createErr)
			}
		} else {
			return nil, nil, fmt.Errorf("failed to lookup open merkle batch: %w", err)
		}
	}

	leaf := models.MerkleLeaf{
		BatchID:        batch.ID,
		OrganizationID: orgID,
		SubmissionID:   submissionID,
		LeafIndex:      batch.LeafCount,
		LeafHash:       payloadHashHex,
	}

	if createErr := models.DB.Create(&leaf).Error; createErr != nil {
		return nil, nil, fmt.Errorf("failed to create merkle leaf: %w", createErr)
	}

	batch.LeafCount++
	models.DB.Model(&batch).Update("leaf_count", batch.LeafCount)

	return &leaf, &batch, nil
}

// SealBatch computes the Merkle root of all leaves in the batch, signs it with the server's Ed25519 key, and seals it.
func SealBatch(batchID uuid.UUID) (*models.MerkleBatch, error) {
	merkleMutex.Lock()
	defer merkleMutex.Unlock()

	var batch models.MerkleBatch
	if err := models.DB.Where("id = ?", batchID).First(&batch).Error; err != nil {
		return nil, fmt.Errorf("batch not found: %w", err)
	}

	if batch.Status == "sealed" {
		return &batch, nil
	}

	if batch.LeafCount == 0 {
		return &batch, nil
	}

	var leaves []models.MerkleLeaf
	if err := models.DB.Where("batch_id = ?", batch.ID).Order("leaf_index ASC").Find(&leaves).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch leaves: %w", err)
	}

	rawLeaves := make([][]byte, len(leaves))
	for i, l := range leaves {
		rawLeaves[i] = []byte(l.LeafHash)
	}

	rootBytes := crypto.ComputeMerkleRoot(rawLeaves)
	rootHex := hex.EncodeToString(rootBytes[:])

	var sigBase64, fingerprint string
	sig, _, fp, _, signErr := crypto.GlobalRegistry.Sign([]byte(rootHex))
	if signErr == nil && sig != nil {
		sigBase64 = base64.StdEncoding.EncodeToString(sig)
		fingerprint = fp
	}

	now := time.Now().UTC()
	updates := map[string]interface{}{
		"status":          "sealed",
		"root_hash":       rootHex,
		"signature":       sigBase64,
		"key_fingerprint": fingerprint,
		"sealed_at":       &now,
		"updated_at":      now,
	}

	if err := models.DB.Model(&batch).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("failed to update batch to sealed: %w", err)
	}

	batch.Status = "sealed"
	batch.RootHash = rootHex
	batch.Signature = sigBase64
	batch.KeyFingerprint = fingerprint
	batch.SealedAt = &now

	log.Printf("MERKLE_BATCH_SEALED: org=%s batch_num=%d leaves=%d root=%s",
		batch.OrganizationID, batch.BatchNumber, batch.LeafCount, rootHex)

	return &batch, nil
}

// SealAllOpenBatches finds all open batches with leaves and seals them.
func SealAllOpenBatches() int {
	var openBatches []models.MerkleBatch
	models.DB.Where("status = ? AND leaf_count > 0", "open").Find(&openBatches)

	sealedCount := 0
	for _, b := range openBatches {
		if _, err := SealBatch(b.ID); err == nil {
			sealedCount++
		}
	}
	return sealedCount
}

// StartMerkleBatchSealer starts a background periodic sealer routine.
func StartMerkleBatchSealer(interval time.Duration) {
	ticker := time.NewTicker(interval)
	for range ticker.C {
		sealed := SealAllOpenBatches()
		if sealed > 0 {
			log.Printf("MERKLE_SEALER: Periodic cycle sealed %d batch(es)", sealed)
		}
	}
}

// GetPortalMerkleRoots returns the signed Merkle roots log for an organization portal.
// NO AUTH REQUIRED - publicly readable for independent transparency auditing.
func GetPortalMerkleRoots(c *fiber.Ctx) error {
	slug := c.Params("slug")
	if slug == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Portal slug is required"})
	}

	var org models.Organization
	if err := models.DB.Select("id", "name", "submission_slug").
		Where("submission_slug = ?", slug).First(&org).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Portal not found"})
	}

	var batches []models.MerkleBatch
	models.DB.Where("organization_id = ? AND status = ?", org.ID, "sealed").
		Order("batch_number DESC").
		Limit(100).
		Find(&batches)

	var serverPubKey, fingerprint string
	_, _, activePub, activeFp, _ := crypto.GlobalRegistry.GetActiveKey()
	if activePub != nil {
		serverPubKey = base64.StdEncoding.EncodeToString(activePub)
		fingerprint = activeFp
	}

	rootsList := make([]fiber.Map, len(batches))
	for i, b := range batches {
		var sealedAtStr string
		if b.SealedAt != nil {
			sealedAtStr = b.SealedAt.Format(time.RFC3339)
		}
		rootsList[i] = fiber.Map{
			"batch_id":        b.ID,
			"batch_number":    b.BatchNumber,
			"root_hash":       b.RootHash,
			"signature":       b.Signature,
			"key_fingerprint": b.KeyFingerprint,
			"leaf_count":      b.LeafCount,
			"sealed_at":       sealedAtStr,
			"created_at":      b.CreatedAt.Format(time.RFC3339),
		}
	}

	return c.JSON(fiber.Map{
		"organization_name": org.Name,
		"slug":              org.SubmissionSlug,
		"server_public_key": serverPubKey,
		"key_fingerprint":   fingerprint,
		"total_sealed":      len(batches),
		"roots":             rootsList,
	})
}

// GetSubmissionInclusionProof returns the Merkle inclusion proof for a submission.
// NO AUTH REQUIRED - allows submitters to independently verify receipt inclusion against sealed roots.
func GetSubmissionInclusionProof(c *fiber.Ctx) error {
	submissionIDStr := c.Params("id")
	if submissionIDStr == "" {
		submissionIDStr = c.Query("submission_id")
	}

	if submissionIDStr == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "submission_id is required",
		})
	}

	subUUID, err := uuid.Parse(submissionIDStr)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid submission_id format",
		})
	}

	var leaf models.MerkleLeaf
	if err := models.DB.Where("submission_id = ?", subUUID).First(&leaf).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "No Merkle leaf found for this submission ID",
		})
	}

	var batch models.MerkleBatch
	if err := models.DB.Where("id = ?", leaf.BatchID).First(&batch).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to load Merkle batch for submission",
		})
	}

	var serverPubKey, fingerprint string
	if batch.KeyFingerprint != "" {
		if vk, _ := crypto.GlobalRegistry.LookupKey(batch.KeyFingerprint); vk != nil && vk.PublicKeyB64 != "" {
			serverPubKey = vk.PublicKeyB64
			fingerprint = vk.Fingerprint
		}
	}
	if serverPubKey == "" {
		_, _, activePub, activeFp, _ := crypto.GlobalRegistry.GetActiveKey()
		if activePub != nil {
			serverPubKey = base64.StdEncoding.EncodeToString(activePub)
			fingerprint = activeFp
		}
	}

	if batch.Status != "sealed" {
		return c.JSON(fiber.Map{
			"status":            "pending_batch",
			"submission_id":     leaf.SubmissionID,
			"batch_id":          batch.ID,
			"batch_number":      batch.BatchNumber,
			"leaf_index":        leaf.LeafIndex,
			"leaf_hash":         leaf.LeafHash,
			"batch_status":      "open",
			"server_public_key": serverPubKey,
			"key_fingerprint":   fingerprint,
			"message":           "Submission is queued in open batch and will be sealed in the next batch cycle.",
		})
	}

	// Fetch all leaves in batch in deterministic order
	var leaves []models.MerkleLeaf
	if err := models.DB.Where("batch_id = ?", batch.ID).Order("leaf_index ASC").Find(&leaves).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to load leaves for inclusion proof generation",
		})
	}

	rawLeaves := make([][]byte, len(leaves))
	for i, l := range leaves {
		rawLeaves[i] = []byte(l.LeafHash)
	}

	proofSteps, computedRoot, proofErr := crypto.GenerateInclusionProof(rawLeaves, leaf.LeafIndex)
	if proofErr != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to generate inclusion proof: %v", proofErr),
		})
	}

	var sealedAtStr string
	if batch.SealedAt != nil {
		sealedAtStr = batch.SealedAt.Format(time.RFC3339)
	}

	return c.JSON(fiber.Map{
		"status":            "sealed",
		"submission_id":     leaf.SubmissionID,
		"batch_id":          batch.ID,
		"batch_number":      batch.BatchNumber,
		"leaf_index":        leaf.LeafIndex,
		"leaf_hash":         leaf.LeafHash,
		"batch_status":      "sealed",
		"total_leaves":      batch.LeafCount,
		"root_hash":         batch.RootHash,
		"computed_root":     hex.EncodeToString(computedRoot[:]),
		"root_signature":    batch.Signature,
		"key_fingerprint":   batch.KeyFingerprint,
		"server_public_key": serverPubKey,
		"sealed_at":         sealedAtStr,
		"inclusion_proof":   proofSteps,
	})
}
