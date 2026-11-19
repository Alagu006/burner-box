package handlers

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"burner-box-backend/internal/crypto"
	"burner-box-backend/internal/models"

	"github.com/google/uuid"
)

func TestMerkleBatch_FullLifecycleAndAPI(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()

	// Register routes
	submit := app.Group("/api/v1/submit")
	submit.Get("/:slug/merkle-roots", GetPortalMerkleRoots)
	submit.Get("/:slug/proof/:id", GetSubmissionInclusionProof)

	portal := app.Group("/api/v1/portal")
	portal.Get("/:slug/merkle-roots", GetPortalMerkleRoots)

	// Create test organization
	org := models.Organization{
		ID:             uuid.New(),
		Name:           "Investigative Desk",
		Email:          "desk@investigative.test",
		SubmissionSlug: "investigative-desk-merkle",
		PublicKey:      "dummy-public-key",
	}
	models.DB.Create(&org)

	// 1. Simulate 5 submissions
	submissionCount := 5
	subIDs := make([]uuid.UUID, submissionCount)
	payloadHashes := make([]string, submissionCount)

	for i := 0; i < submissionCount; i++ {
		subID := uuid.New()
		subIDs[i] = subID

		h := sha256.Sum256([]byte(fmt.Sprintf("ciphertext-data-submission-%d", i)))
		hHex := hex.EncodeToString(h[:])
		payloadHashes[i] = hHex

		leaf, batch, err := AddSubmissionToMerkleBatch(org.ID, subID, hHex)
		if err != nil {
			t.Fatalf("Failed to add submission %d to batch: %v", i, err)
		}

		if leaf.LeafIndex != i {
			t.Errorf("Expected leaf_index %d, got %d", i, leaf.LeafIndex)
		}
		if batch.Status != "open" {
			t.Errorf("Expected batch status 'open', got %s", batch.Status)
		}
		if batch.LeafCount != i+1 {
			t.Errorf("Expected batch leaf_count %d, got %d", i+1, batch.LeafCount)
		}
	}

	// 2. Query inclusion proof while batch is still open -> should be pending_batch
	reqPending := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/submit/investigative-desk-merkle/proof/%s", subIDs[0]), nil)
	respPending, err := app.Test(reqPending, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if respPending.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for pending proof, got %d", respPending.StatusCode)
	}

	var pendingData map[string]interface{}
	json.NewDecoder(respPending.Body).Decode(&pendingData)
	if pendingData["status"] != "pending_batch" {
		t.Fatalf("Expected status 'pending_batch', got %v", pendingData["status"])
	}

	// 3. Seal the batch
	var openBatch models.MerkleBatch
	models.DB.Where("organization_id = ? AND status = ?", org.ID, "open").First(&openBatch)
	sealedBatch, err := SealBatch(openBatch.ID)
	if err != nil {
		t.Fatalf("Failed to seal batch: %v", err)
	}
	if sealedBatch.Status != "sealed" {
		t.Fatalf("Expected status 'sealed', got %s", sealedBatch.Status)
	}
	if sealedBatch.RootHash == "" {
		t.Fatalf("Root hash should not be empty")
	}
	if sealedBatch.Signature == "" {
		t.Fatalf("Root signature should not be empty")
	}

	// Verify Ed25519 signature of root
	sigBytes, _ := base64.StdEncoding.DecodeString(sealedBatch.Signature)
	if !ed25519.Verify(proofPublicKey, []byte(sealedBatch.RootHash), sigBytes) {
		t.Fatalf("Ed25519 signature on root hash is invalid")
	}

	// 4. Test GET /api/v1/portal/:slug/merkle-roots
	reqRoots := httptest.NewRequest(http.MethodGet, "/api/v1/portal/investigative-desk-merkle/merkle-roots", nil)
	respRoots, _ := app.Test(reqRoots, 5000)
	if respRoots.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK on portal merkle roots, got %d", respRoots.StatusCode)
	}

	var rootsData struct {
		OrganizationName string `json:"organization_name"`
		TotalSealed      int    `json:"total_sealed"`
		Roots            []struct {
			BatchID   string `json:"batch_id"`
			RootHash  string `json:"root_hash"`
			Signature string `json:"signature"`
			LeafCount int    `json:"leaf_count"`
		} `json:"roots"`
	}
	json.NewDecoder(respRoots.Body).Decode(&rootsData)
	if rootsData.TotalSealed != 1 || len(rootsData.Roots) != 1 {
		t.Fatalf("Expected 1 sealed root, got %d", rootsData.TotalSealed)
	}
	if rootsData.Roots[0].RootHash != sealedBatch.RootHash {
		t.Fatalf("Root hash mismatch in public endpoint")
	}

	// 5. Test GET /api/v1/submit/:slug/proof/:id for every submission in the sealed batch
	for i := 0; i < submissionCount; i++ {
		reqProof := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/submit/investigative-desk-merkle/proof/%s", subIDs[i]), nil)
		respProof, _ := app.Test(reqProof, 5000)
		if respProof.StatusCode != http.StatusOK {
			t.Fatalf("Expected 200 OK for inclusion proof of sub %d, got %d", i, respProof.StatusCode)
		}

		var proofData struct {
			Status         string             `json:"status"`
			SubmissionID   string             `json:"submission_id"`
			LeafIndex      int                `json:"leaf_index"`
			LeafHash       string             `json:"leaf_hash"`
			RootHash       string             `json:"root_hash"`
			RootSignature  string             `json:"root_signature"`
			InclusionProof []crypto.ProofStep `json:"inclusion_proof"`
		}
		json.NewDecoder(respProof.Body).Decode(&proofData)

		if proofData.Status != "sealed" {
			t.Fatalf("Expected status 'sealed' for sub %d, got %s", i, proofData.Status)
		}
		if proofData.LeafHash != payloadHashes[i] {
			t.Fatalf("Leaf hash mismatch for sub %d", i)
		}

		// Recompute Merkle root from leaf and inclusion proof
		expectedRootBytes, _ := hex.DecodeString(proofData.RootHash)
		var expectedRoot [32]byte
		copy(expectedRoot[:], expectedRootBytes)

		if !crypto.VerifyInclusionProof([]byte(proofData.LeafHash), proofData.InclusionProof, expectedRoot) {
			t.Fatalf("Merkle inclusion proof verification failed for submission %d", i)
		}
	}
}
