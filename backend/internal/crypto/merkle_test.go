package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestMerkleTree_SingleLeaf(t *testing.T) {
	leaf := []byte("submission-hash-1")
	leaves := [][]byte{leaf}

	root := ComputeMerkleRoot(leaves)
	expectedLeafHash := HashLeaf(leaf)

	if root != expectedLeafHash {
		t.Fatalf("Single leaf root mismatch: got %x, expected %x", root, expectedLeafHash)
	}

	proof, proofRoot, err := GenerateInclusionProof(leaves, 0)
	if err != nil {
		t.Fatalf("Failed to generate inclusion proof: %v", err)
	}
	if proofRoot != root {
		t.Fatalf("Proof root %x != compute root %x", proofRoot, root)
	}
	if len(proof) != 0 {
		t.Fatalf("Expected 0 proof steps for single leaf, got %d", len(proof))
	}

	if !VerifyInclusionProof(leaf, proof, root) {
		t.Fatalf("VerifyInclusionProof failed for single leaf")
	}
}

func TestMerkleTree_MultipleLeaves(t *testing.T) {
	testCounts := []int{2, 3, 4, 5, 7, 8, 15, 16, 31, 32}

	for _, count := range testCounts {
		t.Run(fmt.Sprintf("%d_leaves", count), func(t *testing.T) {
			leaves := make([][]byte, count)
			for i := 0; i < count; i++ {
				h := sha256.Sum256([]byte(fmt.Sprintf("encrypted-payload-submission-%d", i)))
				leaves[i] = []byte(hex.EncodeToString(h[:]))
			}

			root := ComputeMerkleRoot(leaves)
			if root == [32]byte{} {
				t.Fatalf("Root should not be empty")
			}

			// Test inclusion proof for each leaf in tree
			for i := 0; i < count; i++ {
				proof, proofRoot, err := GenerateInclusionProof(leaves, i)
				if err != nil {
					t.Fatalf("Failed to generate proof for leaf %d: %v", i, err)
				}
				if proofRoot != root {
					t.Fatalf("Proof root %x does not match tree root %x for leaf %d", proofRoot, root, i)
				}

				// Verify positive case
				if !VerifyInclusionProof(leaves[i], proof, root) {
					t.Fatalf("Failed to verify valid inclusion proof for leaf %d (tree size %d)", i, count)
				}

				// Verify negative case: altered leaf
				tamperedLeaf := []byte("tampered-data-content")
				if VerifyInclusionProof(tamperedLeaf, proof, root) {
					t.Fatalf("Inclusion proof passed for tampered leaf %d", i)
				}

				// Verify negative case: altered sibling step (if any steps exist)
				if len(proof) > 0 {
					tamperedProof := make([]ProofStep, len(proof))
					copy(tamperedProof, proof)
					tamperedProof[0].Hash = "0000000000000000000000000000000000000000000000000000000000000000"
					if VerifyInclusionProof(leaves[i], tamperedProof, root) {
						t.Fatalf("Inclusion proof passed with corrupted sibling hash")
					}
				}
			}
		})
	}
}

func TestMerkleTree_OutOfBounds(t *testing.T) {
	leaves := [][]byte{[]byte("leaf-1"), []byte("leaf-2")}
	_, _, err := GenerateInclusionProof(leaves, 2)
	if err == nil {
		t.Fatalf("Expected error for out of bounds leafIndex")
	}
	_, _, err = GenerateInclusionProof(leaves, -1)
	if err == nil {
		t.Fatalf("Expected error for negative leafIndex")
	}
}
