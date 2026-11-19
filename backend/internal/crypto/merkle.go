package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// ProofStep represents one sibling node in a Merkle inclusion proof path.
type ProofStep struct {
	Position string `json:"position"` // "left" or "right"
	Hash     string `json:"hash"`     // 64-character hexadecimal SHA-256 hash
}

// HashLeaf computes an RFC 6962 domain-separated leaf hash: SHA-256(0x00 || data).
func HashLeaf(data []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// HashNode computes an RFC 6962 domain-separated internal node hash: SHA-256(0x01 || left || right).
func HashNode(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// BuildMerkleTree constructs all levels of a binary Merkle tree from raw leaf byte slices.
// Returns the slice of tree levels where level[0] contains the leaf hashes and level[last] contains [Root].
func BuildMerkleTree(leaves [][]byte) [][][32]byte {
	if len(leaves) == 0 {
		return nil
	}

	// Level 0: leaf hashes
	currentLevel := make([][32]byte, len(leaves))
	for i, leaf := range leaves {
		currentLevel[i] = HashLeaf(leaf)
	}

	levels := [][][32]byte{currentLevel}

	// Build upward until single root is reached
	for len(currentLevel) > 1 {
		var nextLevel [][32]byte
		for i := 0; i < len(currentLevel); i += 2 {
			if i+1 < len(currentLevel) {
				parent := HashNode(currentLevel[i], currentLevel[i+1])
				nextLevel = append(nextLevel, parent)
			} else {
				// Odd node is promoted to next level
				nextLevel = append(nextLevel, currentLevel[i])
			}
		}
		levels = append(levels, nextLevel)
		currentLevel = nextLevel
	}

	return levels
}

// ComputeMerkleRoot calculates the root hash of a Merkle tree given a list of raw leaf byte slices.
func ComputeMerkleRoot(leaves [][]byte) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}
	levels := BuildMerkleTree(leaves)
	if len(levels) == 0 || len(levels[len(levels)-1]) == 0 {
		return [32]byte{}
	}
	return levels[len(levels)-1][0]
}

// GenerateInclusionProof generates the sibling hashes required to prove inclusion of leaf at leafIndex.
func GenerateInclusionProof(leaves [][]byte, leafIndex int) ([]ProofStep, [32]byte, error) {
	if len(leaves) == 0 {
		return nil, [32]byte{}, errors.New("empty leaves slice")
	}
	if leafIndex < 0 || leafIndex >= len(leaves) {
		return nil, [32]byte{}, fmt.Errorf("leafIndex %d out of bounds (total leaves: %d)", leafIndex, len(leaves))
	}

	levels := BuildMerkleTree(leaves)
	root := levels[len(levels)-1][0]

	var proof []ProofStep
	currentIndex := leafIndex

	for levelIdx := 0; levelIdx < len(levels)-1; levelIdx++ {
		level := levels[levelIdx]

		if currentIndex%2 == 0 {
			// Even index: sibling is on the right (if it exists)
			if currentIndex+1 < len(level) {
				proof = append(proof, ProofStep{
					Position: "right",
					Hash:     hex.EncodeToString(level[currentIndex+1][:]),
				})
			}
			// If no sibling, node was promoted (no proof step needed for this level)
		} else {
			// Odd index: sibling is on the left
			proof = append(proof, ProofStep{
				Position: "left",
				Hash:     hex.EncodeToString(level[currentIndex-1][:]),
			})
		}

		currentIndex = currentIndex / 2
	}

	return proof, root, nil
}

// VerifyInclusionProof verifies that a given leaf with proof steps recomputes to the expectedRoot.
func VerifyInclusionProof(leafData []byte, proof []ProofStep, expectedRoot [32]byte) bool {
	current := HashLeaf(leafData)

	for _, step := range proof {
		siblingBytes, err := hex.DecodeString(step.Hash)
		if err != nil || len(siblingBytes) != 32 {
			return false
		}
		var sibling [32]byte
		copy(sibling[:], siblingBytes)

		if step.Position == "left" {
			current = HashNode(sibling, current)
		} else if step.Position == "right" {
			current = HashNode(current, sibling)
		} else {
			return false
		}
	}

	return current == expectedRoot
}
