package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// MerkleProof contains the audit path proving a chunk's membership in the Merkle Manifest Tree.
type MerkleProof struct {
	LeafIndex int      `json:"leaf_index"`
	Siblings  [][]byte `json:"siblings"` // Sibling hashes up to root
	PathBits  []bool   `json:"path_bits"` // false = left sibling, true = right sibling
}

// MerkleTree stores the complete binary hash tree over chunk CIDs.
type MerkleTree struct {
	Leaves [][]byte
	Levels [][][]byte
	Root   []byte
}

// hashNodes computes H(left || right)
func hashNodes(left, right []byte) []byte {
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// NewMerkleTree builds a balanced Merkle tree over the provided chunk hashes.
func NewMerkleTree(leaves [][]byte) (*MerkleTree, error) {
	if len(leaves) == 0 {
		return nil, errors.New("cannot create merkle tree from empty leaves")
	}

	// Clone leaves
	currentLevel := make([][]byte, len(leaves))
	for i, l := range leaves {
		leafCopy := make([]byte, len(l))
		copy(leafCopy, l)
		currentLevel[i] = leafCopy
	}

	var levels [][][]byte
	levels = append(levels, currentLevel)

	for len(currentLevel) > 1 {
		var nextLevel [][]byte
		for i := 0; i < len(currentLevel); i += 2 {
			if i+1 < len(currentLevel) {
				parent := hashNodes(currentLevel[i], currentLevel[i+1])
				nextLevel = append(nextLevel, parent)
			} else {
				// Odd node: duplicate or promote
				parent := hashNodes(currentLevel[i], currentLevel[i])
				nextLevel = append(nextLevel, parent)
			}
		}
		levels = append(levels, nextLevel)
		currentLevel = nextLevel
	}

	return &MerkleTree{
		Leaves: leaves,
		Levels: levels,
		Root:   levels[len(levels)-1][0],
	}, nil
}

// RootHex returns the hex-encoded root hash.
func (mt *MerkleTree) RootHex() string {
	return hex.EncodeToString(mt.Root)
}

// GenerateProof creates a compact cryptographic inclusion proof for leaf at index.
func (mt *MerkleTree) GenerateProof(index int) (*MerkleProof, error) {
	if index < 0 || index >= len(mt.Leaves) {
		return nil, fmt.Errorf("leaf index %d out of bounds (total leaves: %d)", index, len(mt.Leaves))
	}

	var siblings [][]byte
	var pathBits []bool

	currIdx := index
	for l := 0; l < len(mt.Levels)-1; l++ {
		level := mt.Levels[l]
		var sibling []byte
		var isRight bool

		if currIdx%2 == 0 {
			// Current is left node, sibling is right
			if currIdx+1 < len(level) {
				sibling = level[currIdx+1]
			} else {
				sibling = level[currIdx]
			}
			isRight = false
		} else {
			// Current is right node, sibling is left
			sibling = level[currIdx-1]
			isRight = true
		}

		siblings = append(siblings, sibling)
		pathBits = append(pathBits, isRight)
		currIdx /= 2
	}

	return &MerkleProof{
		LeafIndex: index,
		Siblings:  siblings,
		PathBits:  pathBits,
	}, nil
}

// VerifyMerkleProof verifies that leaf belongs to a tree with rootHash using proof.
func VerifyMerkleProof(leaf []byte, proof *MerkleProof, rootHash []byte) bool {
	if proof == nil || len(proof.Siblings) != len(proof.PathBits) {
		return false
	}

	current := leaf
	for i := 0; i < len(proof.Siblings); i++ {
		sibling := proof.Siblings[i]
		isRight := proof.PathBits[i]

		if isRight {
			// Current was right child, sibling was on the left
			current = hashNodes(sibling, current)
		} else {
			// Current was left child, sibling was on the right
			current = hashNodes(current, sibling)
		}
	}

	return bytes.Equal(current, rootHash)
}
