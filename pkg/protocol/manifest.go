package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// CanonicalDigest computes the deterministic SHA-256 digest of a manifest.
func (m *Manifest) CanonicalDigest() ([]byte, error) {
	// Sort env keys and dataset list for canonical representation
	sortedDatasets := make([]string, len(m.RequiredDatasets))
	copy(sortedDatasets, m.RequiredDatasets)
	sort.Strings(sortedDatasets)

	type CanonicalManifest struct {
		Args             []string          `json:"args"`
		Entrypoint       string            `json:"entrypoint"`
		Env              map[string]string `json:"env"`
		FuelLimit        uint64            `json:"fuel_limit"`
		MaxMemoryMB      int64             `json:"max_memory_mb"`
		MinTier          ExecutionTier     `json:"min_tier"`
		Name             string            `json:"name"`
		RequiredDatasets []string          `json:"required_datasets"`
		ResearcherPubKey string            `json:"researcher_pub_key"`
		TaskID           string            `json:"task_id"`
		Version          string            `json:"version"`
	}

	cm := CanonicalManifest{
		Args:             m.Args,
		Entrypoint:       m.Entrypoint,
		Env:              m.Env,
		FuelLimit:        m.FuelLimit,
		MaxMemoryMB:      m.MaxMemoryMB,
		MinTier:          m.MinTier,
		Name:             m.Name,
		RequiredDatasets: sortedDatasets,
		ResearcherPubKey: m.ResearcherPubKey,
		TaskID:           m.TaskID,
		Version:          m.Version,
	}

	bytes, err := json.Marshal(cm)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal canonical manifest: %w", err)
	}

	h := sha256.Sum256(bytes)
	return h[:], nil
}

// CanonicalDigestHex returns the hex-encoded canonical digest.
func (m *Manifest) CanonicalDigestHex() (string, error) {
	d, err := m.CanonicalDigest()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(d), nil
}
