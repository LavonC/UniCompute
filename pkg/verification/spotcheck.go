package verification

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
)

// SpotCheckManager orchestrates Layer 2 asynchronous 5–10% probabilistic spot-checking.
type SpotCheckManager struct {
	mu               sync.RWMutex
	baseRate         float64 // 0.05 (5%)
	maxRate          float64 // 0.10 (10%)
	blacklisted      map[string]bool
	trustedVerifiers map[string]bool
	auditHistory     map[string][]AuditRecord
	disputes         map[string]*DisputeRecord
}

// AuditRecord stores the outcome of a spot check.
type AuditRecord struct {
	TaskID       string
	PrimaryNode  string
	AuditNode    string
	PrimaryCID   string
	AuditCID     string
	PrimaryFuel  uint64
	AuditFuel    uint64
	Passed       bool
	Timestamp    int64
}

// DisputeRecord stores an unverified peer mismatch awaiting tie-breaker validation.
type DisputeRecord struct {
	TaskID       string
	PrimaryNode  string
	AuditNode    string
	PrimaryCID   string
	AuditCID     string
	PrimaryFuel  uint64
	AuditFuel    uint64
	Status       string // "PENDING_TIE_BREAKER", "RESOLVED"
	ResolvedAt   int64
	GuiltyNode   string
}

// NewSpotCheckManager creates a spot check manager.
func NewSpotCheckManager() *SpotCheckManager {
	return &SpotCheckManager{
		baseRate:         0.05,
		maxRate:          0.10,
		blacklisted:      make(map[string]bool),
		trustedVerifiers: make(map[string]bool),
		auditHistory:     make(map[string][]AuditRecord),
		disputes:         make(map[string]*DisputeRecord),
	}
}

// RegisterTrustedVerifier registers an authoritative institutional / campus lab verifier.
func (m *SpotCheckManager) RegisterTrustedVerifier(nodeID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.trustedVerifiers[nodeID] = true
}

// IsTrustedVerifier checks if a node is an authoritative validated verifier.
func (m *SpotCheckManager) IsTrustedVerifier(nodeID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isTrustedVerifierLocked(nodeID)
}

func (m *SpotCheckManager) isTrustedVerifierLocked(nodeID string) bool {
	if m.trustedVerifiers[nodeID] {
		return true
	}
	// Default recognized institutional verifiers & anchor nodes (§7.1, §9.1)
	lower := strings.ToLower(nodeID)
	return strings.Contains(lower, "verifier") || strings.Contains(lower, "anchor")
}

// ShouldSpotCheck decides whether to spot check a task based on worker credit score.
// Workers with lower credit scores receive higher spot-check probabilities (up to 10%+).
func (m *SpotCheckManager) ShouldSpotCheck(workerCreditScore float64) bool {
	// Sample random float in [0.0, 1.0)
	var b [8]byte
	_, _ = rand.Read(b[:])
	val := float64(binary.BigEndian.Uint64(b[:])>>11) / (1 << 53)

	// Rate increases as credit score decreases
	rate := m.baseRate + ((1.0 - workerCreditScore) * (m.maxRate - m.baseRate))
	if rate < m.baseRate {
		rate = m.baseRate
	}
	if rate > m.maxRate {
		rate = m.maxRate
	}

	return val < rate
}

// IsBlacklisted checks if a node is currently blacklisted due to Byzantine cheating.
func (m *SpotCheckManager) IsBlacklisted(nodeID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.blacklisted[nodeID]
}

// EvaluateSpotCheck compares primary execution output with independent audit output (§7.1).
// If a validated verifier detects cheating, the cheater is blacklisted.
// If two unverified peers mismatch, a dispute is recorded without unconditionally slashing the primary.
func (m *SpotCheckManager) EvaluateSpotCheck(taskID, primaryNodeID, auditNodeID, primaryCID, auditCID string) (isMatch bool, err error) {
	return m.EvaluateSpotCheckWithFuel(taskID, primaryNodeID, auditNodeID, primaryCID, auditCID, 0, 0, nil)
}

// EvaluateSpotCheckWithFuel compares both output CID and deterministic fuel consumed (§7.1).
// To prevent Byzantine framing attacks, slashing occurs only after verifier validation or tie-breaking.
func (m *SpotCheckManager) EvaluateSpotCheckWithFuel(taskID, primaryNodeID, auditNodeID, primaryCID, auditCID string, primaryFuel, auditFuel uint64, rep *ReputationTracker) (isMatch bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	matched := (primaryCID == auditCID)
	if primaryFuel > 0 && auditFuel > 0 && primaryFuel != auditFuel {
		matched = false
	}

	rec := AuditRecord{
		TaskID:      taskID,
		PrimaryNode: primaryNodeID,
		AuditNode:   auditNodeID,
		PrimaryCID:  primaryCID,
		AuditCID:    auditCID,
		PrimaryFuel: primaryFuel,
		AuditFuel:   auditFuel,
		Passed:      matched,
	}
	m.auditHistory[primaryNodeID] = append(m.auditHistory[primaryNodeID], rec)

	if !matched {
		auditIsVerifier := m.isTrustedVerifierLocked(auditNodeID)
		primaryIsVerifier := m.isTrustedVerifierLocked(primaryNodeID)

		var reason string
		if primaryCID != auditCID {
			reason = fmt.Sprintf("output CID discrepancy: primary %s != audit %s", primaryCID, auditCID)
		} else {
			reason = fmt.Sprintf("fuel consumption discrepancy: primary %d != audit %d", primaryFuel, auditFuel)
		}

		// Case 1: Audit node is a validated verifier -> Primary worker is guilty
		if auditIsVerifier && !primaryIsVerifier {
			m.blacklisted[primaryNodeID] = true
			if rep != nil {
				rep.SlashToZero(primaryNodeID)
			}
			return false, fmt.Errorf("BYZANTINE DETECTED on node %s: %s (node blacklisted, credit slashed to 0)", primaryNodeID, reason)
		}

		// Case 2: Primary node is a validated verifier -> Audit worker attempted framing
		if primaryIsVerifier && !auditIsVerifier {
			m.blacklisted[auditNodeID] = true
			if rep != nil {
				rep.SlashToZero(auditNodeID)
			}
			return false, fmt.Errorf("BYZANTINE DETECTED on audit node %s (framing attempt): %s (audit node blacklisted, credit slashed to 0)", auditNodeID, reason)
		}

		// Case 3: Peer-to-peer mismatch without validated verifier -> DO NOT unconditionally slash!
		// Record dispute and require tie-breaker validation
		m.disputes[taskID] = &DisputeRecord{
			TaskID:      taskID,
			PrimaryNode: primaryNodeID,
			AuditNode:   auditNodeID,
			PrimaryCID:  primaryCID,
			AuditCID:    auditCID,
			PrimaryFuel: primaryFuel,
			AuditFuel:   auditFuel,
			Status:      "PENDING_TIE_BREAKER",
		}

		return false, fmt.Errorf("DISPUTE DETECTED between primary node %s and audit node %s (%s): awaiting tie-breaker validation before slashing",
			primaryNodeID, auditNodeID, reason)
	}

	return true, nil
}

// ResolveTieBreak uses a third independent referee result to break a tie between primary and audit nodes.
func (m *SpotCheckManager) ResolveTieBreak(taskID, primaryNodeID, auditNodeID, refereeNodeID, primaryCID, auditCID, refereeCID string, primaryFuel, auditFuel, refereeFuel uint64, rep *ReputationTracker) (guiltyNode string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	primaryMatchesRef := (primaryCID == refereeCID)
	if primaryFuel > 0 && refereeFuel > 0 && primaryFuel != refereeFuel {
		primaryMatchesRef = false
	}

	auditMatchesRef := (auditCID == refereeCID)
	if auditFuel > 0 && refereeFuel > 0 && auditFuel != refereeFuel {
		auditMatchesRef = false
	}

	if primaryMatchesRef && auditMatchesRef {
		// Both primary and audit matched referee: unanimous consensus, no Byzantine node
		if d, ok := m.disputes[taskID]; ok {
			d.Status = "RESOLVED"
			d.GuiltyNode = ""
		}
		return "", nil
	}

	if primaryMatchesRef && !auditMatchesRef {
		// Primary is vindicated; audit worker attempted framing!
		m.blacklisted[auditNodeID] = true
		if rep != nil {
			rep.SlashToZero(auditNodeID)
		}
		if d, ok := m.disputes[taskID]; ok {
			d.Status = "RESOLVED"
			d.GuiltyNode = auditNodeID
		}
		return auditNodeID, fmt.Errorf("BYZANTINE DETECTED on audit node %s (framing attempt): referee validated primary node %s (audit node blacklisted, credit slashed to 0)", auditNodeID, primaryNodeID)
	}

	if auditMatchesRef && !primaryMatchesRef {
		// Primary worker is guilty; audit node was correct!
		m.blacklisted[primaryNodeID] = true
		if rep != nil {
			rep.SlashToZero(primaryNodeID)
		}
		if d, ok := m.disputes[taskID]; ok {
			d.Status = "RESOLVED"
			d.GuiltyNode = primaryNodeID
		}
		return primaryNodeID, fmt.Errorf("BYZANTINE DETECTED on primary node %s: referee validated audit node %s (primary node blacklisted, credit slashed to 0)", primaryNodeID, auditNodeID)
	}

	// Referee matches neither: both workers produced invalid results
	m.blacklisted[primaryNodeID] = true
	m.blacklisted[auditNodeID] = true
	if rep != nil {
		rep.SlashToZero(primaryNodeID)
		rep.SlashToZero(auditNodeID)
	}
	if d, ok := m.disputes[taskID]; ok {
		d.Status = "RESOLVED"
		d.GuiltyNode = "both"
	}
	return "both", fmt.Errorf("BYZANTINE DETECTED on both nodes %s and %s: referee output %s matched neither (both blacklisted, credit slashed to 0)", primaryNodeID, auditNodeID, refereeCID)
}

// GetDispute returns the DisputeRecord for a given task ID if it exists.
func (m *SpotCheckManager) GetDispute(taskID string) (*DisputeRecord, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.disputes[taskID]
	if !ok {
		return nil, false
	}
	// Return a copy to prevent data races
	copied := *d
	return &copied, true
}
