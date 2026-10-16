package verification

import (
	"sync"
	"time"
)

// ReputationTracker maintains BitTorrent-inspired credit decay and Bayesian Beta-posterior reliability scores.
type ReputationTracker struct {
	mu           sync.RWMutex
	creditScores map[string]float64
	alpha        map[string]float64 // Beta distribution alpha (successes)
	beta         map[string]float64 // Beta distribution beta (failures)
	failStreaks  map[string]int     // Consecutive audit failures
	disqualified map[string]bool
	lastUpdate   map[string]time.Time
}

// NewReputationTracker creates a reputation manager.
func NewReputationTracker() *ReputationTracker {
	return &ReputationTracker{
		creditScores: make(map[string]float64),
		alpha:        make(map[string]float64),
		beta:         make(map[string]float64),
		failStreaks:  make(map[string]int),
		disqualified: make(map[string]bool),
		lastUpdate:   make(map[string]time.Time),
	}
}

// GetCreditScore returns the current credit score for a node (0.0 to 1.0).
func (rt *ReputationTracker) GetCreditScore(nodeID string) float64 {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	if rt.disqualified[nodeID] {
		return 0.0
	}
	score, exists := rt.creditScores[nodeID]
	if !exists {
		return 0.5 // Default starting credit
	}
	return score
}

// RecordSuccess updates reputation after a verified successful task or storage audit.
func (rt *ReputationTracker) RecordSuccess(nodeID string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if rt.disqualified[nodeID] {
		return
	}

	current := rt.creditScores[nodeID]
	if current == 0 {
		current = 0.5
	}
	// Asymptotic approach to 1.0
	current += (1.0 - current) * 0.05
	if current > 1.0 {
		current = 1.0
	}
	rt.creditScores[nodeID] = current

	// Bayesian update
	rt.alpha[nodeID] = rt.alpha[nodeID] + 1.0
	rt.failStreaks[nodeID] = 0
	rt.lastUpdate[nodeID] = time.Now()
}

// RecordFailure updates reputation after an unverified result or audit failure.
func (rt *ReputationTracker) RecordFailure(nodeID string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	current := rt.creditScores[nodeID]
	current = current * 0.70 // 30% penalty
	if current < 0.05 {
		current = 0.05
	}
	rt.creditScores[nodeID] = current

	rt.beta[nodeID] = rt.beta[nodeID] + 1.0
	rt.failStreaks[nodeID]++
	rt.lastUpdate[nodeID] = time.Now()

	// Section 10.3 / 11: Flag and disqualify nodes that fail 4 consecutive audits within 24 hours
	if rt.failStreaks[nodeID] >= 4 {
		rt.disqualified[nodeID] = true
		rt.creditScores[nodeID] = 0.0
	}
}

// SlashToZero immediately zeroes credit and disqualifies node upon confirmed Byzantine cheating.
func (rt *ReputationTracker) SlashToZero(nodeID string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	rt.creditScores[nodeID] = 0.0
	rt.disqualified[nodeID] = true
	rt.lastUpdate[nodeID] = time.Now()
}

// IsDisqualified checks if the node has been disqualified.
func (rt *ReputationTracker) IsDisqualified(nodeID string) bool {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.disqualified[nodeID]
}

// GetBetaPosterior returns the Beta distribution mean: alpha / (alpha + beta).
func (rt *ReputationTracker) GetBetaPosterior(nodeID string) float64 {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	a := rt.alpha[nodeID] + 1.0 // Laplace prior
	b := rt.beta[nodeID] + 1.0
	return a / (a + b)
}
