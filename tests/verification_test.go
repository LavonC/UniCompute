package tests

import (
	"testing"
	"time"

	"unicompute/pkg/crypto"
	"unicompute/pkg/protocol"
	"unicompute/pkg/verification"
)

func TestExecutionReceiptAttestation(t *testing.T) {
	workerKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate worker keypair: %v", err)
	}

	receipt := &protocol.ExecutionReceipt{
		TaskID:              "task-attest-01",
		NodeID:              "node-win11-8f2a",
		InputCID:            "bafybeih5a6q37",
		OutputCID:           "3c8e9b01f8273645",
		FuelConsumed:        4500000,
		ExitCode:            0,
		ExecutionDurationMs: 1420,
		Timestamp:           time.Now().Unix(),
		WorkerPubKey:        workerKP.PublicKeyHex(),
	}

	digest, err := receipt.CanonicalReceiptHash()
	if err != nil {
		t.Fatalf("Failed to compute canonical receipt hash: %v", err)
	}

	receipt.Signature = workerKP.SignHex(digest)

	// 1. Verify honest receipt
	valid, err := verification.VerifyExecutionReceipt(receipt)
	if err != nil || !valid {
		t.Errorf("Valid execution receipt failed verification: %v", err)
	}

	// 2. Tampered output CID must fail
	receiptTampered := *receipt
	receiptTampered.OutputCID = "tampered_output_cid"
	validTampered, _ := verification.VerifyExecutionReceipt(&receiptTampered)
	if validTampered {
		t.Errorf("Tampered receipt unexpectedly passed cryptographic verification")
	}

	// 3. Tampered fuel count must fail
	receiptTamperedFuel := *receipt
	receiptTamperedFuel.FuelConsumed = 100
	validTamperedFuel, _ := verification.VerifyExecutionReceipt(&receiptTamperedFuel)
	if validTamperedFuel {
		t.Errorf("Tampered fuel receipt unexpectedly passed verification")
	}
}

func TestSpotCheckingByzantineDetection(t *testing.T) {
	mgr := verification.NewSpotCheckManager()
	primaryNode := "node-volunteer-01"
	auditNode := "node-lab-verifier-02"

	// 1. Honest execution: primary CID == audit CID
	taskID1 := "task-honest-01"
	honestCID := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	matched, err := mgr.EvaluateSpotCheck(taskID1, primaryNode, auditNode, honestCID, honestCID)
	if err != nil || !matched {
		t.Errorf("Honest spot check failed: %v", err)
	}
	if mgr.IsBlacklisted(primaryNode) {
		t.Errorf("Honest node was unexpectedly blacklisted")
	}

	// 2. Byzantine cheating worker: skips work and signs fabricated output CID
	taskID2 := "task-cheating-02"
	fakeCID := "fabricated_cheating_hash_deadbeef"
	truthCID := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	matchedCheater, errCheater := mgr.EvaluateSpotCheck(taskID2, primaryNode, auditNode, fakeCID, truthCID)
	if matchedCheater {
		t.Errorf("Cheating node was not caught by spot check!")
	}
	if errCheater == nil {
		t.Errorf("Expected Byzantine error on CID discrepancy")
	}

	// 3. Verify node is now blacklisted
	if !mgr.IsBlacklisted(primaryNode) {
		t.Errorf("Cheating node was not blacklisted!")
	}
}

func TestSpotCheckingFramingAndTieBreaker(t *testing.T) {
	mgr := verification.NewSpotCheckManager()
	rep := verification.NewReputationTracker()

	primaryNode := "node-volunteer-honest"
	framingAuditNode := "node-volunteer-malicious"
	refereeNode := "node-lab-referee"

	honestCID := "a1b2c3d4e5f60000111122223333444455556666777788889999aaaabbbbcccc"
	fabricatedCID := "9999888877776666555544443333222211110000ffffedcba9876543210fedcb"

	// 1. Peer-to-peer mismatch without validated verifiers -> Dispute, primary NOT blacklisted
	taskID := "task-dispute-01"
	matched, err := mgr.EvaluateSpotCheck(taskID, primaryNode, framingAuditNode, honestCID, fabricatedCID)
	if matched {
		t.Errorf("Disputed spot check should not report a match")
	}
	if err == nil {
		t.Errorf("Expected dispute error on mismatch")
	}
	if mgr.IsBlacklisted(primaryNode) {
		t.Errorf("Primary node was prematurely blacklisted without tie-breaker validation!")
	}
	if mgr.IsBlacklisted(framingAuditNode) {
		t.Errorf("Audit node was prematurely blacklisted without tie-breaker validation!")
	}

	// 2. Resolve tie-break with referee node matching primary:
	// Framing audit worker MUST BE blacklisted and slashed; primary worker exonerated.
	guilty, errTie := mgr.ResolveTieBreak(taskID, primaryNode, framingAuditNode, refereeNode, honestCID, fabricatedCID, honestCID, 1000, 1000, 1000, rep)
	if guilty != framingAuditNode {
		t.Errorf("Expected framing audit node %s to be flagged guilty, got %s", framingAuditNode, guilty)
	}
	if errTie == nil {
		t.Errorf("Expected Byzantine error on framing audit worker")
	}
	if !mgr.IsBlacklisted(framingAuditNode) {
		t.Errorf("Framing audit node was not blacklisted!")
	}
	if mgr.IsBlacklisted(primaryNode) {
		t.Errorf("Honest primary node was wrongfully blacklisted!")
	}
	if rep.GetCreditScore(framingAuditNode) != 0.0 {
		t.Errorf("Framing audit node credit was not slashed to 0.0")
	}
}

func TestTieBreakerUnanimousAgreement(t *testing.T) {
	mgr := verification.NewSpotCheckManager()
	rep := verification.NewReputationTracker()

	primaryNode := "node-primary-01"
	auditNode := "node-audit-01"
	refereeNode := "node-referee-01"
	taskID := "task-unanimous-01"
	honestCID := "bafybeih5a6q37_consensus_output_hash"

	// All 3 nodes produce identical output CID and fuel
	guilty, err := mgr.ResolveTieBreak(taskID, primaryNode, auditNode, refereeNode,
		honestCID, honestCID, honestCID,
		5000, 5000, 5000, rep)

	if guilty != "" {
		t.Errorf("Expected no guilty node for unanimous agreement, got %s", guilty)
	}
	if err != nil {
		t.Errorf("Expected nil error for unanimous agreement, got %v", err)
	}
	if mgr.IsBlacklisted(primaryNode) {
		t.Errorf("Primary node was erroneously blacklisted on unanimous consensus")
	}
	if mgr.IsBlacklisted(auditNode) {
		t.Errorf("Audit node was erroneously blacklisted on unanimous consensus")
	}
	if rep.GetCreditScore(primaryNode) <= 0.0 || rep.GetCreditScore(auditNode) <= 0.0 {
		t.Errorf("Worker reputation was erroneously slashed on unanimous consensus")
	}
}

func TestTieBreakerPrimaryCheating(t *testing.T) {
	mgr := verification.NewSpotCheckManager()
	rep := verification.NewReputationTracker()

	primaryNode := "node-cheater-primary"
	auditNode := "node-honest-audit"
	refereeNode := "node-referee-02"
	taskID := "task-primary-cheating-01"

	honestCID := "bafybeih5a6q37_consensus_honest_output"
	fabricatedCID := "bafybeih5a6q37_forged_primary_output"

	// Primary cheated, audit and referee agree
	guilty, err := mgr.ResolveTieBreak(taskID, primaryNode, auditNode, refereeNode,
		fabricatedCID, honestCID, honestCID,
		5000, 5000, 5000, rep)

	if guilty != primaryNode {
		t.Errorf("Expected guilty node %s, got %s", primaryNode, guilty)
	}
	if err == nil {
		t.Errorf("Expected error flagging Byzantine cheating on primary node")
	}
	if !mgr.IsBlacklisted(primaryNode) {
		t.Errorf("Cheating primary node was not blacklisted")
	}
	if mgr.IsBlacklisted(auditNode) {
		t.Errorf("Honest audit node was wrongfully blacklisted")
	}
	if rep.GetCreditScore(primaryNode) != 0.0 {
		t.Errorf("Cheating primary credit score was not slashed to 0.0: got %f", rep.GetCreditScore(primaryNode))
	}
	if rep.GetCreditScore(auditNode) <= 0.0 {
		t.Errorf("Honest audit node credit score was slashed")
	}
}

func TestReputationTrackerAndDisqualification(t *testing.T) {
	rep := verification.NewReputationTracker()
	node := "node-student-laptop-03"

	// Initial score
	initial := rep.GetCreditScore(node)
	if initial != 0.5 {
		t.Errorf("Expected initial credit 0.5, got %f", initial)
	}

	// Success boosts score
	rep.RecordSuccess(node)
	if rep.GetCreditScore(node) <= initial {
		t.Errorf("Score did not increase after successful task")
	}

	// Failures decrease score
	rep.RecordFailure(node)
	rep.RecordFailure(node)
	rep.RecordFailure(node)

	// 4th consecutive failure must disqualify node (§10.3)
	if rep.IsDisqualified(node) {
		t.Errorf("Node should not be disqualified before 4 consecutive failures")
	}

	rep.RecordFailure(node) // 4th consecutive failure

	if !rep.IsDisqualified(node) {
		t.Errorf("Node was not disqualified after 4 consecutive audit failures!")
	}

	if rep.GetCreditScore(node) != 0.0 {
		t.Errorf("Disqualified node credit score not zeroed: %f", rep.GetCreditScore(node))
	}
}

func TestSpotCheckingFuelDiscrepancyAndSlashing(t *testing.T) {
	mgr := verification.NewSpotCheckManager()
	rep := verification.NewReputationTracker()

	primaryNode := "node-cheating-fuel-01"
	auditNode := "node-lab-verifier-01"
	taskID := "task-spotcheck-fuel"
	outputCID := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// Worker forged a low fuel count (100) while real computation consumed 55,000
	primaryFuel := uint64(100)
	truthFuel := uint64(55000)

	matched, err := mgr.EvaluateSpotCheckWithFuel(taskID, primaryNode, auditNode, outputCID, outputCID, primaryFuel, truthFuel, rep)
	if matched {
		t.Errorf("Expected fuel mismatch to fail spot check")
	}
	if err == nil {
		t.Errorf("Expected Byzantine error on fuel discrepancy")
	}

	// Verify node was blacklisted and reputation slashed to 0.0
	if !mgr.IsBlacklisted(primaryNode) {
		t.Errorf("Worker was not blacklisted on fuel discrepancy")
	}
	if rep.GetCreditScore(primaryNode) != 0.0 {
		t.Errorf("Worker credit score was not slashed to 0.0: got %f", rep.GetCreditScore(primaryNode))
	}
	if !rep.IsDisqualified(primaryNode) {
		t.Errorf("Worker was not marked disqualified after Byzantine slash")
	}
}
