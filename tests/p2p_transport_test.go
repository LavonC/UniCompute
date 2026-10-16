package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"unicompute/pkg/protocol"
	"unicompute/pkg/transport"

	"github.com/pion/webrtc/v4"
)

func TestSignalingHubMessageRouting(t *testing.T) {
	hub := transport.NewSignalingHub()
	server := httptest.NewServer(http.HandlerFunc(hub.HandleWebSocket))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// 1. Connect Client A
	clientA, err := transport.DialCoordinator(wsURL)
	if err != nil {
		t.Fatalf("Failed to dial client A: %v", err)
	}
	defer clientA.Close()

	nodeA := protocol.Node{ID: "node-A", Online: true}
	nodeABytes, _ := json.Marshal(nodeA)
	_ = clientA.Send(&protocol.SignalingMessage{
		Type:     "register",
		FromNode: "node-A",
		Payload:  nodeABytes,
	})

	// 2. Connect Client B
	clientB, err := transport.DialCoordinator(wsURL)
	if err != nil {
		t.Fatalf("Failed to dial client B: %v", err)
	}
	defer clientB.Close()

	nodeB := protocol.Node{ID: "node-B", Online: true}
	nodeBBytes, _ := json.Marshal(nodeB)
	_ = clientB.Send(&protocol.SignalingMessage{
		Type:     "register",
		FromNode: "node-B",
		Payload:  nodeBBytes,
	})

	// Wait for registration
	time.Sleep(100 * time.Millisecond)

	// 3. Client A sends routed message to Client B
	receivedCh := make(chan string, 1)
	clientB.On("custom_offer", func(msg *protocol.SignalingMessage) {
		receivedCh <- string(msg.Payload)
	})

	testPayload := `{"sdp":"v=0\r\no=- 123456 2 IN IP4 127.0.0.1"}`
	sendMsg := &protocol.SignalingMessage{
		Type:     "custom_offer",
		FromNode: "node-A",
		ToNode:   "node-B",
		Payload:  json.RawMessage(testPayload),
	}

	if err := clientA.Send(sendMsg); err != nil {
		t.Fatalf("Client A send failed: %v", err)
	}

	select {
	case payload := <-receivedCh:
		if payload != testPayload {
			t.Errorf("Received payload does not match sent payload: %s", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for message to route to Client B")
	}
}

func Test2sDeterministicFallbackLadder(t *testing.T) {
	var fallbackTriggered atomic.Bool

	// Test 1: Timeout fires
	ladder1 := transport.NewFallbackLadder(50*time.Millisecond, func() {
		fallbackTriggered.Store(true)
	})

	cancel1 := ladder1.Start()
	defer cancel1()

	time.Sleep(100 * time.Millisecond)
	if !fallbackTriggered.Load() {
		t.Errorf("Expected fallback ladder to fire on timeout")
	}

	// Test 2: Cancelled before timeout (direct P2P convergence succeeds within 2.0s)
	fallbackTriggered.Store(false)
	ladder2 := transport.NewFallbackLadder(100*time.Millisecond, func() {
		fallbackTriggered.Store(true)
	})

	cancel2 := ladder2.Start()
	cancel2() // cancel immediately
	time.Sleep(150 * time.Millisecond)

	if fallbackTriggered.Load() {
		t.Errorf("Fallback ladder fired even though it was cancelled!")
	}
}

func TestWebRTCDataChannelsDirectP2P(t *testing.T) {
	// Channels to collect received messages
	peer2ChanARecv := make(chan string, 1)
	peer1ChanBRecv := make(chan string, 1)

	var peer1, peer2 *transport.PeerTransport
	var err error

	cfg1 := transport.WebRTCConfig{
		OnChannelBMessage: func(msg []byte) {
			peer1ChanBRecv <- string(msg)
		},
		OnCandidateDiscovered: func(c *webrtc.ICECandidateInit) {
			if peer2 != nil {
				_ = peer2.AddCandidate(*c)
			}
		},
	}

	cfg2 := transport.WebRTCConfig{
		OnChannelAMessage: func(msg []byte) {
			peer2ChanARecv <- string(msg)
		},
		OnCandidateDiscovered: func(c *webrtc.ICECandidateInit) {
			if peer1 != nil {
				_ = peer1.AddCandidate(*c)
			}
		},
	}

	peer1, err = transport.NewPeerTransport(cfg1)
	if err != nil {
		t.Fatalf("Failed to create Peer 1: %v", err)
	}
	defer peer1.Close()

	peer2, err = transport.NewPeerTransport(cfg2)
	if err != nil {
		t.Fatalf("Failed to create Peer 2: %v", err)
	}
	defer peer2.Close()

	// 1. Initialize Caller Channels on Peer 1 (Channel A control, Channel B bulk)
	if err := peer1.InitCallerChannels(); err != nil {
		t.Fatalf("Peer 1 InitCallerChannels failed: %v", err)
	}

	// 2. Perform SDP Offer/Answer Exchange
	offer, err := peer1.CreateOffer()
	if err != nil {
		t.Fatalf("CreateOffer failed: %v", err)
	}

	answer, err := peer2.HandleOffer(offer)
	if err != nil {
		t.Fatalf("HandleOffer failed: %v", err)
	}

	if err := peer1.HandleAnswer(answer); err != nil {
		t.Fatalf("HandleAnswer failed: %v", err)
	}

	// 3. Wait for direct WebRTC connection & DataChannel opening
	if !peer1.WaitForChannels(5 * time.Second) {
		t.Fatalf("Timed out waiting for Peer 1 DataChannels to open")
	}
	if !peer2.WaitForChannels(5 * time.Second) {
		t.Fatalf("Timed out waiting for Peer 2 DataChannels to open")
	}

	// 4. Test Channel A (Low-latency telemetry / control)
	telemetryMsg := `{"task_id":"task-123","progress":45.2,"status":"RUNNING"}`
	if err := peer1.SendChannelA([]byte(telemetryMsg)); err != nil {
		t.Fatalf("Peer 1 SendChannelA failed: %v", err)
	}

	select {
	case received := <-peer2ChanARecv:
		if received != telemetryMsg {
			t.Errorf("Channel A received message mismatch: got %s, want %s", received, telemetryMsg)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Timed out waiting for Channel A message on Peer 2")
	}

	// 5. Test Channel B (High-throughput bulk shard data)
	bulkData := "SHARD_DATA_CAUCHY_RS_32_80_PAYLOAD_CHUNK_SAMPLE_TEST_BYTES"
	if err := peer2.SendChannelB([]byte(bulkData)); err != nil {
		t.Fatalf("Peer 2 SendChannelB failed: %v", err)
	}

	select {
	case received := <-peer1ChanBRecv:
		if received != bulkData {
			t.Errorf("Channel B received message mismatch: got %s, want %s", received, bulkData)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Timed out waiting for Channel B message on Peer 1")
	}
}
