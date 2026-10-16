package transport

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"
)

// WebRTCConfig defines STUN/TURN and ICE parameters.
type WebRTCConfig struct {
	ICEServers         []webrtc.ICEServer
	FallbackTimeout    time.Duration // 2.0s deterministic fallback ladder
	OnChannelAMessage  func(msg []byte)
	OnChannelBMessage  func(msg []byte)
	OnCandidateDiscovered func(candidate *webrtc.ICECandidateInit)
}

// PeerTransport encapsulates dual-channel WebRTC DataChannel communication.
type PeerTransport struct {
	mu           sync.RWMutex
	pc           *webrtc.PeerConnection
	channelA     *webrtc.DataChannel // Low-latency control, live telemetry, compact outputs (< 64 MiB)
	channelB     *webrtc.DataChannel // High-throughput bulk shards and large outputs (> 64 MiB)
	connected    chan struct{}
	channelsOpen chan struct{}
	onceConn     sync.Once
	onceOpen     sync.Once
	chanAOpen    atomic.Bool
	chanBOpen    atomic.Bool
	cfg          WebRTCConfig
}

// NewPeerTransport creates a new WebRTC peer transport instance.
func NewPeerTransport(cfg WebRTCConfig) (*PeerTransport, error) {
	if cfg.FallbackTimeout <= 0 {
		cfg.FallbackTimeout = 2000 * time.Millisecond // 2.0s fallback ladder (§5)
	}

	iceServers := cfg.ICEServers
	if len(iceServers) == 0 {
		iceServers = []webrtc.ICEServer{
			{
				URLs: []string{
					"stun:stun.l.google.com:19302",
					"stun:stun1.l.google.com:19302",
				},
			},
		}
	}

	settingEngine := webrtc.SettingEngine{}
	// Enable dual-stack IPv4 & IPv6 candidate gathering (§5)
	settingEngine.SetNetworkTypes([]webrtc.NetworkType{
		webrtc.NetworkTypeUDP4,
		webrtc.NetworkTypeUDP6,
		webrtc.NetworkTypeTCP4,
		webrtc.NetworkTypeTCP6,
	})

	api := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine))

	pc, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: iceServers,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create peer connection: %w", err)
	}

	pt := &PeerTransport{
		pc:           pc,
		connected:    make(chan struct{}),
		channelsOpen: make(chan struct{}),
		cfg:          cfg,
	}

	// ICE Candidate handler (Trickle ICE)
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil && cfg.OnCandidateDiscovered != nil {
			init := c.ToJSON()
			cfg.OnCandidateDiscovered(&init)
		}
	})

	// Connection state listener
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateConnected {
			pt.onceConn.Do(func() {
				close(pt.connected)
			})
		}
	})

	// Remote DataChannel handler (when acting as answerer)
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		pt.setupDataChannel(dc)
	})

	return pt, nil
}

func (pt *PeerTransport) checkBothOpen() {
	if pt.chanAOpen.Load() && pt.chanBOpen.Load() {
		pt.onceOpen.Do(func() {
			close(pt.channelsOpen)
		})
	}
}

func (pt *PeerTransport) setupDataChannel(dc *webrtc.DataChannel) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	label := dc.Label()
	if label == "channel-a-control" {
		pt.channelA = dc
		dc.OnOpen(func() {
			pt.chanAOpen.Store(true)
			pt.checkBothOpen()
		})
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			if pt.cfg.OnChannelAMessage != nil {
				pt.cfg.OnChannelAMessage(msg.Data)
			}
		})
	} else if label == "channel-b-bulk" {
		pt.channelB = dc
		dc.OnOpen(func() {
			pt.chanBOpen.Store(true)
			pt.checkBothOpen()
		})
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			if pt.cfg.OnChannelBMessage != nil {
				pt.cfg.OnChannelBMessage(msg.Data)
			}
		})
	}
}

// InitCallerChannels initializes Channel A and Channel B on the offering peer.
func (pt *PeerTransport) InitCallerChannels() error {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	ordered := true
	// Channel A: SCTP control / telemetry / compact outputs (< 64 MiB)
	dcA, err := pt.pc.CreateDataChannel("channel-a-control", &webrtc.DataChannelInit{
		Ordered: &ordered,
	})
	if err != nil {
		return fmt.Errorf("failed to create channel A: %w", err)
	}
	pt.channelA = dcA
	dcA.OnOpen(func() {
		pt.chanAOpen.Store(true)
		pt.checkBothOpen()
	})
	dcA.OnMessage(func(msg webrtc.DataChannelMessage) {
		if pt.cfg.OnChannelAMessage != nil {
			pt.cfg.OnChannelAMessage(msg.Data)
		}
	})

	// Channel B: High-throughput bulk data channel for shards
	dcB, err := pt.pc.CreateDataChannel("channel-b-bulk", &webrtc.DataChannelInit{
		Ordered: &ordered,
	})
	if err != nil {
		return fmt.Errorf("failed to create channel B: %w", err)
	}
	pt.channelB = dcB
	dcB.OnOpen(func() {
		pt.chanBOpen.Store(true)
		pt.checkBothOpen()
	})
	dcB.OnMessage(func(msg webrtc.DataChannelMessage) {
		if pt.cfg.OnChannelBMessage != nil {
			pt.cfg.OnChannelBMessage(msg.Data)
		}
	})

	return nil
}

// CreateOffer generates a WebRTC SDP offer.
func (pt *PeerTransport) CreateOffer() (string, error) {
	offer, err := pt.pc.CreateOffer(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create offer: %w", err)
	}
	if err := pt.pc.SetLocalDescription(offer); err != nil {
		return "", fmt.Errorf("failed to set local description: %w", err)
	}

	bytes, err := json.Marshal(offer)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// HandleOffer receives an SDP offer and returns an SDP answer.
func (pt *PeerTransport) HandleOffer(offerJSON string) (string, error) {
	var offer webrtc.SessionDescription
	if err := json.Unmarshal([]byte(offerJSON), &offer); err != nil {
		return "", fmt.Errorf("invalid offer json: %w", err)
	}

	if err := pt.pc.SetRemoteDescription(offer); err != nil {
		return "", fmt.Errorf("failed to set remote description: %w", err)
	}

	answer, err := pt.pc.CreateAnswer(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create answer: %w", err)
	}

	if err := pt.pc.SetLocalDescription(answer); err != nil {
		return "", fmt.Errorf("failed to set local answer: %w", err)
	}

	bytes, err := json.Marshal(answer)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// HandleAnswer receives the remote answer SDP.
func (pt *PeerTransport) HandleAnswer(answerJSON string) error {
	var answer webrtc.SessionDescription
	if err := json.Unmarshal([]byte(answerJSON), &answer); err != nil {
		return fmt.Errorf("invalid answer json: %w", err)
	}
	return pt.pc.SetRemoteDescription(answer)
}

// AddCandidate adds a remote ICE candidate.
func (pt *PeerTransport) AddCandidate(candidate webrtc.ICECandidateInit) error {
	return pt.pc.AddICECandidate(candidate)
}

// WaitConnected blocks until direct P2P data connection is established or timeout.
func (pt *PeerTransport) WaitConnected(timeout time.Duration) bool {
	select {
	case <-pt.connected:
		return true
	case <-time.After(timeout):
		return false
	}
}

// WaitForChannels blocks until both Channel A and Channel B are open or timeout expires.
func (pt *PeerTransport) WaitForChannels(timeout time.Duration) bool {
	select {
	case <-pt.channelsOpen:
		return true
	case <-time.After(timeout):
		return false
	}
}

// SendChannelA sends data over low-latency control/telemetry Channel A.
func (pt *PeerTransport) SendChannelA(data []byte) error {
	pt.mu.RLock()
	dc := pt.channelA
	pt.mu.RUnlock()
	if dc == nil {
		return fmt.Errorf("channel A not initialized")
	}

	// If not yet open, wait briefly (up to 2 seconds)
	deadline := time.Now().Add(2 * time.Second)
	for dc.ReadyState() != webrtc.DataChannelStateOpen {
		state := dc.ReadyState()
		if state == webrtc.DataChannelStateClosed || state == webrtc.DataChannelStateClosing {
			return fmt.Errorf("channel A closed (state: %s)", state.String())
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("channel A not open (current state: %s)", state.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	return dc.Send(data)
}

// SendChannelB sends bulk shards over Channel B.
func (pt *PeerTransport) SendChannelB(data []byte) error {
	pt.mu.RLock()
	dc := pt.channelB
	pt.mu.RUnlock()
	if dc == nil {
		return fmt.Errorf("channel B not initialized")
	}

	// If not yet open, wait briefly (up to 2 seconds)
	deadline := time.Now().Add(2 * time.Second)
	for dc.ReadyState() != webrtc.DataChannelStateOpen {
		state := dc.ReadyState()
		if state == webrtc.DataChannelStateClosed || state == webrtc.DataChannelStateClosing {
			return fmt.Errorf("channel B closed (state: %s)", state.String())
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("channel B not open (current state: %s)", state.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	return dc.Send(data)
}

// Close closes the peer connection.
func (pt *PeerTransport) Close() error {
	return pt.pc.Close()
}
