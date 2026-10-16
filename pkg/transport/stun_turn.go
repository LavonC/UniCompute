package transport

import (
	"fmt"
	"net"
	"time"

	"github.com/pion/turn/v5"
)

// STUNTURNConfig holds settings for the campus TURN/STUN daemon.
type STUNTURNConfig struct {
	PublicIP net.IP
	Port     int
	Realm    string
	Username string
	Password string
}

// StartSTUNTURNServer launches an embedded STUN/TURN daemon for NAT traversal and 2.0s relay fallback.
func StartSTUNTURNServer(cfg STUNTURNConfig) (*turn.Server, error) {
	if cfg.Port <= 0 {
		cfg.Port = 3478
	}
	if cfg.Realm == "" {
		cfg.Realm = "unicompute.campus"
	}
	if cfg.PublicIP == nil {
		cfg.PublicIP = net.ParseIP("127.0.0.1")
	}

	udpListener, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", cfg.Port))
	if err != nil {
		return nil, fmt.Errorf("failed to listen on STUN/TURN port %d: %w", cfg.Port, err)
	}

	server, err := turn.NewServer(turn.ServerConfig{
		Realm:       cfg.Realm,
		AuthHandler: turn.NewLongTermAuthHandler(cfg.Password, nil),
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: udpListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
					RelayAddress: cfg.PublicIP,
					Address:      "0.0.0.0",
				},
			},
		},
	})
	if err != nil {
		udpListener.Close()
		return nil, fmt.Errorf("failed to create turn server: %w", err)
	}

	return server, nil
}

// FallbackLadder enforces the 2.0-second deterministic fallback ladder (§5, Stage 4).
type FallbackLadder struct {
	timeout    time.Duration
	fallbackFn func()
}

// NewFallbackLadder creates a fallback timer for P2P connection attempts.
func NewFallbackLadder(timeout time.Duration, onFallback func()) *FallbackLadder {
	if timeout <= 0 {
		timeout = 2000 * time.Millisecond // 2.0s (§5)
	}
	return &FallbackLadder{
		timeout:    timeout,
		fallbackFn: onFallback,
	}
}

// Start launches the fallback timer. If cancel() is not called before timeout, onFallback fires.
func (fl *FallbackLadder) Start() func() {
	timer := time.NewTimer(fl.timeout)
	done := make(chan struct{})

	go func() {
		select {
		case <-timer.C:
			if fl.fallbackFn != nil {
				fl.fallbackFn()
			}
		case <-done:
			timer.Stop()
		}
	}()

	return func() {
		close(done)
	}
}
