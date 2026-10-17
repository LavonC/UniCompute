package transport

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"unicompute/pkg/protocol"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all cross-origin connections within campus network
	},
	ReadBufferSize:  64 * 1024,
	WriteBufferSize: 64 * 1024,
}

// HandlerFunc is called when a signaling message arrives.
type HandlerFunc func(msg *protocol.SignalingMessage)

// SignalingHub coordinates mTLS / WSS signaling exchanges between Requesters and Workers.
type SignalingHub struct {
	mu          sync.RWMutex
	conns       map[string]*websocket.Conn // NodeID -> Conn
	handlers    map[string][]HandlerFunc   // MessageType -> []HandlerFunc
	onRegister  func(node *protocol.Node)
	onHeartbeat func(nodeID string)
	onUnregister func(nodeID string)
}

// NewSignalingHub creates a new WebSocket signaling coordinator.
func NewSignalingHub() *SignalingHub {
	return &SignalingHub{
		conns:    make(map[string]*websocket.Conn),
		handlers: make(map[string][]HandlerFunc),
	}
}

// On registers a callback for a specific message type.
func (h *SignalingHub) On(msgType string, fn HandlerFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handlers[msgType] = append(h.handlers[msgType], fn)
}

// SetCallbacks sets node lifecycle hooks.
func (h *SignalingHub) SetCallbacks(onReg func(node *protocol.Node), onHb func(nodeID string), onUnreg func(nodeID string)) {
	h.onRegister = onReg
	h.onHeartbeat = onHb
	h.onUnregister = onUnreg
}

// HandleWebSocket upgrades incoming HTTP to WebSocket and manages signaling loop.
func (h *SignalingHub) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[Signaling] Failed to upgrade websocket: %v", err)
		return
	}
	defer conn.Close()

	var registeredNodeID string

	defer func() {
		if registeredNodeID != "" {
			h.mu.Lock()
			delete(h.conns, registeredNodeID)
			h.mu.Unlock()
			if h.onUnregister != nil {
				h.onUnregister(registeredNodeID)
			}
		}
	}()

	for {
		_, rawMsg, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var sigMsg protocol.SignalingMessage
		if err := json.Unmarshal(rawMsg, &sigMsg); err != nil {
			continue
		}

		switch sigMsg.Type {
		case "register":
			var node protocol.Node
			if err := json.Unmarshal(sigMsg.Payload, &node); err == nil {
				registeredNodeID = node.ID
				h.mu.Lock()
				h.conns[node.ID] = conn
				h.mu.Unlock()
				if h.onRegister != nil {
					h.onRegister(&node)
				}
			}

		case "heartbeat":
			if sigMsg.FromNode != "" && h.onHeartbeat != nil {
				h.onHeartbeat(sigMsg.FromNode)
			}

		default:
			// Route message to target peer if specified
			if sigMsg.ToNode != "" {
				h.mu.RLock()
				targetConn, ok := h.conns[sigMsg.ToNode]
				h.mu.RUnlock()
				if ok {
					_ = targetConn.WriteJSON(sigMsg)
				}
			}

			// Trigger registered local handlers
			h.mu.RLock()
			handlers := h.handlers[sigMsg.Type]
			h.mu.RUnlock()
			for _, fn := range handlers {
				fn(&sigMsg)
			}
		}
	}
}

// SendToNode routes a message to a specific connected node.
func (h *SignalingHub) SendToNode(nodeID string, msg *protocol.SignalingMessage) error {
	h.mu.RLock()
	conn, ok := h.conns[nodeID]
	h.mu.RUnlock()
	if !ok {
		return fmt.Errorf("node %s not connected", nodeID)
	}

	return conn.WriteJSON(msg)
}

// Broadcast sends a message to all connected nodes.
func (h *SignalingHub) Broadcast(msg *protocol.SignalingMessage) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, conn := range h.conns {
		_ = conn.WriteJSON(msg)
	}
}

// ConnectedNodes returns list of connected node IDs.
func (h *SignalingHub) ConnectedNodes() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	nodes := make([]string, 0, len(h.conns))
	for id := range h.conns {
		nodes = append(nodes, id)
	}
	return nodes
}

// Client represents a node's outbound persistent connection to the Coordinator.
type Client struct {
	url       string
	conn      *websocket.Conn
	mu        sync.Mutex
	handlers  map[string][]HandlerFunc
	stopCh    chan struct{}
	closeOnce sync.Once
}

// DialCoordinator connects a worker or requester to the central coordinator over WSS/WS.
func DialCoordinator(urlStr string) (*Client, error) {
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.Dial(urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to coordinator at %s: %w", urlStr, err)
	}

	c := &Client{
		url:      urlStr,
		conn:     conn,
		handlers: make(map[string][]HandlerFunc),
		stopCh:   make(chan struct{}),
	}

	go c.readLoop()
	return c, nil
}

// On registers a handler for incoming signaling messages on the client.
func (c *Client) On(msgType string, fn HandlerFunc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handlers[msgType] = append(c.handlers[msgType], fn)
}

// Send transmits a signaling message to the coordinator.
func (c *Client) Send(msg *protocol.SignalingMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteJSON(msg)
}

// Close disconnects the client idempotently.
func (c *Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.stopCh)
		if c.conn != nil {
			err = c.conn.Close()
		}
	})
	return err
}

func (c *Client) readLoop() {
	for {
		select {
		case <-c.stopCh:
			return
		default:
			_, raw, err := c.conn.ReadMessage()
			if err != nil {
				return
			}
			var msg protocol.SignalingMessage
			if err := json.Unmarshal(raw, &msg); err == nil {
				c.mu.Lock()
				handlers := c.handlers[msg.Type]
				c.mu.Unlock()
				for _, fn := range handlers {
					fn(&msg)
				}
			}
		}
	}
}
