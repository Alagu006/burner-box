package handlers

import (
	"burner-box-backend/internal/models"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/websocket/v2"
)

// ---- Status notification WebSocket hub ----

type statusClient struct {
	conn *websocket.Conn
	send chan []byte
	kill chan struct{}
}

type statusHub struct {
	clients    map[*statusClient]struct{}
	broadcast  chan []byte
	register   chan *statusClient
	unregister chan *statusClient
	mu         sync.Mutex
	subID      string
}

var (
	statusHubs   = make(map[string]*statusHub)
	statusHubsMu sync.Mutex
)

func getOrCreateStatusHub(subID string) *statusHub {
	statusHubsMu.Lock()
	defer statusHubsMu.Unlock()

	if hub, ok := statusHubs[subID]; ok {
		return hub
	}

	hub := &statusHub{
		clients:    make(map[*statusClient]struct{}),
		broadcast:  make(chan []byte, 64),
		register:   make(chan *statusClient),
		unregister: make(chan *statusClient),
		subID:      subID,
	}
	statusHubs[subID] = hub
	go hub.run()
	return hub
}

func (h *statusHub) run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = struct{}{}
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			empty := len(h.clients) == 0
			h.mu.Unlock()
			if empty {
				statusHubsMu.Lock()
				delete(statusHubs, h.subID)
				statusHubsMu.Unlock()
				return
			}

		case message := <-h.broadcast:
			h.mu.Lock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.Unlock()
		}
	}
}

// PushStatusChange sends a status change to all WebSocket listeners for a submission.
// Called from UpdateSubmissionStatus when the status field changes.
func PushStatusChange(submissionID string, status string) {
	statusHubsMu.Lock()
	hub, ok := statusHubs[submissionID]
	statusHubsMu.Unlock()
	if !ok {
		return
	}

	out := map[string]string{
		"type":   "status",
		"status": status,
		"time":   time.Now().Format(time.RFC3339),
	}
	data, _ := json.Marshal(out)

	hub.mu.Lock()
	for client := range hub.clients {
		select {
		case client.send <- data:
		default:
			close(client.send)
			delete(hub.clients, client)
		}
	}
	hub.mu.Unlock()
}

// JoinStatusStream is the WebSocket endpoint for status notifications.
// URL: /api/v1/submit/:slug/status/:anonymous_name
// Pushes only { type: "status", status: "read", time: "..." } — no submission content.
func JoinStatusStream(c *websocket.Conn) {
	slug := c.Params("slug")
	anonName := c.Params("anonymous_name")

	if slug == "" || anonName == "" {
		c.WriteJSON(fiber.Map{"type": "error", "payload": "Missing parameters"})
		c.Close()
		return
	}

	// Verify the anonymous name belongs to a submission under this slug
	var org models.Organization
	if err := models.DB.Where("submission_slug = ?", slug).First(&org).Error; err != nil {
		c.WriteJSON(fiber.Map{"type": "error", "payload": "Not found"})
		c.Close()
		return
	}

	var sub models.Submission
	if err := models.DB.Where("anonymous_name = ? AND organization_id = ?", anonName, org.ID).
		First(&sub).Error; err != nil {
		c.WriteJSON(fiber.Map{"type": "error", "payload": "Not found"})
		c.Close()
		return
	}

	subID := sub.ID.String()
	hub := getOrCreateStatusHub(subID)

	client := &statusClient{
		conn: c,
		send: make(chan []byte, 32),
		kill: make(chan struct{}),
	}
	hub.register <- client

	// Send current status immediately
	c.WriteJSON(map[string]string{
		"type":   "status",
		"status": sub.Status,
		"time":   sub.UpdatedAt.Format(time.RFC3339),
	})

	log.Printf("STATUS_WS JOIN: sub=%s", subID)

	// Write pump in background
	go func() {
		for {
			select {
			case msg, ok := <-client.send:
				if !ok {
					return
				}
				if err := c.WriteMessage(websocket.TextMessage, msg); err != nil {
					return
				}
			case <-client.kill:
				return
			}
		}
	}()

	// Read loop (blocks; only receives pings)
	for {
		_, rawMsg, err := c.ReadMessage()
		if err != nil {
			break
		}
		var incoming struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(rawMsg, &incoming); err == nil && incoming.Type == "ping" {
			c.WriteJSON(map[string]string{"type": "pong"})
		}
	}

	log.Printf("STATUS_WS LEAVE: sub=%s", subID)
	hub.unregister <- client
	c.Close()
}
