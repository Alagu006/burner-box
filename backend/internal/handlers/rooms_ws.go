package handlers

import (
	"burner-box-backend/internal/crypto"
	"burner-box-backend/internal/models"
	"context"
	"encoding/json"
	"errors"
	"log"
	"math"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/websocket/v2"
	"github.com/google/uuid"
)

// ---- WebSocket hub per room ----

type wsClient struct {
	conn *websocket.Conn
	room string
	send chan []byte
	kill chan struct{}
}

type wsHub struct {
	roomID     uuid.UUID
	roomCode   string
	clients    map[*wsClient]struct{}
	broadcast  chan []byte
	register   chan *wsClient
	unregister chan *wsClient
	mu         sync.Mutex
	destroyed  bool
}

type roomTombstone struct {
	roomID      uuid.UUID
	destroyedAt time.Time
}

var (
	roomHubs       = make(map[string]*wsHub)
	destroyedRooms = make(map[string]roomTombstone)
	roomHubsMu     sync.RWMutex
)

const (
	MaxJoinHandshakeDuration = 15 * time.Second
	tombstoneTTL             = 10 * time.Minute
)

// registerClientAtomic performs atomic client registration following L1 (roomHubsMu) -> L2 (hub.mu)
func registerClientAtomic(
	roomCode string,
	roomID uuid.UUID,
	client *wsClient,
	maxParticipants int,
	ctx context.Context,
) (*wsHub, error) {
	// 1. Pre-lock context assertion: abort early if join handshake already expired
	if err := ctx.Err(); err != nil {
		return nil, errors.New("join handshake timed out before lock acquisition")
	}

	// 2. Acquire Level 1 Lock: roomHubsMu
	roomHubsMu.Lock()
	defer roomHubsMu.Unlock()

	// 3. Reject if the room generation has been tombstoned
	if ts, isDestroyed := destroyedRooms[roomCode]; isDestroyed {
		if ts.roomID == roomID {
			return nil, errors.New("room has been destroyed")
		}
	}

	// 4. Branch based on existing hub vs new candidate hub
	hub, exists := roomHubs[roomCode]
	isNewHub := false

	if !exists {
		// Construct candidate hub locally in heap memory.
		// DO NOT publish to roomHubs map yet.
		// DO NOT spawn hub.run() goroutine yet.
		hub = &wsHub{
			roomID:     roomID,
			roomCode:   roomCode,
			clients:    make(map[*wsClient]struct{}),
			broadcast:  make(chan []byte, 256),
			register:   make(chan *wsClient),
			unregister: make(chan *wsClient, 64),
			destroyed:  false,
		}
		isNewHub = true
	}

	// 5. Acquire Level 2 Lock: hub.mu while holding roomHubsMu (strictly preserving L1 -> L2)
	hub.mu.Lock()
	defer hub.mu.Unlock()

	// 6. If existing hub, perform state and generation identity validations
	if !isNewHub {
		if hub.destroyed {
			return nil, errors.New("room hub has been destroyed")
		}
		if hub.roomID != roomID {
			return nil, errors.New("room generation mismatch")
		}
		if len(hub.clients) >= maxParticipants {
			return nil, errors.New("room is full")
		}
	}

	// 7. Perform final context expiration check immediately before insertion
	if err := ctx.Err(); err != nil {
		return nil, errors.New("join request expired before registration")
	}

	// 8. Register the client atomically under both locks
	hub.clients[client] = struct{}{}

	// 9. If candidate hub, publish to registry and spawn worker now that registration succeeded
	if isNewHub {
		roomHubs[roomCode] = hub
		go hub.run()
	}

	// 10. Locks released in reverse order (hub.mu then roomHubsMu) via defers
	return hub, nil
}

// CloseRoomHubAtomic severs all WebSocket connections for a room generation under L1 -> L2 locks
func CloseRoomHubAtomic(roomCode string, roomID uuid.UUID, reason string) {
	var clientsToClose []*wsClient

	// 1. Acquire Level 1 Lock: roomHubsMu
	roomHubsMu.Lock()

	hub, exists := roomHubs[roomCode]
	shouldDestroy := false

	if exists && hub != nil {
		// GENERATION SAFETY CHECK:
		// Only remove from map and destroy if hub matches the targeted roomID generation!
		// If hub.roomID != roomID, a newer room generation has reused roomCode.
		// A stale invalidation event for an old room UUID must NEVER destroy a newer room!
		if hub.roomID == roomID {
			delete(roomHubs, roomCode)
			shouldDestroy = true
		} else {
			// Stale invalidation event: harmless NO-OP
			roomHubsMu.Unlock()
			return
		}
	}

	// Record generation tombstone
	destroyedRooms[roomCode] = roomTombstone{
		roomID:      roomID,
		destroyedAt: time.Now(),
	}

	if shouldDestroy {
		// 2. Acquire Level 2 Lock: hub.mu
		hub.mu.Lock()

		// Mark destroyed under lock
		hub.destroyed = true

		// Drain clients into local slice
		clientsToClose = make([]*wsClient, 0, len(hub.clients))
		for client := range hub.clients {
			clientsToClose = append(clientsToClose, client)
			delete(hub.clients, client)
		}

		// Release hub.mu
		hub.mu.Unlock()
	}

	// Release roomHubsMu
	roomHubsMu.Unlock()

	// Clean up revival proposals outside locks
	removeRevivalProposalsForRoom(roomCode)

	// 3. Network I/O outside all locks
	if len(clientsToClose) > 0 {
		outBytes, _ := json.Marshal(map[string]interface{}{
			"type":    "room_destroyed",
			"payload": reason,
		})
		for _, client := range clientsToClose {
			select {
			case client.send <- outBytes:
			default:
			}
			if client.conn != nil {
				client.conn.Close()
			}
		}
	}
}

func (h *wsHub) run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			if !h.destroyed {
				h.clients[client] = struct{}{}
			}
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			// Clean up empty hubs
			if len(h.clients) == 0 {
				roomHubsMu.Lock()
				if currentHub, ok := roomHubs[h.roomCode]; ok && currentHub == h {
					delete(roomHubs, h.roomCode)
				}
				roomHubsMu.Unlock()
				h.mu.Unlock()
				return
			}
			h.mu.Unlock()

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

// broadcastToOthers sends a message to all clients except the sender
func (h *wsHub) broadcastToOthers(exclude *wsClient, message []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for client := range h.clients {
		if client == exclude {
			continue
		}
		select {
		case client.send <- message:
		default:
			close(client.send)
			delete(h.clients, client)
		}
	}
}

// clientCount returns the current number of connected clients
func (h *wsHub) clientCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// broadcastParticipantCount sends participant count to all clients
func (h *wsHub) broadcastParticipantCount(maxParticipants int) {
	count := h.clientCount()
	out := map[string]interface{}{
		"type":             "participant_count",
		"count":            count,
		"max":              maxParticipants,
		"participant_text": formatParticipantText(count, maxParticipants),
	}
	outBytes, _ := json.Marshal(out)
	h.broadcast <- outBytes
}

func formatParticipantText(count, max int) string {
	if count == 1 {
		return "1 of " + itoa(max) + " slots"
	}
	return itoa(count) + " of " + itoa(max) + " slots"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + itoa(-n)
	}
	digits := make([]byte, 0, 10)
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// ---- Room revival proposal tracking (in-memory) ----

type revivalProposal struct {
	ProposalID string          `json:"proposal_id"`
	RoomCode   string          `json:"room_code"`
	ProposedBy string          `json:"proposed_by"` // sender_tag
	Confirmed  map[string]bool `json:"-"`           // sender_tag -> confirmed
	CreatedAt  time.Time       `json:"created_at"`
}

var (
	revivalProposals   = make(map[string]*revivalProposal) // proposalID -> proposal
	revivalProposalsMu sync.Mutex
)

func newRevivalProposal(roomCode, proposedBy string) *revivalProposal {
	id := generateProposalID()
	p := &revivalProposal{
		ProposalID: id,
		RoomCode:   roomCode,
		ProposedBy: proposedBy,
		Confirmed:  make(map[string]bool),
		CreatedAt:  time.Now(),
	}
	p.Confirmed[proposedBy] = true // proposer auto-confirms
	revivalProposalsMu.Lock()
	revivalProposals[id] = p
	revivalProposalsMu.Unlock()
	return p
}

func getRevivalProposal(id string) *revivalProposal {
	revivalProposalsMu.Lock()
	defer revivalProposalsMu.Unlock()
	return revivalProposals[id]
}

func removeRevivalProposal(id string) {
	revivalProposalsMu.Lock()
	delete(revivalProposals, id)
	revivalProposalsMu.Unlock()
}

func removeRevivalProposalsForRoom(roomCode string) {
	revivalProposalsMu.Lock()
	defer revivalProposalsMu.Unlock()
	for id, p := range revivalProposals {
		if p.RoomCode == roomCode {
			delete(revivalProposals, id)
		}
	}
}

func generateProposalID() string {
	b := make([]byte, 8)
	time.Now().UnixNano()
	// Use time-based pseudo-random (not crypto — this is just a display ID)
	t := time.Now().UnixNano()
	for i := range b {
		b[i] = byte(t >> (uint(i) * 8))
	}
	// Add some randomness from the timer
	b[0] ^= byte(time.Now().UnixNano() & 0xff)
	b[7] ^= byte(time.Now().UnixNano() >> 40 & 0xff)
	s := ""
	for _, v := range b {
		s += string([]byte{hexChar(v >> 4), hexChar(v & 0xf)})
	}
	return s
}

func hexChar(b byte) byte {
	if b < 10 {
		return '0' + b
	}
	return 'a' + b - 10
}

// ---- WebSocket message types ----

type wsIncoming struct {
	Type string `json:"type"` // "message", "ping", "typing", "reaction", "propose_revival", "confirm_revival", "reject_revival"
}

type wsOutgoing struct {
	Type      string `json:"type"` // "message", "error", "system", "typing", "reaction", "participant_count", "revival_proposal", "revival_result"
	SenderTag string `json:"sender_tag,omitempty"`
	Payload   string `json:"payload,omitempty"` // encrypted ciphertext
	Meta      string `json:"meta,omitempty"`    // encryption metadata
	MessageID string `json:"message_id,omitempty"`
	TTL       int    `json:"ttl,omitempty"` // self-destruct seconds (echo back for UI)
	CreatedAt string `json:"created_at,omitempty"`
}

type wsRoomMessage struct {
	ID               string  `json:"id"`
	RoomCode         string  `json:"room_code"`
	SenderTag        string  `json:"sender_tag"`
	EncryptedMessage string  `json:"encrypted_message"`
	EncryptionMeta   string  `json:"encryption_meta"`
	SelfDestructAt   *string `json:"self_destruct_at,omitempty"`
	CreatedAt        string  `json:"created_at"`
}

// ---- JoinRoom WebSocket endpoint ----

func JoinRoom(c *websocket.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), MaxJoinHandshakeDuration)
	defer cancel()

	code := c.Params("code")
	if code == "" {
		c.WriteJSON(fiber.Map{"type": "error", "payload": "Room code required"})
		c.Close()
		return
	}

	// Look up room
	var room models.Room
	if err := models.DB.Where("room_code = ?", code).First(&room).Error; err != nil {
		c.WriteJSON(fiber.Map{"type": "error", "payload": "Room not found"})
		c.Close()
		return
	}

	if room.IsExpired() || room.IsDestroyed() {
		c.WriteJSON(fiber.Map{"type": "error", "payload": "Room is no longer available"})
		c.Close()
		return
	}

	// Check password if room is protected
	password := c.Query("password")
	if room.PasswordHash != "" {
		if password == "" {
			c.WriteJSON(fiber.Map{"type": "error", "payload": "Password required"})
			c.Close()
			return
		}
		ok, err := crypto.VerifyPassword(password, room.PasswordHash)
		if err != nil || !ok {
			c.WriteJSON(fiber.Map{"type": "error", "payload": "Invalid password"})
			c.Close()
			return
		}
	}

	// Generate anonymous sender tag
	senderTag := models.GenerateSenderTag()

	// Register client atomically under strict L1 -> L2 locks
	client := &wsClient{
		conn: c,
		room: code,
		send: make(chan []byte, 256),
		kill: make(chan struct{}),
	}

	hub, err := registerClientAtomic(code, room.ID, client, room.MaxParticipants, ctx)
	if err != nil {
		c.WriteJSON(fiber.Map{"type": "error", "payload": err.Error()})
		c.Close()
		return
	}
	log.Printf("ROOM_WS JOIN: room=%s tag=%s", code, senderTag)

	// Send join confirmation with sender tag and expiry info
	c.WriteJSON(fiber.Map{
		"type":             "system",
		"payload":          "You joined as " + senderTag,
		"sender_tag":       senderTag,
		"expires_at":       room.ExpiresAt.Format(time.RFC3339),
		"max_participants": room.MaxParticipants,
	})

	// Broadcast updated participant count to all clients
	hub.broadcastParticipantCount(room.MaxParticipants)

	// Send recent message history (last 50 messages)
	var history []models.RoomMessage
	models.DB.Where("room_code = ?", code).
		Order("created_at DESC").
		Limit(50).
		Find(&history)

	// Reverse so oldest first
	for i, j := 0, len(history)-1; i < j; i, j = i+1, j-1 {
		history[i], history[j] = history[j], history[i]
	}

	for _, msg := range history {
		out := wsOutgoing{
			Type:      "message",
			SenderTag: msg.SenderTag,
			Payload:   msg.EncryptedMessage,
			Meta:      msg.EncryptionMeta,
			MessageID: msg.ID.String(),
			CreatedAt: msg.CreatedAt.Format(time.RFC3339),
		}
		if msg.SelfDestructAt != nil {
			remaining := int(time.Until(*msg.SelfDestructAt).Seconds())
			if remaining > 0 {
				out.TTL = remaining
			}
		}
		c.WriteJSON(out)
	}

	// Write pump (sender) — runs in background goroutine
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

	// Read loop — MUST block in the main handler goroutine.
	// gofiber/websocket closes the connection when the handler returns.
	for {
		_, rawMsg, err := c.ReadMessage()
		if err != nil {
			break
		}

		var incoming wsIncoming
		if err := json.Unmarshal(rawMsg, &incoming); err != nil {
			continue
		}

		switch incoming.Type {
		case "message":
			// Parse the full message to extract encrypted fields
			var msg struct {
				Type    string `json:"type"`
				Payload string `json:"payload"`
				Meta    string `json:"meta"`
				TTL     int    `json:"ttl"`
			}
			if err := json.Unmarshal(rawMsg, &msg); err != nil {
				continue
			}

			if msg.Payload == "" {
				continue
			}

			// Compute SelfDestructAt if TTL provided
			var selfDestructAt *time.Time
			if msg.TTL > 0 {
				t := time.Now().Add(time.Duration(msg.TTL) * time.Second)
				selfDestructAt = &t
			}

			// Persist encrypted message to DB
			roomMsg := models.RoomMessage{
				RoomCode:         code,
				SenderTag:        senderTag,
				EncryptedMessage: msg.Payload,
				EncryptionMeta:   msg.Meta,
				SelfDestructAt:   selfDestructAt,
			}

			if err := models.DB.Create(&roomMsg).Error; err != nil {
				log.Printf("Room %s: failed to persist message: %v", code, err)
				continue
			}

			// Broadcast to all clients in room
			out := wsOutgoing{
				Type:      "message",
				SenderTag: senderTag,
				Payload:   msg.Payload,
				Meta:      msg.Meta,
				MessageID: roomMsg.ID.String(),
				TTL:       msg.TTL,
				CreatedAt: roomMsg.CreatedAt.Format(time.RFC3339),
			}
			outBytes, _ := json.Marshal(out)
			hub.broadcast <- outBytes

		case "typing":
			// Parse and relay typing indicator to all OTHER clients
			var typingMsg struct {
				Type        string `json:"type"`
				DisplayName string `json:"display_name"`
			}
			if err := json.Unmarshal(rawMsg, &typingMsg); err != nil {
				continue
			}
			if typingMsg.DisplayName == "" {
				continue
			}
			out := map[string]interface{}{
				"type":         "typing",
				"sender_tag":   senderTag,
				"display_name": typingMsg.DisplayName,
			}
			outBytes, _ := json.Marshal(out)
			hub.broadcastToOthers(client, outBytes)

		case "reaction":
			// Parse and persist encrypted reaction
			var reactionMsg struct {
				Type      string `json:"type"`
				MessageID string `json:"message_id"`
				Payload   string `json:"payload"` // encrypted emoji
				Meta      string `json:"meta"`
			}
			if err := json.Unmarshal(rawMsg, &reactionMsg); err != nil {
				continue
			}
			if reactionMsg.Payload == "" || reactionMsg.MessageID == "" {
				continue
			}

			// Validate message exists
			msgID, err := uuid.Parse(reactionMsg.MessageID)
			if err != nil {
				continue
			}

			reaction := models.RoomReaction{
				RoomCode:       code,
				MessageID:      msgID,
				SenderTag:      senderTag,
				EncryptedEmoji: reactionMsg.Payload,
				EncryptionMeta: reactionMsg.Meta,
			}

			if err := models.DB.Create(&reaction).Error; err != nil {
				log.Printf("Room %s: failed to persist reaction: %v", code, err)
				continue
			}

			// Broadcast reaction to all clients in room
			out := map[string]interface{}{
				"type":        "reaction",
				"sender_tag":  senderTag,
				"message_id":  reactionMsg.MessageID,
				"payload":     reactionMsg.Payload,
				"meta":        reactionMsg.Meta,
				"reaction_id": reaction.ID.String(),
				"created_at":  reaction.CreatedAt.Format(time.RFC3339),
			}
			outBytes, _ := json.Marshal(out)
			hub.broadcast <- outBytes

		case "propose_revival":
			// Create a revival proposal
			proposal := newRevivalProposal(code, senderTag)
			currentCount := hub.clientCount()

			out := map[string]interface{}{
				"type":          "revival_proposal",
				"proposal_id":   proposal.ProposalID,
				"proposed_by":   senderTag,
				"confirmations": 1,
				"required":      int(math.Ceil(float64(currentCount) / 2.0)),
				"total":         currentCount,
			}
			outBytes, _ := json.Marshal(out)
			hub.broadcast <- outBytes
			log.Printf("ROOM_REVIVAL: room=%s proposed_by=%s id=%s", code, senderTag, proposal.ProposalID)

		case "confirm_revival":
			var confirmMsg struct {
				Type       string `json:"type"`
				ProposalID string `json:"proposal_id"`
			}
			if err := json.Unmarshal(rawMsg, &confirmMsg); err != nil {
				continue
			}

			proposal := getRevivalProposal(confirmMsg.ProposalID)
			if proposal == nil || proposal.RoomCode != code {
				c.WriteJSON(fiber.Map{"type": "error", "payload": "Invalid or expired proposal"})
				continue
			}

			proposal.Confirmed[senderTag] = true
			confirmations := len(proposal.Confirmed)
			currentCount := hub.clientCount()
			required := int(math.Ceil(float64(currentCount) / 2.0))

			if confirmations >= required {
				// Majority reached — extend room expiry
				var r models.Room
				if err := models.DB.Where("room_code = ?", code).First(&r).Error; err == nil {
					// Extend by the time already elapsed since creation (minimum 1h)
					elapsed := time.Since(r.CreatedAt)
					if elapsed < time.Hour {
						elapsed = time.Hour
					}
					newExpiry := time.Now().Add(elapsed)
					models.DB.Model(&r).Update("expires_at", newExpiry)

					out := map[string]interface{}{
						"type":          "revival_result",
						"proposal_id":   confirmMsg.ProposalID,
						"accepted":      true,
						"new_expires":   newExpiry.Format(time.RFC3339),
						"confirmations": confirmations,
					}
					outBytes, _ := json.Marshal(out)
					hub.broadcast <- outBytes
					log.Printf("ROOM_REVIVAL: room=%s ACCEPTED new_expiry=%v", code, newExpiry)
				}
				removeRevivalProposal(confirmMsg.ProposalID)
			} else {
				// Broadcast updated confirmation count
				out := map[string]interface{}{
					"type":          "revival_proposal",
					"proposal_id":   confirmMsg.ProposalID,
					"proposed_by":   proposal.ProposedBy,
					"confirmations": confirmations,
					"required":      required,
					"total":         currentCount,
					"confirmed_by":  senderTag,
				}
				outBytes, _ := json.Marshal(out)
				hub.broadcast <- outBytes
			}

		case "reject_revival":
			var rejectMsg struct {
				Type       string `json:"type"`
				ProposalID string `json:"proposal_id"`
			}
			if err := json.Unmarshal(rawMsg, &rejectMsg); err != nil {
				continue
			}

			proposal := getRevivalProposal(rejectMsg.ProposalID)
			if proposal == nil || proposal.RoomCode != code {
				continue
			}

			// Any participant can cancel the proposal
			removeRevivalProposal(rejectMsg.ProposalID)
			out := map[string]interface{}{
				"type":        "revival_result",
				"proposal_id": rejectMsg.ProposalID,
				"accepted":    false,
				"rejected_by": senderTag,
			}
			outBytes, _ := json.Marshal(out)
			hub.broadcast <- outBytes
			log.Printf("ROOM_REVIVAL: room=%s REJECTED by=%s", code, senderTag)

		case "file":
			// File upload notification — broadcast to all OTHER clients (sender shows locally)
			var fileMsg struct {
				Type         string `json:"type"`
				FileID       string `json:"file_id"`
				OriginalName string `json:"original_name"`
				MimeType     string `json:"mime_type"`
				FileSize     int64  `json:"file_size"`
				Meta         string `json:"meta"`
			}
			if err := json.Unmarshal(rawMsg, &fileMsg); err != nil {
				continue
			}
			if fileMsg.FileID == "" {
				continue
			}
			out := map[string]interface{}{
				"type":          "file",
				"sender_tag":    senderTag,
				"file_id":       fileMsg.FileID,
				"original_name": fileMsg.OriginalName,
				"mime_type":     fileMsg.MimeType,
				"file_size":     fileMsg.FileSize,
				"meta":          fileMsg.Meta,
				"created_at":    time.Now().Format(time.RFC3339),
			}
			outBytes, _ := json.Marshal(out)
			hub.broadcastToOthers(client, outBytes)

		case "ping":
			c.WriteJSON(wsOutgoing{Type: "system", Payload: "pong"})
		}
	}

	// Cleanup when read loop exits (client disconnected or error)
	log.Printf("ROOM_WS LEAVE: room=%s tag=%s", code, senderTag)
	select {
	case hub.unregister <- client:
	default:
	}
	hub.broadcastParticipantCount(room.MaxParticipants)
	c.Close()
}

func startTombstoneJanitor(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Minute)
	go func() {
		for {
			select {
			case <-ticker.C:
				roomHubsMu.Lock()
				now := time.Now()
				for code, ts := range destroyedRooms {
					if now.Sub(ts.destroyedAt) > tombstoneTTL {
						delete(destroyedRooms, code)
					}
				}
				roomHubsMu.Unlock()
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

func reconcileActiveRoomHubs() {
	roomHubsMu.RLock()
	if len(roomHubs) == 0 {
		roomHubsMu.RUnlock()
		return
	}
	type hubSnapshot struct {
		code string
		id   uuid.UUID
	}
	snapshots := make([]hubSnapshot, 0, len(roomHubs))
	codes := make([]string, 0, len(roomHubs))
	for code, hub := range roomHubs {
		if hub != nil {
			snapshots = append(snapshots, hubSnapshot{code: code, id: hub.roomID})
			codes = append(codes, code)
		}
	}
	roomHubsMu.RUnlock()

	var existingRooms []struct {
		RoomCode string    `gorm:"column:room_code"`
		ID       uuid.UUID `gorm:"column:id"`
	}
	err := models.DB.Table("rooms").Select("room_code, id").Where("room_code IN ?", codes).Scan(&existingRooms).Error
	if err != nil {
		log.Printf("[RECONCILER] Query error during reconciliation: %v. Aborting pass.", err)
		return
	}

	activeMap := make(map[string]uuid.UUID, len(existingRooms))
	for _, r := range existingRooms {
		activeMap[r.RoomCode] = r.ID
	}

	for _, snap := range snapshots {
		dbID, exists := activeMap[snap.code]
		if !exists || dbID != snap.id {
			log.Printf("[RECONCILER] Room %s (ID %s) not found in DB. Closing hub.", snap.code, snap.id)
			CloseRoomHubAtomic(snap.code, snap.id, "reconcile")
		}
	}
}

func startRoomReconciler(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				reconcileActiveRoomHubs()
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

// StartRoomLifecycleWorkers starts the background tombstone janitor and reconciler
func StartRoomLifecycleWorkers() {
	ctx := context.Background()
	startTombstoneJanitor(ctx)
	startRoomReconciler(ctx)
}

// GetRecentRoomMessages returns recent messages for a room (REST fallback)
func GetRecentRoomMessages(c *fiber.Ctx) error {
	code := c.Params("code")
	if code == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Room code required"})
	}

	var room models.Room
	if err := models.DB.Where("room_code = ?", code).First(&room).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Room not found"})
	}

	if room.IsExpired() || room.IsDestroyed() {
		return c.Status(410).JSON(fiber.Map{"error": "Room is no longer available"})
	}

	var messages []models.RoomMessage
	models.DB.Where("room_code = ?", code).
		Order("created_at DESC").
		Limit(100).
		Find(&messages)

	// Reverse
	for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
		messages[i], messages[j] = messages[j], messages[i]
	}

	// Convert to safe output (strip any unneeded fields)
	result := make([]wsRoomMessage, 0, len(messages))
	for _, msg := range messages {
		rm := wsRoomMessage{
			ID:               msg.ID.String(),
			RoomCode:         msg.RoomCode,
			SenderTag:        msg.SenderTag,
			EncryptedMessage: msg.EncryptedMessage,
			EncryptionMeta:   msg.EncryptionMeta,
			CreatedAt:        msg.CreatedAt.Format(time.RFC3339),
		}
		if msg.SelfDestructAt != nil {
			s := msg.SelfDestructAt.Format(time.RFC3339)
			rm.SelfDestructAt = &s
		}
		result = append(result, rm)
	}

	return c.Status(200).JSON(fiber.Map{
		"messages": result,
	})
}
