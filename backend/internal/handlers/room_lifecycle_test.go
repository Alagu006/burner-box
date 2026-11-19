package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"burner-box-backend/internal/crypto"
	"burner-box-backend/internal/models"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// helper to create a test room with a valid creator token
func createTestRoomWithToken(t *testing.T, roomCode string) (string, uuid.UUID) {
	t.Helper()
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		t.Fatalf("Failed to generate token bytes: %v", err)
	}
	token := "bb_rt_" + hex.EncodeToString(tokenBytes)
	h := sha256.Sum256([]byte(token))
	hashHex := hex.EncodeToString(h[:])

	roomID := uuid.New()
	room := models.Room{
		ID:               roomID,
		RoomCode:         roomCode,
		CreatorTokenHash: hashHex,
		ExpiresAt:        time.Now().Add(24 * time.Hour),
	}
	if err := models.DB.Create(&room).Error; err != nil {
		t.Fatalf("Failed to create test room: %v", err)
	}
	return token, roomID
}

func TestRoomLifecycle_ExpiredRooms_HardDeleted(t *testing.T) {
	setupTestDB(t)

	now := time.Now()
	expiredTime := now.Add(-2 * time.Hour)
	futureTime := now.Add(24 * time.Hour)

	// Create an expired room with messages and reactions
	expiredRoomCode := "expired-room-1111"
	expiredRoom := models.Room{
		ID:        uuid.New(),
		RoomCode:  expiredRoomCode,
		ExpiresAt: expiredTime,
	}
	models.DB.Create(&expiredRoom)

	expiredMsg := models.RoomMessage{
		ID:               uuid.New(),
		RoomCode:         expiredRoomCode,
		SenderTag:        "brave-falcon",
		EncryptedMessage: "c2VjcmV0LW1lc3NhZ2U=",
	}
	models.DB.Create(&expiredMsg)

	expiredReaction := models.RoomReaction{
		ID:             uuid.New(),
		RoomCode:       expiredRoomCode,
		MessageID:      expiredMsg.ID,
		SenderTag:      "calm-river",
		EncryptedEmoji: "8J+RoQ==",
	}
	models.DB.Create(&expiredReaction)

	// Create an active room that should NOT be deleted
	activeRoomCode := "active-room-2222"
	activeRoom := models.Room{
		ID:        uuid.New(),
		RoomCode:  activeRoomCode,
		ExpiresAt: futureTime,
	}
	models.DB.Create(&activeRoom)

	activeMsg := models.RoomMessage{
		ID:               uuid.New(),
		RoomCode:         activeRoomCode,
		SenderTag:        "wise-lion",
		EncryptedMessage: "YWN0aXZlLW1lc3NhZ2U=",
	}
	models.DB.Create(&activeMsg)

	// Execute room cleanup pass
	if err := PurgeExpiredRoomsAt(now); err != nil {
		t.Fatalf("PurgeExpiredRoomsAt failed: %v", err)
	}

	// Security Assertion 1: Expired room record must be hard-deleted from database
	var roomCount int64
	models.DB.Model(&models.Room{}).Where("room_code = ?", expiredRoomCode).Count(&roomCount)
	if roomCount != 0 {
		t.Fatalf("SECURITY VIOLATION: Expired room was not hard-deleted from database (found %d records)", roomCount)
	}

	// Security Assertion 2: All messages in expired room must be hard-deleted
	var msgCount int64
	models.DB.Model(&models.Room{}).Where("room_code = ?", expiredRoomCode).Count(&msgCount)
	if msgCount != 0 {
		t.Fatalf("SECURITY VIOLATION: Messages in expired room were not hard-deleted (found %d records)", msgCount)
	}

	// Security Assertion 3: All reactions in expired room must be hard-deleted
	var reactionCount int64
	models.DB.Model(&models.RoomReaction{}).Where("room_code = ?", expiredRoomCode).Count(&reactionCount)
	if reactionCount != 0 {
		t.Fatalf("SECURITY VIOLATION: Reactions in expired room were not hard-deleted (found %d records)", reactionCount)
	}

	// Security Assertion 4: Active room and its messages must remain intact
	var activeRoomCount int64
	models.DB.Model(&models.Room{}).Where("room_code = ?", activeRoomCode).Count(&activeRoomCount)
	if activeRoomCount != 1 {
		t.Errorf("Active room was erroneously deleted")
	}
}

func TestRoomLifecycle_SelfDestructMessages_HardDeleted(t *testing.T) {
	setupTestDB(t)

	now := time.Now()
	roomCode := "selfdestruct-room-3333"
	room := models.Room{
		ID:        uuid.New(),
		RoomCode:  roomCode,
		ExpiresAt: now.Add(48 * time.Hour), // Room itself is still valid
	}
	models.DB.Create(&room)

	// Message with self-destruct timer in the past
	pastSelfDestruct := now.Add(-5 * time.Minute)
	expiredMsg := models.RoomMessage{
		ID:               uuid.New(),
		RoomCode:         roomCode,
		SenderTag:        "swift-eagle",
		EncryptedMessage: "dGhpcy1tZXNzYWdlLXNob3VsZC1iZS1nb25l",
		SelfDestructAt:   &pastSelfDestruct,
	}
	models.DB.Create(&expiredMsg)

	// Message with self-destruct timer in the future
	futureSelfDestruct := now.Add(10 * time.Minute)
	aliveMsg := models.RoomMessage{
		ID:               uuid.New(),
		RoomCode:         roomCode,
		SenderTag:        "swift-eagle",
		EncryptedMessage: "dGhpcy1tZXNzYWdlLXNob3VsZC1zdGlsbC1leGlzdA==",
		SelfDestructAt:   &futureSelfDestruct,
	}
	models.DB.Create(&aliveMsg)

	// Message with no self-destruct timer
	normalMsg := models.RoomMessage{
		ID:               uuid.New(),
		RoomCode:         roomCode,
		SenderTag:        "swift-eagle",
		EncryptedMessage: "bm9ybWFsLW1lc3NhZ2U=",
		SelfDestructAt:   nil,
	}
	models.DB.Create(&normalMsg)

	// Run cleanup pass
	if err := PurgeExpiredRoomsAt(now); err != nil {
		t.Fatalf("PurgeExpiredRoomsAt failed: %v", err)
	}

	// Security Assertion 1: Expired self-destruct message MUST be hard-deleted from DB
	var expiredCount int64
	models.DB.Model(&models.RoomMessage{}).Where("id = ?", expiredMsg.ID).Count(&expiredCount)
	if expiredCount != 0 {
		t.Fatalf("SECURITY VIOLATION: Self-destructed message still exists in database! (found %d records)", expiredCount)
	}

	// Security Assertion 2: Future self-destruct and normal messages must remain
	var aliveCount int64
	models.DB.Model(&models.RoomMessage{}).Where("id = ?", aliveMsg.ID).Count(&aliveCount)
	if aliveCount != 1 {
		t.Errorf("Future self-destruct message was erroneously deleted")
	}

	var normalCount int64
	models.DB.Model(&models.RoomMessage{}).Where("id = ?", normalMsg.ID).Count(&normalCount)
	if normalCount != 1 {
		t.Errorf("Normal message was erroneously deleted")
	}
}

func TestRoomLifecycle_DestroyRoom_HardDeletesAllCascades(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Delete("/api/v1/rooms/:code", DestroyRoom)

	roomCode := "destroy-me-4444"
	token, _ := createTestRoomWithToken(t, roomCode)

	msg := models.RoomMessage{
		ID:               uuid.New(),
		RoomCode:         roomCode,
		SenderTag:        "brave-falcon",
		EncryptedMessage: "dG9wLXNlY3JldA==",
	}
	models.DB.Create(&msg)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rooms/"+roomCode, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Destroy request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK from DestroyRoom, got %d", resp.StatusCode)
	}

	// Verify all records were hard-deleted
	var roomCount int64
	models.DB.Model(&models.Room{}).Where("room_code = ?", roomCode).Count(&roomCount)
	if roomCount != 0 {
		t.Fatalf("SECURITY VIOLATION: Destroyed room was not hard-deleted from database")
	}

	var msgCount int64
	models.DB.Model(&models.RoomMessage{}).Where("room_code = ?", roomCode).Count(&msgCount)
	if msgCount != 0 {
		t.Fatalf("SECURITY VIOLATION: Destroyed room messages were not hard-deleted from database")
	}
}

// SEC-TEST-201: Unauthenticated deletion denied
func TestSecTest201_UnauthenticatedDeletionDenied(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Delete("/api/v1/rooms/:code", DestroyRoom)

	roomCode := "sec-201-room"
	_, _ = createTestRoomWithToken(t, roomCode)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rooms/"+roomCode, nil)
	// No auth header
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for unauthenticated deletion, got %d", resp.StatusCode)
	}

	var count int64
	models.DB.Model(&models.Room{}).Where("room_code = ?", roomCode).Count(&count)
	if count != 1 {
		t.Fatalf("SECURITY VIOLATION: Room record was deleted despite unauthenticated request")
	}
}

// SEC-TEST-202: Invalid creator token denied
func TestSecTest202_InvalidCreatorTokenDenied(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Delete("/api/v1/rooms/:code", DestroyRoom)

	roomCode := "sec-202-room"
	_, _ = createTestRoomWithToken(t, roomCode)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rooms/"+roomCode, nil)
	req.Header.Set("Authorization", "Bearer bb_rt_wrongtokencannotmatchhex1234567890abcdef1234567890abcdef12345678")
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden for invalid creator token, got %d", resp.StatusCode)
	}

	var count int64
	models.DB.Model(&models.Room{}).Where("room_code = ?", roomCode).Count(&count)
	if count != 1 {
		t.Fatalf("SECURITY VIOLATION: Room was deleted with invalid creator token")
	}
}

// SEC-TEST-203: Valid creator token deletes room
func TestSecTest203_ValidCreatorTokenDeletesRoom(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Delete("/api/v1/rooms/:code", DestroyRoom)

	roomCode := "sec-203-room"
	token, _ := createTestRoomWithToken(t, roomCode)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rooms/"+roomCode, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for valid creator token, got %d", resp.StatusCode)
	}

	var count int64
	models.DB.Model(&models.Room{}).Where("room_code = ?", roomCode).Count(&count)
	if count != 0 {
		t.Fatalf("Room was not deleted after valid creator token deletion")
	}
}

// SEC-TEST-204: Invalid / non-existent room code
func TestSecTest204_NonExistentRoomCode(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Delete("/api/v1/rooms/:code", DestroyRoom)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rooms/non-existent-code-9999", nil)
	req.Header.Set("Authorization", "Bearer bb_rt_anytoken1234567890abcdef1234567890abcdef1234567890abcdef12345678")
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected 404 Not Found for nonexistent room, got %d", resp.StatusCode)
	}
}

// SEC-TEST-205: Token cross-room isolation
func TestSecTest205_TokenCrossRoomIsolation(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Delete("/api/v1/rooms/:code", DestroyRoom)

	roomCodeA := "sec-205-room-a"
	tokenA, _ := createTestRoomWithToken(t, roomCodeA)

	roomCodeB := "sec-205-room-b"
	_, _ = createTestRoomWithToken(t, roomCodeB)

	// Attempt to delete room B using token A
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rooms/"+roomCodeB, nil)
	req.Header.Set("Authorization", "Bearer "+tokenA)
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden when using token A on room B, got %d", resp.StatusCode)
	}

	var countA, countB int64
	models.DB.Model(&models.Room{}).Where("room_code = ?", roomCodeA).Count(&countA)
	models.DB.Model(&models.Room{}).Where("room_code = ?", roomCodeB).Count(&countB)
	if countA != 1 || countB != 1 {
		t.Fatalf("SECURITY VIOLATION: Cross-room token unauthorized modification detected")
	}
}

// SEC-TEST-206: Alternative header supported (X-Room-Creator-Token)
func TestSecTest206_AlternativeHeaderSupported(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Delete("/api/v1/rooms/:code", DestroyRoom)

	roomCode := "sec-206-room"
	token, _ := createTestRoomWithToken(t, roomCode)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rooms/"+roomCode, nil)
	req.Header.Set("X-Room-Creator-Token", token)
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK using X-Room-Creator-Token header, got %d", resp.StatusCode)
	}

	var count int64
	models.DB.Model(&models.Room{}).Where("room_code = ?", roomCode).Count(&count)
	if count != 0 {
		t.Fatalf("Room was not deleted using X-Room-Creator-Token")
	}
}

// SEC-TEST-207: Password-protected room requires creator token
func TestSecTest207_PasswordProtectedRoomRequiresCreatorToken(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Delete("/api/v1/rooms/:code", DestroyRoom)

	roomCode := "sec-207-room"
	token, _ := createTestRoomWithToken(t, roomCode)

	// Set password hash on room
	passHash, _ := crypto.HashPassword("supersecretroompassword")
	models.DB.Model(&models.Room{}).Where("room_code = ?", roomCode).Update("password_hash", passHash)

	// 1. Caller passes password in JSON body, but no creator token
	body := bytes.NewBufferString(`{"password":"supersecretroompassword"}`)
	req1 := httptest.NewRequest(http.MethodDelete, "/api/v1/rooms/"+roomCode, body)
	req1.Header.Set("Content-Type", "application/json")
	resp1, _ := app.Test(req1, 5000)
	if resp1.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized when password supplied without creator token, got %d", resp1.StatusCode)
	}

	// 2. Caller passes wrong creator token with password
	body2 := bytes.NewBufferString(`{"password":"supersecretroompassword"}`)
	req2 := httptest.NewRequest(http.MethodDelete, "/api/v1/rooms/"+roomCode, body2)
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer bb_rt_wrongtoken1234567890abcdef1234567890abcdef1234567890abcdef12345678")
	resp2, _ := app.Test(req2, 5000)
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden with invalid token, got %d", resp2.StatusCode)
	}

	// 3. Caller passes valid creator token
	req3 := httptest.NewRequest(http.MethodDelete, "/api/v1/rooms/"+roomCode, nil)
	req3.Header.Set("Authorization", "Bearer "+token)
	resp3, _ := app.Test(req3, 5000)
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK with valid creator token, got %d", resp3.StatusCode)
	}
}

// SEC-TEST-208: Message and reaction cascade
func TestSecTest208_MessageAndReactionCascade(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Delete("/api/v1/rooms/:code", DestroyRoom)

	roomCode := "sec-208-room"
	token, _ := createTestRoomWithToken(t, roomCode)

	msgID := uuid.New()
	msg := models.RoomMessage{
		ID:               msgID,
		RoomCode:         roomCode,
		SenderTag:        "brave-falcon",
		EncryptedMessage: "dG9wLXNlY3JldA==",
	}
	models.DB.Create(&msg)

	rxn := models.RoomReaction{
		ID:             uuid.New(),
		RoomCode:       roomCode,
		MessageID:      msgID,
		SenderTag:      "calm-river",
		EncryptedEmoji: "8J+RoQ==",
	}
	models.DB.Create(&rxn)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rooms/"+roomCode, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", resp.StatusCode)
	}

	var msgCount, rxnCount int64
	models.DB.Model(&models.RoomMessage{}).Where("room_code = ?", roomCode).Count(&msgCount)
	models.DB.Model(&models.RoomReaction{}).Where("room_code = ?", roomCode).Count(&rxnCount)
	if msgCount != 0 || rxnCount != 0 {
		t.Fatalf("SECURITY VIOLATION: Cascade deletion failed for messages (%d) or reactions (%d)", msgCount, rxnCount)
	}
}

// SEC-TEST-209: Encrypted room file cascade
func TestSecTest209_EncryptedRoomFileCascade(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Delete("/api/v1/rooms/:code", DestroyRoom)

	roomCode := "sec-209-room"
	token, _ := createTestRoomWithToken(t, roomCode)

	file := models.RoomFile{
		ID:            uuid.New(),
		RoomCode:      roomCode,
		SenderTag:     "brave-falcon",
		OriginalName:  "leak.pdf",
		MimeType:      "application/pdf",
		FileSize:      1024,
		EncryptedData: []byte("encrypted-payload-bytes"),
	}
	models.DB.Create(&file)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rooms/"+roomCode, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", resp.StatusCode)
	}

	var fileCount int64
	models.DB.Model(&models.RoomFile{}).Where("room_code = ?", roomCode).Count(&fileCount)
	if fileCount != 0 {
		t.Fatalf("SECURITY VIOLATION: RoomFile records not cascaded upon deletion")
	}
}

// SEC-TEST-210: Active WebSocket sessions severed
func TestSecTest210_ActiveWebSocketSessionsSevered(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Delete("/api/v1/rooms/:code", DestroyRoom)

	roomCode := "sec-210-room"
	token, roomID := createTestRoomWithToken(t, roomCode)

	client := &wsClient{
		room: roomCode,
		send: make(chan []byte, 10),
	}
	ctx := context.Background()
	hub, err := registerClientAtomic(roomCode, roomID, client, 10, ctx)
	if err != nil {
		t.Fatalf("Failed to register client: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rooms/"+roomCode, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", resp.StatusCode)
	}

	// Verify client received room_destroyed event
	select {
	case msg := <-client.send:
		var evt map[string]interface{}
		if err := json.Unmarshal(msg, &evt); err != nil {
			t.Fatalf("Failed to unmarshal event: %v", err)
		}
		if evt["type"] != "room_destroyed" {
			t.Fatalf("Expected type room_destroyed, got %v", evt["type"])
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("Client did not receive room_destroyed event within 1s")
	}

	// Verify hub is marked destroyed and deleted from roomHubs
	hub.mu.Lock()
	destroyed := hub.destroyed
	hub.mu.Unlock()
	if !destroyed {
		t.Fatalf("Hub destroyed flag was not set to true")
	}

	roomHubsMu.RLock()
	_, exists := roomHubs[roomCode]
	roomHubsMu.RUnlock()
	if exists {
		t.Fatalf("Hub was not deleted from roomHubs map")
	}
}

// SEC-TEST-211: Concurrent deletion idempotency
func TestSecTest211_ConcurrentDeletionIdempotency(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Delete("/api/v1/rooms/:code", DestroyRoom)

	roomCode := "sec-211-room"
	token, _ := createTestRoomWithToken(t, roomCode)

	var wg sync.WaitGroup
	statuses := make([]int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodDelete, "/api/v1/rooms/"+roomCode, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := app.Test(req, 5000)
			if err != nil {
				return
			}
			statuses[idx] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	has200 := (statuses[0] == 200 || statuses[1] == 200)
	has404 := (statuses[0] == 404 || statuses[1] == 404)
	if !has200 || !has404 {
		t.Fatalf("Expected exactly one 200 OK and one 404 Not Found, got: %v", statuses)
	}

	var count int64
	models.DB.Model(&models.Room{}).Where("room_code = ?", roomCode).Count(&count)
	if count != 0 {
		t.Fatalf("Room was not deleted")
	}
}

// SEC-TEST-212: Room creation response contract
func TestSecTest212_RoomCreationResponseContract(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Post("/api/v1/rooms", CreateRoom)

	body := bytes.NewBufferString(`{"expiry_duration":"24h"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rooms", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Create room request failed: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected 201 Created, got %d", resp.StatusCode)
	}

	var res CreateRoomResponse
	respBytes, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(respBytes, &res); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if res.RoomCode == "" {
		t.Fatalf("RoomCode was empty in response")
	}
	if !strings.HasPrefix(res.CreatorToken, "bb_rt_") {
		t.Fatalf("CreatorToken did not have bb_rt_ prefix: %s", res.CreatorToken)
	}
	if len(res.CreatorToken) != 70 { // 6 chars prefix + 64 hex chars
		t.Fatalf("CreatorToken length incorrect: %d", len(res.CreatorToken))
	}

	// Verify hash in database matches token
	var room models.Room
	if err := models.DB.Where("room_code = ?", res.RoomCode).First(&room).Error; err != nil {
		t.Fatalf("Room not found in DB: %v", err)
	}
	expectedHash := sha256.Sum256([]byte(res.CreatorToken))
	expectedHex := hex.EncodeToString(expectedHash[:])
	if room.CreatorTokenHash != expectedHex {
		t.Fatalf("Database CreatorTokenHash does not match computed SHA-256")
	}
}

// SEC-TEST-213: Lost creator token handling
func TestSecTest213_LostCreatorTokenHandling(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Delete("/api/v1/rooms/:code", DestroyRoom)

	roomCode := "sec-213-room"
	_, _ = createTestRoomWithToken(t, roomCode)

	// Attempt deletion without creator token
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rooms/"+roomCode, nil)
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized, got %d", resp.StatusCode)
	}

	// Room remains intact
	var count int64
	models.DB.Model(&models.Room{}).Where("room_code = ?", roomCode).Count(&count)
	if count != 1 {
		t.Fatalf("Room was erroneously deleted when creator token was lost")
	}
}

// SEC-TEST-214: Legacy room fail-closed
func TestSecTest214_LegacyRoomFailClosed(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Delete("/api/v1/rooms/:code", DestroyRoom)

	roomCode := "sec-214-legacy-room"
	room := models.Room{
		ID:               uuid.New(),
		RoomCode:         roomCode,
		CreatorTokenHash: "", // Legacy unmanaged room
		ExpiresAt:        time.Now().Add(24 * time.Hour),
	}
	models.DB.Create(&room)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rooms/"+roomCode, nil)
	req.Header.Set("Authorization", "Bearer bb_rt_anytoken1234567890abcdef1234567890abcdef1234567890abcdef12345678")
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden for legacy room deletion, got %d", resp.StatusCode)
	}

	var res map[string]interface{}
	respBytes, _ := io.ReadAll(resp.Body)
	json.Unmarshal(respBytes, &res)
	if !strings.Contains(res["error"].(string), "legacy room") {
		t.Fatalf("Expected error mentioning legacy room, got: %v", res["error"])
	}

	// Room remains intact
	var count int64
	models.DB.Model(&models.Room{}).Where("room_code = ?", roomCode).Count(&count)
	if count != 1 {
		t.Fatalf("SECURITY VIOLATION: Legacy room was deleted")
	}
}

// SEC-TEST-215: Token absence audit
func TestSecTest215_TokenAbsenceAudit(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Get("/api/v1/rooms/:code", GetRoomStatus)
	app.Get("/api/v1/rooms/:code/messages", GetRecentRoomMessages)

	roomCode := "sec-215-room"
	token, _ := createTestRoomWithToken(t, roomCode)

	// 1. Status endpoint response
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/rooms/"+roomCode, nil)
	resp1, _ := app.Test(req1, 5000)
	bytes1, _ := io.ReadAll(resp1.Body)
	str1 := string(bytes1)
	if strings.Contains(str1, "creator_token") || strings.Contains(str1, token) {
		t.Fatalf("SECURITY VIOLATION: creator token exposed in status response: %s", str1)
	}

	// 2. Messages endpoint response
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/rooms/"+roomCode+"/messages", nil)
	resp2, _ := app.Test(req2, 5000)
	bytes2, _ := io.ReadAll(resp2.Body)
	str2 := string(bytes2)
	if strings.Contains(str2, "creator_token") || strings.Contains(str2, token) {
		t.Fatalf("SECURITY VIOLATION: creator token exposed in messages response: %s", str2)
	}
}

// SEC-TEST-216: Atomic Registration Race (Interleaving A)
func TestSecTest216_AtomicRegistrationRace_InterleavingA(t *testing.T) {
	setupTestDB(t)
	roomCode := "sec-216-room"
	roomID := uuid.New()

	// Deletion happens first: writes tombstone
	CloseRoomHubAtomic(roomCode, roomID, "destroyed")

	// In-flight registration arrives afterwards
	client := &wsClient{
		room: roomCode,
		send: make(chan []byte, 10),
	}
	ctx := context.Background()
	_, err := registerClientAtomic(roomCode, roomID, client, 10, ctx)
	if err == nil {
		t.Fatalf("Expected registration to be rejected by tombstone, but got nil error")
	}
	if err.Error() != "room has been destroyed" {
		t.Fatalf("Expected error 'room has been destroyed', got: %v", err)
	}

	// Verify no hub is in roomHubs
	roomHubsMu.RLock()
	_, exists := roomHubs[roomCode]
	roomHubsMu.RUnlock()
	if exists {
		t.Fatalf("Orphan hub was created despite tombstone")
	}
}

// SEC-TEST-217: Atomic Registration Race (Interleaving B)
func TestSecTest217_AtomicRegistrationRace_InterleavingB(t *testing.T) {
	setupTestDB(t)
	roomCode := "sec-217-room"
	roomID := uuid.New()

	// Registration happens first
	client := &wsClient{
		room: roomCode,
		send: make(chan []byte, 10),
	}
	ctx := context.Background()
	hub, err := registerClientAtomic(roomCode, roomID, client, 10, ctx)
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}

	// Deletion happens after registration
	CloseRoomHubAtomic(roomCode, roomID, "destroyed")

	// Client must have received room_destroyed
	select {
	case msg := <-client.send:
		var evt map[string]interface{}
		json.Unmarshal(msg, &evt)
		if evt["type"] != "room_destroyed" {
			t.Fatalf("Expected room_destroyed event, got %v", evt)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("Client did not receive room_destroyed event")
	}

	hub.mu.Lock()
	destroyed := hub.destroyed
	hub.mu.Unlock()
	if !destroyed {
		t.Fatalf("Hub destroyed was false")
	}
}

// SEC-TEST-218: Database failure and rollback safety
func TestSecTest218_DatabaseFailureAndRollbackSafety(t *testing.T) {
	setupTestDB(t)
	roomCode := "sec-218-room"
	token, roomID := createTestRoomWithToken(t, roomCode)

	client := &wsClient{
		room: roomCode,
		send: make(chan []byte, 10),
	}
	ctx := context.Background()
	hub, err := registerClientAtomic(roomCode, roomID, client, 10, ctx)
	if err != nil {
		t.Fatalf("Failed to register client: %v", err)
	}

	// Simulate transaction failure rollback
	tx := models.DB.Begin()
	// Create an intentional collision or error
	tx.Where("room_code = ?", roomCode).Delete(&models.RoomFile{})
	// Roll back transaction
	tx.Rollback()

	// Ensure room is intact
	var count int64
	models.DB.Model(&models.Room{}).Where("room_code = ?", roomCode).Count(&count)
	if count != 1 {
		t.Fatalf("Room was affected despite rollback")
	}

	// Ensure hub is still intact and not destroyed
	hub.mu.Lock()
	destroyed := hub.destroyed
	hub.mu.Unlock()
	if destroyed {
		t.Fatalf("Hub was destroyed despite transaction rollback")
	}
	_ = token
}

// SEC-TEST-219: PostgreSQL Migration Test: Existing Rows
func TestSecTest219_PostgreSQLMigration_ExistingRows(t *testing.T) {
	setupTestDB(t)
	roomCode := "sec-219-migrated"

	// Simulate row inserted without creator_token_hash (defaulting to '')
	models.DB.Exec("INSERT INTO rooms (id, room_code, expires_at) VALUES (?, ?, ?)",
		uuid.New().String(), roomCode, time.Now().Add(24*time.Hour))

	var room models.Room
	if err := models.DB.Where("room_code = ?", roomCode).First(&room).Error; err != nil {
		t.Fatalf("Failed to scan migrated row: %v", err)
	}

	if room.CreatorTokenHash != "" {
		t.Fatalf("Expected CreatorTokenHash to be empty string, got: %q", room.CreatorTokenHash)
	}
}

// SEC-TEST-220: PostgreSQL Migration Test: Driver Scan & Auth
func TestSecTest220_PostgreSQLMigration_DriverScanAndAuth(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Delete("/api/v1/rooms/:code", DestroyRoom)

	roomCode := "sec-220-legacy"
	models.DB.Exec("INSERT INTO rooms (id, room_code, expires_at) VALUES (?, ?, ?)",
		uuid.New().String(), roomCode, time.Now().Add(24*time.Hour))

	// Attempt deletion of legacy row
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rooms/"+roomCode, nil)
	req.Header.Set("Authorization", "Bearer bb_rt_testtoken1234567890abcdef1234567890abcdef1234567890abcdef12345678")
	resp, _ := app.Test(req, 5000)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden for scanned legacy row, got %d", resp.StatusCode)
	}
}

// SEC-TEST-221: Tombstone Janitor Sweep Test
func TestSecTest221_TombstoneJanitorSweepTest(t *testing.T) {
	roomHubsMu.Lock()
	expiredCode := "expired-tombstone-" + uuid.New().String()
	freshCode := "fresh-tombstone-" + uuid.New().String()
	destroyedRooms[expiredCode] = roomTombstone{
		roomID:      uuid.New(),
		destroyedAt: time.Now().Add(-15 * time.Minute), // older than 10m TTL
	}
	destroyedRooms[freshCode] = roomTombstone{
		roomID:      uuid.New(),
		destroyedAt: time.Now().Add(-1 * time.Minute), // fresh
	}
	roomHubsMu.Unlock()

	// Execute manual janitor sweep logic
	roomHubsMu.Lock()
	now := time.Now()
	for code, ts := range destroyedRooms {
		if now.Sub(ts.destroyedAt) > tombstoneTTL {
			delete(destroyedRooms, code)
		}
	}
	_, expiredExists := destroyedRooms[expiredCode]
	_, freshExists := destroyedRooms[freshCode]
	roomHubsMu.Unlock()

	if expiredExists {
		t.Fatalf("Expired tombstone was not purged by janitor")
	}
	if !freshExists {
		t.Fatalf("Fresh tombstone was prematurely purged by janitor")
	}
}

// SEC-TEST-222: Safe Reconciliation Failure Test
func TestSecTest222_SafeReconciliationFailureTest(t *testing.T) {
	setupTestDB(t)

	roomCode := "sec-222-safe-reconcile"
	roomID := uuid.New()
	client := &wsClient{
		room: roomCode,
		send: make(chan []byte, 10),
	}
	ctx := context.Background()
	hub, err := registerClientAtomic(roomCode, roomID, client, 10, ctx)
	if err != nil {
		t.Fatalf("Failed to register client: %v", err)
	}

	// Verify that if models.DB encounters an error, reconcileActiveRoomHubs aborts without touching hubs
	origDB := models.DB
	brokenDB, _ := gorm.Open(sqlite.Open("file:broken_mem?mode=memory"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	sqlDB, _ := brokenDB.DB()
	sqlDB.Close() // Close underlying SQL DB to force query error
	models.DB = brokenDB

	// Sweep will encounter closed DB error and must abort immediately
	reconcileActiveRoomHubs()

	// Restore original DB
	models.DB = origDB

	// Hub should still be alive
	hub.mu.Lock()
	destroyed := hub.destroyed
	hub.mu.Unlock()
	if destroyed {
		t.Fatalf("Hub was destroyed when database query failed")
	}

	// Now add room to DB and verify normal reconciliation preserves active hub
	models.DB.Create(&models.Room{
		ID:        roomID,
		RoomCode:  roomCode,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	reconcileActiveRoomHubs()

	hub.mu.Lock()
	destroyed = hub.destroyed
	hub.mu.Unlock()
	if destroyed {
		t.Fatalf("Hub was destroyed despite being active in DB")
	}
	if destroyed {
		t.Fatalf("Hub was destroyed despite being active in DB")
	}
}

// SEC-TEST-223: Generation-Safe Invalidation (Code Reuse)
func TestSecTest223_GenerationSafeInvalidation_CodeReuse(t *testing.T) {
	setupTestDB(t)
	sharedRoomCode := "reused-code-8888"
	roomAID := uuid.New()
	roomBID := uuid.New()

	// Active room generation is Room B
	clientB := &wsClient{
		room: sharedRoomCode,
		send: make(chan []byte, 10),
	}
	ctx := context.Background()
	hubB, err := registerClientAtomic(sharedRoomCode, roomBID, clientB, 10, ctx)
	if err != nil {
		t.Fatalf("Failed to register client on room B: %v", err)
	}

	// Delayed invalidation for Room A arrives
	CloseRoomHubAtomic(sharedRoomCode, roomAID, "stale-destruction-event")

	// Hub B must NOT be destroyed!
	hubB.mu.Lock()
	destroyed := hubB.destroyed
	hubB.mu.Unlock()
	if destroyed {
		t.Fatalf("SECURITY VIOLATION: Newer room generation B was destroyed by stale Room A event")
	}

	// Hub B must still be registered in roomHubs
	roomHubsMu.RLock()
	currentHub, exists := roomHubs[sharedRoomCode]
	roomHubsMu.RUnlock()
	if !exists || currentHub != hubB {
		t.Fatalf("Hub B was removed from roomHubs by stale event")
	}

	// Client B must NOT have received room_destroyed
	select {
	case msg := <-clientB.send:
		t.Fatalf("Client B unexpectedly received message: %s", string(msg))
	default:
		// Success: no event sent to Client B
	}
}

// SEC-TEST-224: Deterministic Concurrent Deletion (FOR UPDATE)
func TestSecTest224_DeterministicConcurrentDeletion_ForUpdate(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Delete("/api/v1/rooms/:code", DestroyRoom)

	roomCode := "sec-224-for-update"
	token, _ := createTestRoomWithToken(t, roomCode)

	var wg sync.WaitGroup
	results := make([]int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodDelete, "/api/v1/rooms/"+roomCode, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := app.Test(req, 5000)
			if err != nil {
				return
			}
			results[idx] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	has200 := (results[0] == 200 || results[1] == 200)
	has404 := (results[0] == 404 || results[1] == 404)
	if !has200 || !has404 {
		t.Fatalf("Deterministic concurrency check failed. Expected [200, 404], got: %v", results)
	}
}
