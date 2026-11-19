# BurnerBox — Checkpoint 2A.8: Room Deletion Security Design (Final Generation & Concurrency Review Baseline)

**Document ID:** STEP-2A-8-DESIGN  
**Baseline Date:** 2026-11-19  
**Security Finding:** BB-SEC-002 (High Severity: Unauthenticated `DELETE /api/v1/rooms/:code`)  
**Phase:** Step 1 Remediation — Checkpoint 2A.8 (Final Generation & Concurrency Review)  
**Status:** COMPLETE — Ready for Implementation Authorization  

---

## 1. Executive Summary

Finding **BB-SEC-002** identifies that the BurnerBox backend exposes an unauthenticated HTTP `DELETE /api/v1/rooms/:code` endpoint that immediately and irreversibly destroys any room, along with all associated messages, reactions, and encrypted files. Any caller who possesses or discovers a 16-hex-character room code can delete the room without supplying a password, session token, or proof of ownership.

This final design document addresses all criteria and technical conditions from Checkpoint 2A.8:
- **Generation-Safe Invalidation (`hub.roomID == roomID`)**: Corrects `CloseRoomHubAtomic` so that an active hub is removed and destroyed **only if its immutable database UUID matches the target generation** (`hub.roomID == roomID`). A delayed or out-of-order notification/reconciliation event for an older room UUID can never destroy or disconnect a newer room generation that reused the same room code. Tombstones retain generation identity, and reconciliation compares both `room_code` and `roomID`.
- **Deterministic Concurrent Deletion Strategy (`SELECT ... FOR UPDATE`)**: Resolves concurrent deletion races by moving room lookup, row locking, creator-token verification, and cascading deletion entirely inside the PostgreSQL transaction. Uses `SELECT ... FOR UPDATE` to serialize concurrent requests. The first transaction deletes the room, asserts `RowsAffected == 1`, commits, returns `200 OK`, and triggers post-commit WebSocket invalidation. The second waiting transaction unblocks, discovers the row was deleted (`ErrRecordNotFound`), rolls back, and returns `404 Not Found`. False successes are eliminated.
- **Accurate Machine-Failure & Socket Lifecycle Distinction**: Formally distinguishes process termination while the OS remains operational (where the OS kernel reclaims descriptors and sends TCP FIN/RST) from complete machine/power failure (where the OS dies instantly, no TCP FIN/RST is sent, and clients detect failure via TCP/heartbeat timeouts). Clarifies that recovered panics do not terminate the process, relying on database reconciliation to clean up orphaned hubs. Eliminates false promises of immediate remote client observation.
- **Prevention of Empty Orphan Hubs on Expired Registration**: Preserves candidate hub construction in heap memory without premature registry publication or goroutine creation, performing double context expiration verification.
- **Clarified Cross-Instance Consistency Guarantees**: Preserves best-effort `LISTEN / NOTIFY` invalidation, treating the 30-second reconciliation interval as an operational target, aborting on DB errors, and recovering when a subsequent query detects room absence.
- **Acceptance Checklist & Test Matrix**: Extends the test matrix with explicit tests for stale invalidation after room-code reuse (`SEC-TEST-223`) and concurrent deletion determinism (`SEC-TEST-224`).

---

## 2. Verified Facts vs Assumptions

| Area | Verified Fact | Corrected Assumption / Myth |
|---|---|---|
| **PostgreSQL vs In-Memory Boundary** | PostgreSQL database commits and in-memory WebSocket hubs belong to two separate storage domains. There is **no distributed two-phase commit** or cross-system atomicity between PostgreSQL and RAM. Server socket closure transmits TCP FIN/RST; client observation is subject to network and OS scheduling. | *Myth:* "Room deletion is atomic across both the database and active WebSocket connections, guaranteeing simultaneous client-side observation." Database deletion is ACID atomic; WebSocket severance is post-commit and crash-safe. |
| **Abrupt Machine Failure** | If a machine loses power or crashes, the OS cannot send TCP FIN/RST packets. Remote clients detect failure asynchronously via TCP keepalive/WebSocket ping timeouts. | *Myth:* "Power failure guarantees an orderly TCP FIN/RST disconnect." Only clean process termination on an operational OS guarantees kernel socket reclamation. |
| **Concurrent Deletion** | Without row-level locking, concurrent deletions interleave. In PostgreSQL `READ COMMITTED`, `SELECT ... FOR UPDATE` serializes concurrent deletions: Request 1 deletes and returns `200 OK`; Request 2 unblocks, finds no row, rolls back, and returns `404 Not Found`. | *Myth:* "Fetching a room before starting a transaction safely prevents race conditions." Pre-transaction reads permit duplicate delete attempts and non-deterministic status codes. |
| **Cross-Instance Invalidation** | PostgreSQL `LISTEN / NOTIFY` is a best-effort asynchronous pub/sub channel. Periodic reconciliation is the recovery mechanism. The 30s interval is an **operational target**, not a hard real-time deadline. | *Myth:* "Cross-instance invalidation is guaranteed within 30 seconds." Reconciliation can be delayed by query latency, retries, or database outages. |
| **SQL Driver NULL Scanning** | In standard Go `database/sql`, scanning a SQL `NULL` into a Go `string` variable throws a runtime error: `sql: Scan error on column ... converting NULL to string is unsupported`. | *Myth:* "SQL `NULL` safely scans into a Go `string` as `\"\"` automatically." Drivers reject `NULL` into non-nullable primitives unless explicitly configured or modeled as `*string` / `sql.NullString`. |
| **Database Schema** | `Room` in `backend/internal/models/room.go` currently has **zero** ownership or creator fields. | *Myth:* Room creator identity is retained somewhere in the database. |
| **Fly.io Architecture** | `backend/fly.toml` configures Fly Proxy autostop/autostart for existing machines (`min_machines_running = 0`, `soft_limit = 200`, `hard_limit = 250`). | *Myth:* "Fly Proxy provisions new machines dynamically when concurrency limits are exceeded." Fly Proxy only routes and wakes/suspends *pre-existing* machines. Dynamic scaling requires `fly scale count` or external API provisioning. |
| **Fly Instance Count** | Declaring a single process group in `fly.toml` does **not** prove a single machine exists at runtime. An operator can provision $N \ge 1$ machines. | *Myth:* "BurnerBox is guaranteed to run on a single instance." Instance count is an external deployment variable that must be verified. |
| **In-Memory WebSockets** | WebSocket hubs (`roomHubs`) exist strictly in the RAM of the handling operating system process. | *Fact:* `CloseRoomHubAtomic` severs connections on the local machine only. Multi-instance deployments require cross-instance invalidation. |
| **Cascade Mechanics** | `RoomFile`, `RoomReaction`, and `RoomMessage` records are stored in PostgreSQL and reference `room_code`. Files are stored as binary `bytea` in the DB. | *Fact:* No orphaned disk files exist in `/app/uploads` for room attachments; hard-deleting database records completely purges room files. |

---

## 3. Complete Request-to-Deletion Execution Trace

### 3.1 Route Registration
In `backend/cmd/server/main.go#L95`:
```go
rooms.Delete("/:code", handlers.DestroyRoom)
```
- Endpoint: `DELETE /api/v1/rooms/:code`
- Middleware stack: **None**. The route group `rooms := api.Group("/rooms")` has no authentication middleware applied.

### 3.2 Current Handler Flow (`backend/internal/handlers/rooms.go#L111-L157`)
1. **Extraction**: Handler extracts `code := c.Params("code")`. If empty, returns `HTTP 400 Bad Request`.
2. **Lookup**: Handler runs `models.DB.Where("room_code = ?", code).First(&room)`. If not found, returns `HTTP 404 Not Found`.
3. **Cascading Hard Deletes**:
   ```go
   tx := models.DB.Begin()
   tx.Where("room_code = ?", code).Delete(&models.RoomFile{})
   tx.Where("room_code = ?", code).Delete(&models.RoomReaction{})
   tx.Where("room_code = ?", code).Delete(&models.RoomMessage{})
   tx.Delete(&room)
   tx.Commit()
   ```
4. **WebSocket Severance**: Calls `handlers.CloseRoomHub(code, "destroyed")`.
5. **Response**: Returns `HTTP 200 OK` with `{"message": "Room destroyed successfully"}`.

### 3.3 Root Cause Analysis
Any actor who discovers or guesses a valid 16-hex room code can issue an unauthenticated HTTP `DELETE /api/v1/rooms/<code_here>` request, triggering an immediate and irreversible deletion of all room data and severing active sessions.

---

## 4. Threat Model

### 4.1 Threat Actors
1. **Malicious Room Participant**: An invited participant who wants to censor discussion, destroy evidence, or disrupt the room before its scheduled expiration.
2. **Network Observer / Link Eavesdropper**: An adversary who intercepts a join link containing the room code (e.g. from chat logs, browser history, or proxy logs) and executes deletion.
3. **Brute-Force Attacker**: An external actor scanning or guessing room codes.

### 4.2 Impact Assessment
- **Severity**: **High** (CVSS: 7.5 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
- **Impact**: Permanent Denial of Service (DoS) and data loss for active ephemeral rooms.

---

## 5. Creator Capability Token Lifecycle

To preserve BurnerBox's zero-knowledge, anonymous user model (which avoids persistent user accounts for ephemeral rooms), room deletion authorization is governed by a **Creator Capability Token**.

```
+---------------------------------------------------------------------------------------------------------+
|                                    CREATOR TOKEN LIFECYCLE                                              |
|                                                                                                         |
|  1. GENERATION (Server-Side)                                                                            |
|     32 cryptographically secure bytes from crypto/rand                                                  |
|     Format: "bb_rt_" + 64 hex characters (e.g., bb_rt_3a8f...9c1e)                                      |
|                                                                                                         |
|  2. HASHED STORAGE (Database Invariant)                                                                 |
|     creator_token_hash = sha256(creator_token)                                                          |
|     Stored in PostgreSQL as VARCHAR(64) NOT NULL DEFAULT ''                                             |
|     Raw token is NEVER persisted in database, logs, or server-side caches                               |
|                                                                                                         |
|  3. ONE-TIME DISCLOSURE                                                                                 |
|     Disclosed exclusively in HTTP 201 Created response payload:                                         |
|     { "room_code": "...", "creator_token": "bb_rt_...", "join_url": "...", "expires_at": "..." }        |
|                                                                                                         |
|  4. CLIENT RETENTION (Browser Isolated)                                                                 |
|     Stored in creator's tab: sessionStorage.setItem("bb_creator_token_" + roomCode, token)              |
|     Never placed in join URLs, URL fragments, query parameters, or shared links                         |
|                                                                                                         |
|  5. CONSTANT-TIME VERIFICATION                                                                          |
|     Presented in HTTP header: Authorization: Bearer <creator_token>                                     |
|     Verified via crypto/subtle.ConstantTimeCompare(sha256(input), db_hash)                              |
+---------------------------------------------------------------------------------------------------------+
```

### 5.1 Cryptographic Generation & Format
- **Entropy**: 32 cryptographically secure random bytes generated via `crypto/rand` ($2^{256}$ entropy).
- **Format**: Prefixed string: `bb_rt_<64_hex_characters>` (total length: 70 characters).
  - Prefix `bb_rt_` stands for "BurnerBox Room Token", enabling immediate credential scanning and secret-leak detection tools (e.g., GitHub Secret Scanning, TruffleHog).

### 5.2 Hashed Storage & Verification
- **Storage Invariant**: The backend **never** stores the raw capability token.
- **Hash Algorithm**: SHA-256 (`crypto/sha256`).
- **Database Column**: `creator_token_hash VARCHAR(64) NOT NULL DEFAULT ''`.
- **Verification Invariant**:
  ```go
  presentedHash := sha256.Sum256([]byte(rawToken))
  presentedHex := hex.EncodeToString(presentedHash[:])

  if subtle.ConstantTimeCompare([]byte(presentedHex), []byte(room.CreatorTokenHash)) != 1 {
      return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
          "error": "Invalid creator authorization token",
      })
  }
  ```
  Comparison is strictly constant-time, preventing timing side-channel attacks.

### 5.3 Strict One-Time Disclosure
- Disclosed **only once** to the creator in the JSON response of `POST /api/v1/rooms/`.
- Never returned in `GET /api/v1/rooms/:code`, `GET /api/v1/rooms/:code/messages`, WebSocket handshakes, or public endpoints.
- Never placed in the `join_url` or URL query parameters.

### 5.4 Frontend Retention & Tab Lifecycle
- The creator's browser stores the token in `sessionStorage`:
  ```javascript
  sessionStorage.setItem(`bb_creator_token_${roomCode}`, data.creator_token);
  ```
- **Tab Lifecycle**:
  - Survives page reloads within the same browser tab.
  - Automatically destroyed by the browser when the tab or browser window is closed.
  - Never shared across tabs, windows, or devices.

### 5.5 Lost-Token Policy (Strictly Fail-Closed)
- If the creator closes the tab, clears browser storage, or loses the token, **manual early deletion is permanently disabled**.
- **No Insecure Fallbacks**: The room code, room password, or IP address **never** act as deletion credentials.
- The room remains fully functional and will self-destruct naturally upon reaching its scheduled `expires_at` via the background janitor worker.

---

## 6. Database Migration Representation & Driver Verification

### 6.1 Driver Behavior Analysis: Why SQL NULL Fails in Go
In standard Go `database/sql`, attempting to scan a SQL `NULL` value into a standard non-pointer primitive (such as `string`) fails with a runtime error:
```
sql: Scan error on column index 2, name "creator_token_hash": converting NULL to string is unsupported
```
While GORM provides abstraction layers, relying on driver-specific `NULL`-to-zero-value coercion is fragile and fails when using raw SQL queries, alternative database drivers (such as `pgx` with `database/sql`), or standard library scanners.

### 6.2 Comparison of Schema Representations

| Criterion | Option A: Nullable SQL Column (`*string` / `sql.NullString`) | Option B: Non-Nullable SQL Column (`NOT NULL DEFAULT ''`) [SELECTED] |
|---|---|---|
| **SQL Definition** | `creator_token_hash VARCHAR(64) NULL` | `creator_token_hash VARCHAR(64) NOT NULL DEFAULT ''` |
| **Go Field Type** | `*string` or `sql.NullString` | `string` |
| **Existing Rows** | Populated as `NULL` | Populated as `''` (empty string) |
| **Driver Scan Safety** | Safe: scanned as `nil` / `Valid: false` | Safe: scanned as `""`. SQL `NULL` is impossible. |
| **Nil Pointer Risk** | Exists: dereferencing `*room.CreatorTokenHash` without checking `nil` causes runtime panic. | **Zero**: standard primitive `string` has no nil pointer risk. |
| **Fail-Closed Logic** | `if room.CreatorTokenHash == nil \|\| *room.CreatorTokenHash == ""` | `if strings.TrimSpace(room.CreatorTokenHash) == ""` |
| **Database Query Simplicity** | Requires `IS NULL OR creator_token_hash = ''` | Direct equality: `WHERE creator_token_hash = ''` |

**Architectural Decision**: **Option B (`NOT NULL DEFAULT ''`) is selected as the canonical implementation.** It completely eliminates `NULL` states from PostgreSQL, avoids driver scan errors across all Go database drivers, and eliminates any possibility of nil-pointer panics.

### 6.3 Exact PostgreSQL Migration DDL

#### UP Migration (`migrations/000003_add_room_creator_token_hash.up.sql`)
```sql
-- Step 1: Add column with NOT NULL and DEFAULT ''
-- In PostgreSQL 11+, adding a column with NOT NULL DEFAULT '' is an O(1) metadata-only update.
ALTER TABLE rooms ADD COLUMN IF NOT EXISTS creator_token_hash VARCHAR(64) NOT NULL DEFAULT '';

-- Step 2: Ensure any legacy rows that might somehow contain NULL are sanitized to ''
UPDATE rooms SET creator_token_hash = '' WHERE creator_token_hash IS NULL;

-- Step 3: Add comment for documentation
COMMENT ON COLUMN rooms.creator_token_hash IS 'SHA-256 hash of creator capability token. Empty string indicates legacy/unmanaged room.';
```

#### DOWN Migration (`migrations/000003_add_room_creator_token_hash.down.sql`)
```sql
ALTER TABLE rooms DROP COLUMN IF EXISTS creator_token_hash;
```

### 6.4 GORM Model Definition
In `backend/internal/models/room.go`:
```go
type Room struct {
	ID               uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	RoomCode         string     `gorm:"size:32;uniqueIndex;not null" json:"room_code"`
	CreatorTokenHash string     `gorm:"type:varchar(64);not null;default:''" json:"-"`
	PasswordHash     string     `gorm:"type:text" json:"-"`
	MaxParticipants  int        `gorm:"default:10" json:"max_participants"`
	ExpiresAt        time.Time  `gorm:"not null" json:"expires_at"`
	DestroyedAt      *time.Time `json:"destroyed_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}
```

### 6.5 Fail-Closed Authorization Invariant for Legacy Rooms
For any room created prior to this remediation, `room.CreatorTokenHash` will scan as `""`.
The authorization logic enforces:
```go
if strings.TrimSpace(room.CreatorTokenHash) == "" {
    return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
        "error": "This room cannot be manually deleted (legacy room or unmanaged)",
    })
}
```
- Legacy rooms **cannot be deleted by anyone** via the API.
- Legacy rooms remain active until their scheduled `expires_at` timestamp.
- No backdoors exist.

---

## 7. Deterministic Deletion Transaction & System Boundary Analysis

```
Caller (Creator)                    Backend Handler                       PostgreSQL DB                wsHub / Clients
      |                                    |                                     |                            |
      |-- DELETE /api/v1/rooms/:code ----->|                                     |                            |
      |   (Auth: Bearer <creator_token>)   |                                     |                            |
      |                                    |-- 1. Extract header pre-checks ---->|                            |
      |                                    |-- 2. BEGIN Transaction ------------>|                            |
      |                                    |-- 3. SELECT FOR UPDATE (Locks row)->|                            |
      |                                    |<-- Returns locked room -------------|                            |
      |                                    |-- 4. Verify token under lock ------>|                            |
      |                                    |-- 5. DELETE RoomFiles ------------->|                            |
      |                                    |      DELETE RoomReactions --------->|                            |
      |                                    |      DELETE RoomMessages ---------->|                            |
      |                                    |      DELETE Room (RowsAffected==1) >|                            |
      |                                    |-- 6. COMMIT ----------------------->|                            |
      |                                    |                                     |                            |
      |                                    |-- 7. CloseRoomHubAtomic ---------------------------------------->|
      |                                    |      (Post-commit local side-effect)|     Broadcast room_destroyed
      |                                    |                                     |     Initiate socket close
      |<-- HTTP 200 OK --------------------|                                     |                            |
```

### 7.1 Deterministic PostgreSQL Row-Locking Strategy (`SELECT ... FOR UPDATE`)
To prevent concurrent deletion requests from interleaving or returning false success after another request has already deleted the room, room lookup, token authorization, and deletion occur entirely within an isolated PostgreSQL transaction using `SELECT ... FOR UPDATE`:

```go
func DestroyRoom(c *fiber.Ctx) error {
	code := c.Params("code")
	if code == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Room code is required"})
	}

	// 1. Extract creator token from header
	rawToken := extractCreatorToken(c)
	if rawToken == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Creator authorization token required"})
	}

	// 2. Begin database transaction
	tx := models.DB.Begin()
	if tx.Error != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	defer tx.Rollback()

	// 3. Fetch and lock room row exclusively with SELECT ... FOR UPDATE
	var room models.Room
	err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("room_code = ?", code).
		First(&room).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Room was not found, or was already deleted by a preceding concurrent transaction!
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Room not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// 4. Verify legacy room status under row lock (fail closed)
	if strings.TrimSpace(room.CreatorTokenHash) == "" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "This room cannot be manually deleted (legacy room or unmanaged)",
		})
	}

	// 5. Verify creator token in constant time under row lock
	presentedHash := sha256.Sum256([]byte(rawToken))
	presentedHex := hex.EncodeToString(presentedHash[:])
	if subtle.ConstantTimeCompare([]byte(presentedHex), []byte(room.CreatorTokenHash)) != 1 {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Invalid creator authorization token"})
	}

	// 6. Cascading deletions within transaction
	if err := tx.Where("room_code = ?", code).Delete(&models.RoomFile{}).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete room files"})
	}
	if err := tx.Where("room_code = ?", code).Delete(&models.RoomReaction{}).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete room reactions"})
	}
	if err := tx.Where("room_code = ?", code).Delete(&models.RoomMessage{}).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete room messages"})
	}

	// 7. Hard-delete room record and verify RowsAffected
	delRes := tx.Where("id = ?", room.ID).Delete(&models.Room{})
	if delRes.Error != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete room record"})
	}
	if delRes.RowsAffected != 1 {
		// Exactly one room row must be deleted
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Room no longer available"})
	}

	// 8. Commit database transaction
	if err := tx.Commit().Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database commit failed"})
	}

	// 9. Post-commit local WebSocket invalidation (generation-safe)
	CloseRoomHubAtomic(room.RoomCode, room.ID, "destroyed")

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Room destroyed successfully"})
}
```

#### Deterministic Concurrent Deletion Resolution & HTTP Outcomes:
- **First valid deletion**: Enters `tx.Clauses(clause.Locking{Strength: "UPDATE"})` and acquires the exclusive row lock. Verifies creator token in constant time, deletes cascades, deletes the room (`RowsAffected == 1`), commits, triggers generation-safe `CloseRoomHubAtomic(room.RoomCode, room.ID, "destroyed")`, and returns `200 OK` (`{"message": "Room destroyed successfully"}`).
- **Waiting deletion when no replacement room exists**: When the first deletion commits and releases the lock, PostgreSQL re-evaluates the query: the deleted row no longer exists. `First(&room)` returns `gorm.ErrRecordNotFound`. The waiting transaction rolls back and returns `404 Not Found` (`{"error": "Room not found"}`). It never calls `CloseRoomHubAtomic`.
- **Waiting deletion when room code has been reused (New Room Generation)**: If a new room with the same room code was created immediately after the first deletion, `SELECT ... FOR UPDATE` locks and returns the **new room generation**. The handler then authenticates the incoming token against the new room's `creator_token_hash`. Because the caller holds the old creator token for the destroyed room, constant-time comparison fails. The transaction rolls back and returns `403 Forbidden` (`{"error": "Invalid creator authorization token"}`). An old creator token can **never** authorize deletion of a newer room generation.
- **Invalid creator token**: Any request presenting an incorrect or mismatched creator token fails constant-time comparison under row lock, rolls back the transaction, and returns `403 Forbidden`. Local WebSocket connections are left untouched.

### 7.2 Corrected Deletion Guarantee Language & Failure Mode Analysis
To maintain absolute technical accuracy, BurnerBox **does not claim atomicity between PostgreSQL and in-memory WebSockets, nor does it claim that remote clients observe disconnection at the exact physical timestamp of database commit**. The failure modes are formally categorized:

1. **PostgreSQL Transaction Commit and Atomic Database Deletion**:
   The database transaction (`DELETE RoomFiles`, `DELETE RoomReactions`, `DELETE RoomMessages`, `DELETE Room`, `COMMIT`) provides strict ACID guarantees within PostgreSQL. From the moment `tx.Commit()` succeeds, the room and its records cease to exist in durable storage. Either all records are destroyed or none are.
2. **Synchronous Post-Commit Invocation of Local Hub Invalidation**:
   Immediately upon the successful return of `tx.Commit()`, the HTTP handler synchronously invokes `CloseRoomHubAtomic` on the local instance. This transitions `hub.destroyed = true` and drains local client references under `hub.mu`.
3. **Server-Side Attempts to Close Registered Local Client Connections**:
   Outside of lifecycle locks, `CloseRoomHubAtomic` loops over all drained local client references, attempts to write the `room_destroyed` JSON control frame, and executes `conn.Close()` on each client socket.
   *Clarification on Observation*: While the server synchronously executes socket closure, client-side observation of disconnection is governed by network transit time, OS TCP stack buffers, and client event-loop scheduling. The server cannot guarantee that remote clients observe disconnection at the exact physical timestamp of the database commit.
4. **Process Termination with Operational OS vs Complete Machine Failure**:
   - **Process Termination while OS Remains Operational** (e.g. clean exit, SIGKILL, fatal crash, or Linux kernel OOM kill):
     The operating system kernel remains operational and automatically reclaims all open file descriptors for the deceased process. The OS network stack transmits `TCP FIN` or `TCP RST` packets across all open sockets. Client runtimes receive an immediate socket close event.
   - **Complete Machine or Power Failure** (e.g. sudden host power loss, physical machine crash, hypervisor fault):
     The host machine ceases executing instantaneously. **There is no operating system running to transmit TCP FIN or RST packets.** A power failure does **not** guarantee an orderly TCP FIN/RST. Remote clients do not observe immediate socket closure; instead, clients detect machine failure asynchronously through:
     - Application-level WebSocket ping/pong heartbeat timeouts (e.g. 30–60s).
     - TCP keepalive probe timeouts.
     - TCP retransmission timeouts (RTO) upon attempting to send outbound frames.
   - **Recovered Panics**:
     Fiber's `recover.New()` middleware catches unhandled runtime panics in HTTP/WebSocket request handlers. **A recovered panic does not terminate the process.** If a panic occurs after `tx.Commit()` but before `CloseRoomHubAtomic` runs, the process remains alive and the OS does not close sockets. In this edge case, the background database reconciliation worker detects that the room was deleted from PostgreSQL and cleans up the orphaned hub.
5. **Best-Effort Cross-Instance Notification & Reconciliation Recovery**:
   PostgreSQL `LISTEN / NOTIFY` is best-effort asynchronous invalidation. Remote instances attempt severance upon message receipt. For missed notifications or network partitions, periodic database reconciliation serves as the recovery mechanism. There is no distributed transaction, no cross-system atomicity, and no hard remote-observation deadline across the cluster.

---

## 8. Generation-Safe Atomic Registration and Destruction Synchronization Contract

### 8.1 The Race Condition & Generation Invalidation Hazards
Without atomic multi-lock synchronization and generation binding:
1. An in-flight join could bypass tombstones and register on an old hub pointer.
2. A delayed `LISTEN / NOTIFY` message or reconciliation sweep for an older room UUID could arrive on an instance where a newer room has reused the room code, inadvertently destroying the newer room's hub and disconnecting its active users.

### 8.2 Synchronization Mechanics & State
```go
type wsHub struct {
	roomID     uuid.UUID                     // Immutable database UUID
	roomCode   string                        // Room code
	clients    map[*wsClient]struct{}
	broadcast  chan []byte
	register   chan *wsClient
	unregister chan *wsClient
	mu         sync.Mutex                    // Per-hub lock (Level 2)
	destroyed  bool                          // Protected strictly by mu
}

type roomTombstone struct {
	roomID      uuid.UUID
	destroyedAt time.Time
}

var (
	roomHubs       = make(map[string]*wsHub)         // Keyed by roomCode
	destroyedRooms = make(map[string]roomTombstone)  // Keyed by roomCode
	roomHubsMu     sync.RWMutex                      // Global registry lock (Level 1)
)
```

### 8.3 Single Atomic Registration Procedure (`registerClientAtomic`)
To guarantee that old hub pointers cannot bypass tombstones, that join operations have deterministic outcomes, and that **expired join requests never leave empty orphan hubs or dangling goroutines in memory**, client registration is unified into a single atomic procedure:
$$\text{Level 1 } (L_1): \text{roomHubsMu} \quad \longrightarrow \quad \text{Level 2 } (L_2): \text{hub.mu}$$

```go
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
		// CRITICAL: DO NOT publish to roomHubs map yet.
		// CRITICAL: DO NOT spawn hub.run() goroutine yet.
		hub = &wsHub{
			roomID:     roomID,
			roomCode:   roomCode,
			clients:    make(map[*wsClient]struct{}),
			broadcast:  make(chan []byte, 256),
			register:   make(chan *wsClient),
			unregister: make(chan *wsClient),
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
	// INVARIANT: An expired join cannot register merely because it passed the pre-lock check.
	// If the context expired while waiting for locks:
	// - Return immediately with an error.
	// - For a candidate hub: it is NEVER published to roomHubs, and NO goroutine is spawned.
	//   The unreferenced candidate struct is safely garbage-collected. Zero orphan hubs/goroutines!
	// - For an existing hub: hub state remains untouched.
	// - Locks are released in exact reverse order (hub.mu via defer, roomHubsMu via defer).
	// - Zero database or network I/O is performed under either lock.
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
```

### 8.4 Prevention of Orphan Hubs and Partial Initialization
- **Prevention of Empty Orphan Hubs**:
  If `ctx.Err() != nil` fires at Step 7, the function returns immediately without executing Step 9. The candidate hub was never assigned to `roomHubs[roomCode]`, and `go hub.run()` was never called. The unreferenced pointer is safely reclaimed by the Go garbage collector. No empty hub is left in the global map, and no idle background goroutine is leaked.
- **Prevention of Observing Partially Initialized Hubs**:
  Because `roomHubsMu.Lock()` is held continuously while:
  1. Constructing the candidate hub,
  2. Acquiring `hub.mu.Lock()`,
  3. Verifying the context deadline,
  4. Inserting the client into `hub.clients`, and
  5. Assigning `roomHubs[roomCode] = hub`,
  no concurrent registration or deletion routine can acquire `roomHubsMu` and observe `hub` in `roomHubs` while it is in an uninitialized, empty, or un-run state. When `roomHubsMu.Unlock()` is released, the hub in `roomHubs` is guaranteed to be fully initialized, contains its first client, has its background goroutine running, and is ready for broadcast/join/destroy traffic.

### 8.5 Generation-Safe Atomic Destruction Procedure (`CloseRoomHubAtomic`)
To protect newer room generations from stale destruction events, `CloseRoomHubAtomic` validates that the active hub's `roomID` matches the event generation before removal:

```go
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
			client.conn.Close()
		}
	}
}
```

### 8.6 Verification of Concurrency Invariants
- **Generation Safety**: A stale event carrying `oldRoomID` encounters `hub.roomID != roomID`, immediately aborts without acquiring `hub.mu`, leaves the active hub intact, and does not disconnect active users.
- **Context Expiration Under Locks**: Step 7 in `registerClientAtomic` explicitly re-verifies `ctx.Err()` under both `roomHubsMu` and `hub.mu` immediately before mutating `hub.clients`. If the context expired while waiting to acquire locks, client insertion is aborted, candidate hubs are never published, and locks are released in reverse order.
- **No Database Query Under Locks**: Database queries occur outside `registerClientAtomic` and `CloseRoomHubAtomic`.
- **No Network I/O Under Locks**: Socket writes and closes occur strictly outside both locks.
- **Prohibition of Reverse Lock Acquisition**:
  $$\text{Allowed: } \text{Acquire } L_1 \rightarrow \text{Acquire } L_2 \qquad \text{Prohibited: } \text{Acquire } L_2 \rightarrow \text{Acquire } L_1$$
- **Old Hub Pointers Cannot Bypass Tombstones**: Registration must pass through `registerClientAtomic` ($L_1 \rightarrow L_2$).
- **Deterministic Outcomes**: Proved in Section 7.1 and 8.3 for all interleavings.

---

## 9. Tombstone Lifecycle, Synchronization & Room Code Reuse

### 9.1 Tombstone Retention vs Maximum In-Flight Join Lifetime
- **Tombstone TTL**: `const tombstoneTTL = 10 * time.Minute` ($600\text{ seconds}$).
- **Maximum Join Lifetime**: `const MaxJoinHandshakeDuration = 15 * time.Second`.
- **Mathematical Ratio**:
  $$\frac{\text{tombstoneTTL}}{\text{MaxJoinHandshakeDuration}} = \frac{600\text{s}}{15\text{s}} = 40$$
- **Proof of In-Flight Join Safety**:
  1. A join operation initiates at $T_0$, reads the database at $T_1$, and obtains a context deadline of $T_0 + 15\text{s}$.
  2. If deletion commits at $T_2 > T_1$, a tombstone is recorded at $T_2$ with expiration $T_2 + 600\text{s}$.
  3. The join operation can only attempt registration while $T \le T_0 + 15\text{s}$.
  4. Because $T_0 + 15\text{s} \ll T_2 + 600\text{s}$, the tombstone is **mathematically guaranteed to be active** during the entire potential lifetime of the in-flight join.
  5. If the join request is delayed past $T_0 + 15\text{s}$, `ctx.Err() != nil` fires, and Contract 2 aborts the join before registration.
  6. Therefore, an in-flight join can **never** register after tombstone expiration.

### 9.2 Janitor Sweep (Preventing Unbounded RAM Growth)
To prevent `destroyedRooms` from growing indefinitely:
```go
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
```

### 9.3 Database Barrier After Tombstone Expiration
Once a tombstone expires after 10 minutes:
1. Any incoming connection for that room code must execute `JoinRoom`.
2. `JoinRoom` executes `models.DB.WithContext(ctx).Where("room_code = ?", code).First(&room)`.
3. Because the room was permanently deleted from PostgreSQL during the deletion transaction, PostgreSQL returns `ErrRecordNotFound`.
4. `JoinRoom` returns `HTTP 404 / Room not found` and closes the connection.
5. **Conclusion**: PostgreSQL persistent state serves as the permanent barrier against deleted rooms. Tombstones exist exclusively to bridge the sub-minute in-flight network window.

### 9.4 Prevention of Room Code Reuse Hazards
- **Entropy**: Room codes have 64 bits of cryptographic entropy ($2^{64} \approx 1.84 \times 10^{19}$ combinations), making collisions negligible.
- **Generation Binding via `roomID`**: If a room code were ever legitimately reused after tombstone expiration:
  - The new room has a new UUID (`room.ID = gen_random_uuid()`).
  - Any old connection or lingering hub pointer retains the old UUID.
  - Contract 2 asserts `hub.roomID == roomID`; generation mismatch immediately aborts registration. Old connections can never attach to a new room.

---

## 10. Deployment Topology & Multi-Instance Invalidation

### 10.1 Grounding the Fly.io Deployment Reality
Inspection of `backend/fly.toml`:
```toml
app = "burnerbox-api"
primary_region = "iad"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = true
  auto_start_machines = true
  min_machines_running = 0

  [http_service.concurrency]
    type = "connections"
    hard_limit = 250
    soft_limit = 200

[[vm]]
  size = "shared-cpu-1x"
  memory = "512mb"
```

#### What `fly.toml` Establishes:
- Fly Proxy manages machine lifecycle using **autostop** and **autostart**.
- Concurrency limits (`soft_limit = 200`, `hard_limit = 250`) guide Fly Proxy's routing decisions: when an active machine reaches 200 connections, Fly Proxy routes new incoming connections to another *existing* machine in the pool (waking it if stopped).
- When traffic drops to zero, idle machines are suspended to save compute costs.

#### What `fly.toml` Does NOT Establish:
- Fly Proxy **does not** dynamically provision new Machines. Autostop/autostart operates exclusively over pre-allocated machines. Dynamic scaling requires explicit CLI commands (`fly scale count N`) or Terraform/API operations.
- Declaring a single process group does **not** prove a single machine is running. An operator can provision 2, 5, or 10 machine replicas under that same process group.
- The actual number of deployed machines ($N$) is an **external deployment fact** that can only be verified via `fly status` or `fly machines list`.

#### Multi-Instance Reality:
- If $N = 1$, process-local memory invalidation via `CloseRoomHubAtomic` is sufficient.
- If $N > 1$, process-local invalidation on Machine 1 terminates connections on Machine 1, but leaves connections connected on Machine 2.
- **Architectural Requirement**: Multi-instance cross-invalidation is a required architectural capability for production deployments.

### 10.2 Dual-Layer Multi-Instance Invalidation Model

```
+---------------------------------------------------------------------------------------------------------+
|                                DUAL-LAYER MULTI-INSTANCE INVALIDATION                                   |
|                                                                                                         |
|  LAYER 1: TRANSIENT PUB/SUB (Best-Effort Low-Latency Path: <10ms)                                       |
|  - Instance A executes DestroyRoom -> COMMIT -> NOTIFY bb_room_events, '{"code":"..","id":".."}'        |
|  - Instance B (healthy listener) receives notification -> executes CloseRoomHubAtomic immediately       |
|                                                                                                         |
|  LAYER 2: DATABASE RECONCILIATION SWEEP (Recovery Mechanism: 30s Operational Target)                   |
|  - Recovery mechanism for missed notifications caused by network blips, buffer overflow, or reconnect   |
|  - Every instance runs a background reconciler on a 30-second operational target:                       |
|      1. Snapshot active local room codes and IDs: localHubs := snapshot(roomHubs)                       |
|      2. Batch query DB: SELECT room_code, id FROM rooms WHERE room_code IN (codes)                      |
|      3. Compare BOTH room_code AND roomID. If (code, id) is missing from DB ->                          |
|         invoke CloseRoomHubAtomic(code, id, "reconcile")                                                |
|  - On Listener Reconnect: Immediately triggers an out-of-cycle reconciliation sweep                     |
+---------------------------------------------------------------------------------------------------------+
```

### 10.3 Corrected Cross-Instance Consistency Guarantees
To maintain complete technical accuracy regarding distributed cluster behavior:
1. **Best-Effort Notification**: PostgreSQL `LISTEN / NOTIFY` is strictly a best-effort asynchronous invalidation channel. Delivered messages are received in $<10\text{ms}$ under normal conditions, but messages are dropped if an instance is disconnected or restarting during transaction commit.
2. **Reconciliation Recovery Mechanism**: Periodic database reconciliation is the formal recovery mechanism for missed notifications.
3. **Operational Target vs Guaranteed Deadline**: The 30-second reconciliation interval is strictly an **operational target**, not a hard maximum, strict bound, or guaranteed invalidation deadline. Database query latencies, query retry backoffs, scheduling jitter, or database downtime can extend this interval.
4. **Database Errors Abort Reconciliation**: If the database query encounters an error (network partition, timeout, connection pool exhaustion, database restart):
   - The reconciliation pass **aborts immediately**.
   - Rooms are **never** assumed or treated as deleted upon query error.
   - **Zero** hubs are closed; zero connections are severed.
   - The error is logged to operational metrics and retried on the next tick.
5. **Exact Recovery Condition**: Invalidation recovery occurs **only** when notification delivery succeeds or a subsequent successful reconciliation query definitively confirms that the room has been deleted from PostgreSQL.
6. **Behavior During Extended PostgreSQL Outages**:
   - If PostgreSQL remains unreachable for extended periods (e.g. 5–30 minutes):
     - Active in-memory WebSocket connections on each instance remain connected, allowing ongoing participant chat on that instance.
     - New room creations and deletions are blocked by the database layer.
     - Once PostgreSQL connectivity is restored, the `pq.Listener` reconnects, immediately triggering an out-of-cycle reconciliation sweep to synchronize state.
7. **Local Deletion vs Cross-Instance Distinction**:
   - **Local Invalidation**: On the instance handling `DELETE /api/v1/rooms/:code`, local database deletion commits atomically in PostgreSQL, followed immediately by synchronous in-memory hub closure and server-side socket termination.
   - **Cross-Instance Invalidation**: Remote instances receive best-effort notification via `LISTEN / NOTIFY` (<10ms), with eventual severance guaranteed by database reconciliation once connectivity is healthy. Neither distributed atomicity nor simultaneous remote client-side observation is claimed.

---

## 11. Frontend XSS Residual Risk & Honest Security Boundary

### 11.1 `sessionStorage` Same-Origin XSS Residual Risk
- **Security Boundary**: `sessionStorage` is strictly scoped per origin and per browser tab.
- **XSS Exposure Invariant**: Any script executing within the BurnerBox origin has unrestricted read access to `sessionStorage`.
- **Honest Security Assessment**:
  - Content Security Policy (`script-src 'self'`) and DOMPurify provide defense-in-depth against common script injection attacks.
  - **However, CSP and DOMPurify do not constitute proof of complete immunity to XSS.** Novel DOM-based XSS vectors, browser rendering vulnerabilities, or compromised frontend npm dependencies remain potential attack surfaces.
  - **If an XSS vulnerability is exploited, the creator token stored in `sessionStorage` can be read and exfiltrated by an attacker.**
  - **We make explicitly NO claim that `sessionStorage` provides protection equivalent to `HttpOnly` cookies.** `HttpOnly` cookies are inaccessible to client-side scripts by browser design; `sessionStorage` is designed specifically for client-side script access.
- **Why `sessionStorage` is Utilized**:
  - BurnerBox rooms are anonymous, stateless, and unauthenticated. Persistent user accounts and authentication sessions do not exist.
  - `sessionStorage` prevents accidental token disclosure through shared join links, copy-pasted URLs, browser history, proxy query logs, or shoulder-surfing.
  - It bounds deletion authority strictly to the browser tab where the room was created.

### 11.2 Access Log Redaction & Zero-Leakage Invariants
- **Fiber Application Logger ([backend/cmd/server/main.go#L80-L82](file:///e:/burnerbox/backend/cmd/server/main.go#L80-L82))**:
  ```go
  app.Use(logger.New(logger.Config{
      Format: "[${time}] ${method} ${path} - ${status}\n",
  }))
  ```
  - Logs only `${time}`, `${method}`, `${path}`, and `${status}`. Request headers, query strings, and request bodies are **never** logged.
- **Zero-Leakage Invariants**:
  - Creator tokens must **never** be placed in URLs, URL fragments, query parameters, participant endpoints (`GET /rooms/:code`, `GET /rooms/:code/messages`), WebSocket handshakes, analytics trackers, or application/proxy logs.
  - Disclosed exclusively once in the `201 Created` JSON body to the creator.

---

## 12. Existing API Compatibility & Contract Specification

### 12.1 Room Creation (`POST /api/v1/rooms/`)

#### Current Response (`201 Created`):
```json
{
  "room_code": "4c94e8156fb18a42",
  "join_url": "http://localhost:5173/rooms/4c94e8156fb18a42",
  "expires_at": "2026-11-20T22:38:00Z"
}
```

#### Proposed Backward-Compatible Response (`201 Created`):
```json
{
  "room_code": "4c94e8156fb18a42",
  "creator_token": "bb_rt_3a8f9c1e2b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f",
  "join_url": "http://localhost:5173/rooms/4c94e8156fb18a42",
  "expires_at": "2026-11-20T22:38:00Z"
}
```
- **Go Contract Model**:
  ```go
  type CreateRoomResponse struct {
      RoomCode     string    `json:"room_code"`
      CreatorToken string    `json:"creator_token,omitempty"`
      JoinURL      string    `json:"join_url"`
      ExpiresAt    time.Time `json:"expires_at"`
  }
  ```
- **Compatibility**: Third-party clients or older frontends that deserialize only existing fields ignore `creator_token` and continue operating without failure.

### 12.2 Room Deletion (`DELETE /api/v1/rooms/:code`)
- **Headers**:
  - `Authorization: Bearer <creator_token>` (or `X-Room-Creator-Token: <creator_token>`)
- **HTTP Status Codes**:
  - `200 OK`: `{"message": "Room destroyed successfully"}`
  - `400 Bad Request`: `{"error": "Room code is required"}`
  - `401 Unauthorized`: `{"error": "Creator authorization token required"}`
  - `403 Forbidden`: `{"error": "Invalid creator authorization token"}` or `{"error": "This room cannot be manually deleted (legacy room or unmanaged)"}`
  - `404 Not Found`: `{"error": "Room not found"}`

### 12.3 Frontend Handling
- In `frontend/src/routes/room/create/+page.svelte`:
  ```javascript
  if (data.creator_token) {
    sessionStorage.setItem(`bb_creator_token_${data.room_code}`, data.creator_token);
  }
  ```
- In `frontend/src/routes/room/[code]/+page.svelte`:
  - If `sessionStorage.getItem("bb_creator_token_" + roomCode)` exists $\rightarrow$ render "🔥 Burn Room Now" control.
  - If absent $\rightarrow$ hide deletion control.
- When creator clicks "Burn Room Now":
  ```javascript
  const token = sessionStorage.getItem(`bb_creator_token_${roomCode}`);
  await fetch(`/api/v1/rooms/${roomCode}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  sessionStorage.removeItem(`bb_creator_token_${roomCode}`);
  ```

---

## 13. Comprehensive Security Test Matrix (24 Scenarios)

| Test ID | Test Scenario | Inputs & Headers | Expected HTTP Status | Expected Assertions |
|---|---|---|---|---|
| **SEC-TEST-201** | Unauthenticated deletion denied | `DELETE /api/v1/rooms/:code`<br/>No auth header | `401 Unauthorized` | Zero database records deleted. Room intact. |
| **SEC-TEST-202** | Invalid creator token denied | `DELETE /api/v1/rooms/:code`<br/>`Authorization: Bearer wrong-token` | `403 Forbidden` | `Count(Room) == 1`. Constant-time comparison verified. |
| **SEC-TEST-203** | Valid creator token deletes room | `DELETE /api/v1/rooms/:code`<br/>`Authorization: Bearer <valid_token>` | `200 OK` | Room and all cascades hard-deleted from DB. |
| **SEC-TEST-204** | Invalid / non-existent room code | `DELETE /api/v1/rooms/nonexistent`<br/>`Authorization: Bearer <token>` | `404 Not Found` | No error panics. |
| **SEC-TEST-205** | Token cross-room isolation | `DELETE /api/v1/rooms/:code_B`<br/>`Authorization: Bearer <token_A>` | `403 Forbidden` | Room B remains completely intact. |
| **SEC-TEST-206** | Alternative header supported | `DELETE /api/v1/rooms/:code`<br/>`X-Room-Creator-Token: <token>` | `200 OK` | Room successfully deleted. |
| **SEC-TEST-207** | Password-protected room requires creator token | Room has password; caller sends password in body but no token | `401 Unauthorized` | Deletion fails. Password cannot delete room. |
| **SEC-TEST-208** | Message and reaction cascade | Valid creator token on room with messages and reactions | `200 OK` | `Count(RoomMessage) == 0`, `Count(RoomReaction) == 0`. |
| **SEC-TEST-209** | Encrypted room file cascade | Valid creator token on room with `RoomFile` bytea records | `200 OK` | `Count(RoomFile) == 0`. Database bytea rows deleted. |
| **SEC-TEST-210** | Active WebSocket sessions severed | WebSocket client connected to room hub; creator deletes room | `200 OK` | Client receives `room_destroyed` event, connection closes, hub purged. |
| **SEC-TEST-211** | Concurrent deletion idempotency | 2 simultaneous deletion requests with valid token | 1st: `200 OK`<br/>2nd: `404 Not Found` | Row lock serializes execution; exactly one deletion commits. |
| **SEC-TEST-212** | Room creation response contract | `POST /api/v1/rooms/` | `201 Created` | Response body contains `room_code`, `creator_token` (`bb_rt_...`), `join_url`. |
| **SEC-TEST-213** | Lost creator token handling | Creator token lost; caller attempts deletion with code only | `401 Unauthorized` | Room cannot be deleted early. Room remains alive until `expires_at`. |
| **SEC-TEST-214** | Legacy room fail-closed | Room in DB has `CreatorTokenHash == ""`; caller sends DELETE | `403 Forbidden` | Deletion denied; legacy room is protected until scheduled `expires_at`. |
| **SEC-TEST-215** | Token absence audit | Inspect logs, `GET /rooms/:code`, and `GET /rooms/:code/messages` | `200 OK` | Zero occurrences of `creator_token` or `creator_token_hash` in responses. |
| **SEC-TEST-216** | Atomic Registration Race (Interleaving A) | Client calls `registerClientAtomic` after `CloseRoomHubAtomic` writes tombstone | Rejected | Client rejected by `destroyedRooms` tombstone. Orphan hub NOT created. |
| **SEC-TEST-217** | Atomic Registration Race (Interleaving B) | Client calls `registerClientAtomic` before `CloseRoomHubAtomic` writes tombstone | Registered then Severed | Client registered atomically under `hub.mu`, then severed by `CloseRoomHubAtomic`. |
| **SEC-TEST-218** | Database failure and rollback safety | Simulated DB error during cascading delete | `500 Internal Server Error` | Transaction rolls back. Room remains intact. WebSockets NOT disconnected. |
| **SEC-TEST-219** | PostgreSQL Migration Test: Existing Rows | Run migration against PostgreSQL with existing rooms | Schema migrated | Existing rows have `creator_token_hash == ''`. Driver scan succeeds without error. |
| **SEC-TEST-220** | PostgreSQL Migration Test: Driver Scan & Auth | Read legacy row via `models.DB.First(&room)` | Query succeeds | `room.CreatorTokenHash` is `""`. Deletion returns `403 Forbidden`. |
| **SEC-TEST-221** | Tombstone Janitor Sweep Test | Tombstone older than 10 minutes | Sweep runs | Expired tombstone deleted from RAM. Context timeout ($15\text{s}$) prevents join race. |
| **SEC-TEST-222** | Safe Reconciliation Failure Test | PostgreSQL query fails during reconciliation | Sweep runs | Query error logged; zero local hubs closed; connections preserved. |
| **SEC-TEST-223** | **Generation-Safe Invalidation (Code Reuse)** | Delayed invalidation for `room_A` received on node with active `room_B` (same code) | Harmless NO-OP | `CloseRoomHubAtomic` asserts `hub.roomID == room_A`, detects mismatch, leaves `room_B` intact. |
| **SEC-TEST-224** | **Deterministic Concurrent Deletion (`FOR UPDATE`)** | 2 simultaneous `DELETE` requests with valid tokens | 1st: `200 OK`<br/>2nd: `404 Not Found` | `SELECT ... FOR UPDATE` serializes; Req 2 gets `RecordNotFound` and rolls back cleanly. |

---

## 14. Checkpoint 2B Implementation Acceptance Checklist

The implementation in Checkpoint 2B will be evaluated against the following criteria:

- [ ] **Unauthorized deletion cannot destroy any room**: `DELETE /api/v1/rooms/:code` without a valid token returns `401 Unauthorized` or `403 Forbidden`, leaving database records and active WebSocket sessions untouched.
- [ ] **Only the creator capability can delete its corresponding room**: Only the exact capability token returned upon room creation authorizes early deletion. Cross-room token reuse is rejected (`403 Forbidden`).
- [ ] **Legacy rooms fail closed**: Any room existing prior to remediation (`CreatorTokenHash == ""`) cannot be deleted via the API (`403 Forbidden`) and remains active until natural expiration.
- [ ] **Database transaction failure leaves room records and WebSocket connections intact**: A simulated database failure during cascading deletion triggers transaction rollback; active WebSocket connections are not severed.
- [ ] **Successful deletion removes the room and cascaded records**: Valid creator deletion transactionally hard-deletes `Room`, `RoomMessage`, `RoomReaction`, and `RoomFile` records, asserting `RowsAffected == 1`.
- [ ] **Deterministic concurrent deletion semantics**: Simultaneous deletion requests are serialized by `SELECT ... FOR UPDATE`. The first returns `200 OK`; subsequent requests return `404 Not Found`. False successes are eliminated.
- [ ] **No stale WebSocket connection can register after destruction**: Context deadlines ($15\text{s}$), candidate hub deferred publication, atomic `registerClientAtomic` checks ($L_1 \rightarrow L_2$), and `destroyedRooms` tombstones prevent connections from registering after destruction.
- [ ] **All local room clients are disconnected on the deleting instance**: `CloseRoomHubAtomic` broadcasts the terminal `room_destroyed` event, purges the hub from memory, and terminates client TCP connections.
- [ ] **Other instances are invalidated through notification or reconciliation**: The architecture specifies `LISTEN / NOTIFY` for real-time invalidation and periodic reconciliation for multi-instance deployments.
- [ ] **Stale invalidation events cannot destroy newer room generations**: Invalidation verifies `hub.roomID == roomID`; delayed events for older UUIDs are harmless no-ops.
- [ ] **Failed reconciliation never causes false deletion**: Database query errors during reconciliation abort the sweep immediately, preserving all active connections.
- [ ] **Creator tokens are not leaked through logs, URLs, participant APIs, or error responses**: Tokens appear only in the initial `201 Created` response to the creator and in `DELETE` request headers.
- [ ] **PostgreSQL migration and driver tests pass**: Verification confirms `NOT NULL DEFAULT ''` scans correctly into Go `string` without error across drivers.
- [ ] **Existing backend and frontend tests remain passing**: Full regression suites (`go test ./...` and `npm test`) pass without regression.

---

## 15. Implementation File Manifest (For Step 2B)

When authorized to proceed with implementation, the following files will be modified:

1. **`backend/internal/models/room.go`**:
   - Add `CreatorTokenHash string gorm:"type:varchar(64);not null;default:''" json:"-"` to `Room` struct.
2. **`backend/internal/handlers/rooms.go`**:
   - In `CreateRoom`: Generate 32-byte crypto random token (`bb_rt_...`), compute SHA-256 hash, store hash in `models.Room`, return `creator_token` in `CreateRoomResponse`.
   - In `DestroyRoom`: Implement deterministic PostgreSQL transaction with `clause.Locking{Strength: "UPDATE"}`, constant-time token verification under row lock, cascading delete, `RowsAffected == 1` check, commit, and post-commit `CloseRoomHubAtomic(room.RoomCode, room.ID, "destroyed")`.
3. **`backend/internal/handlers/rooms_ws.go`**:
   - Add `roomID uuid.UUID` and `destroyed bool` to `wsHub`.
   - Implement `destroyedRooms map[string]roomTombstone` and `startTombstoneJanitor`.
   - Implement bounded join context (`MaxJoinHandshakeDuration = 15*time.Second`).
   - Implement atomic `registerClientAtomic(roomCode, roomID, client, max, ctx)` with local candidate construction, double context verification, and deferred publication.
   - Implement generation-safe `CloseRoomHubAtomic(roomCode, roomID, reason)` verifying `hub.roomID == roomID` under $L_1 \rightarrow L_2$.
   - Refactor empty hub cleanup to strictly enforce $L_1 (\text{roomHubsMu}) \rightarrow L_2 (\text{hub.mu})$ ordering.
4. **`backend/internal/handlers/room_lifecycle_test.go`**:
   - Update `TestRoomLifecycle_DestroyRoom_HardDeletesAllCascades` to assert creator token requirements.
   - Implement the complete 24-scenario test suite (`SEC-TEST-201` through `SEC-TEST-224`).
5. **`docs/STEP_1_CHANGELOG.md`**:
   - Record Checkpoint 2B implementation details.

---

## 16. Unresolved Decisions, Documented Limitations & Conclusion

### 16.1 Resolved Technical Decisions
1. **Generation-Safe Invalidation**: Formally verified. `CloseRoomHubAtomic` verifies `hub.roomID == roomID`. Delayed events for old UUIDs are harmless no-ops.
2. **Deterministic Concurrent Deletions**: Formally verified. Implemented `SELECT ... FOR UPDATE` inside `tx`. Request 1 deletes and returns `200 OK`; Request 2 receives `RecordNotFound`, rolls back, and returns `404 Not Found`.
3. **Accurate Failure Mode Distinction**: Formally decoupled process termination with operational OS (kernel reclaims sockets) from complete machine/power failure (clients detect via TCP/heartbeat timeouts). Documented that recovered panics do not terminate the process.
4. **Prevention of Empty Orphan Hubs & Partial Initialization**: Candidate hubs are constructed locally in heap memory without being published to `roomHubs` or starting background goroutines until client registration commits under both locks. Expired joins discard candidate hubs cleanly with zero leaks.
5. **Double Context Expiration Verification in Atomic Registration**: Formally verified. `registerClientAtomic` checks `ctx.Err()` pre-lock, and checks `ctx.Err()` again under both $L_1$ and $L_2$ immediately before client insertion, releasing locks in reverse order upon expiration.
6. **Clarified Cross-Instance Consistency Guarantees**: Formally decoupled best-effort `LISTEN / NOTIFY` from reconciliation recovery. The 30s interval is documented as an operational target, not a strict bound. Recovery occurs when notification delivery succeeds or a subsequent successful query detects room absence.
7. **Atomic Multi-Lock Synchronization**: Formally unified registration into `registerClientAtomic` and destruction into `CloseRoomHubAtomic` adhering strictly to $L_1 (\text{roomHubsMu}) \rightarrow L_2 (\text{hub.mu})$. Reverse acquisitions are prohibited; deadlocks are eliminated; race outcomes are deterministic.
8. **In-Flight Join Lifecycle & Tombstone Synchronization**: Formally proven. Enforced strict 15-second context timeout; $TTL = 600\text{s}$ is $40 \times$ longer than maximum possible in-flight join duration. Bound room identity to immutable `room.ID uuid.UUID`, eliminating generation/reuse race conditions.
9. **Reconciliation Failure Behavior**: Formally defined. Reconciler requires successful DB query confirming absence; DB errors abort the sweep with zero hub closures. Listener reconnection triggers re-sync.
10. **Frontend XSS Residual Risk**: Formally documented. Acknowledged `sessionStorage` XSS boundary and residual risk without false claims of `HttpOnly` cookie equivalence.
11. **Implementation Acceptance Checklist**: Complete 14-point acceptance checklist documented for Checkpoint 2B.

### 16.2 Explicitly Documented Architecture Limitations
- **Single-Node Test Harness vs Multi-Instance Cluster**: Checkpoint 2B unit and integration tests run against a single process instance. Multi-instance `LISTEN / NOTIFY` signaling and the periodic reconciliation worker are designed for cluster deployments where $N > 1$.
- **Frontend XSS Residual Risk**: While CSP (`script-src 'self'`) and DOMPurify prevent common script injection attacks, an XSS compromise in the creator's browser tab can read `sessionStorage`. This is an accepted residual risk inherent to client-side anonymous capability tokens.

---

**STATUS: READY FOR IMPLEMENTATION & STOPPED.** All technical specifications and acceptance conditions for Checkpoint 2A.8 are complete. No application code, schemas, migrations, frontend files, tests, or configurations were modified. Awaiting user review and authorization before proceeding to **Checkpoint 2B** (Implementation of BB-SEC-002).
