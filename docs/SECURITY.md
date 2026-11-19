# BurnerBox Security Documentation

This document describes the security properties of BurnerBox as implemented in the current codebase. Gaps and architectural limitations are stated explicitly. Unresolved items requiring administrative or legal specification are marked as requiring human input.

---

## 1. End-to-End Encryption (E2EE)

### Ephemeral Secure Rooms
- **Encryption Scheme:** NaCl `crypto_secretbox` (libsodium).
- **Key Exchange:** The symmetric key is generated in the creator's browser using cryptographic random bytes and embedded in the shareable URL fragment (`#key=...`).
- **Server Role:** The URL fragment is never transmitted in HTTP requests. The server stores and broadcasts only ciphertext over WebSockets and REST endpoints. Anyone with raw database or server access cannot read room messages without the URL fragment key.
- **Caveat:** If the URL fragment is exposed (e.g. browser history, shoulder surfing, unencrypted clipboard, or external link referral), the room key is compromised.

### Anonymous Submissions (Tips)
- **Encryption Scheme:** The browser encrypts submission messages prior to transmission using either:
  - **Libsodium:** `crypto_box` authenticated envelope encryption with ephemeral sender keypair.
  - **OpenPGP:** PGP armor ciphertext encrypted against the organization's PGP public key.
- **Server Enforcement:** Server-side encryption is strictly enforced. When an organization has configured a public key (`org.PublicKey != ""`), the backend (`POST /api/v1/submit/:slug`) rejects unencrypted submissions (`encrypted_message == ""`) with `400 Bad Request`. Plaintext tip content is never accepted or stored for encrypted portals.
- **Custom Form Fields:** Any customized questionnaire answers are bundled into a JSON structure client-side and encrypted alongside the primary message into the single ciphertext payload before leaving the browser.

### Submission Replies & Multi-Turn Threads
- **Replies:** When a submitter enables replies, they generate a dedicated reply keypair. The organization's reply is encrypted in the browser with the submitter's reply public key. When a reply key exists, the backend (`POST /api/v1/dashboard/submissions/:id/reply`) rejects plaintext replies with `400 Bad Request`.
- **Thread Messages:** Follow-up conversation messages (`POST /api/v1/dashboard/submissions/:id/messages` and `POST /api/v1/submit/:slug/thread/:id/messages`) strictly require `encrypted_text` and `encryption_meta`. Plaintext submissions are rejected.

### File Attachments
- **Client-Side Encryption:** Files selected for submission are encrypted directly in the submitter's browser using the organization's public key (libsodium envelope encryption or OpenPGP binary literal encryption) prior to upload.
- **Server-Side Defense-in-Depth:**
  1. *Magic-Byte Validation:* File headers are inspected to verify declared MIME types against allowed formats.
  2. *Image Metadata Stripping:* EXIF, GPS coordinates, and camera profiles are stripped from JPEG, PNG, and GIF images. If stripping fails, the upload is aborted and rejected (`400 Bad Request`), preventing fail-open leaks.
  3. *At-Rest Disk Encryption:* Files are encrypted on the server with AES-256-GCM using `FILE_ENCRYPTION_KEY` before being written to disk at `uploads/submissions/<id>/`.

---

## 2. Key Management & At-Rest Storage

### Private Key Protection (Client Storage)
- **Organization Dashboard Keys:** Organization private keys are encrypted before storage in browser `localStorage`. A key is derived from the user's login password using Argon2id (`crypto_pwhash`) and used to encrypt the private key with NaCl `crypto_secretbox` using random salt and nonce parameters. For PGP, private keys are protected with OpenPGP passphrase encryption.
- **Submitter Reply Keys:** Submitter private keys stored in `localStorage` are encrypted at rest with a user-chosen or randomly generated multi-word passphrase.
- **Server Knowledge:** The server never receives, logs, or stores private decryption keys for organizations or submitters.

### Server-Held Cryptographic Keys
- **Proof Signing Key (`proof_key.json`):** Dedicated Ed25519 keypair used solely for signing submission hashes and Merkle roots.
- **File Encryption Key (`FILE_ENCRYPTION_KEY`):** 32-byte AES-256-GCM key used for server-side file encryption at rest.
- **TOTP Encryption Key (`TOTP_ENCRYPTION_KEY`):** 32-byte AES-256-GCM key used to encrypt organization 2FA secrets in the database.
- **JWT Secret (`JWT_SECRET`):** HMAC-SHA256 secret for signing authentication tokens.

---

## 3. Cryptographic Receipts & Append-Only Merkle Tree Log

BurnerBox provides non-repudiable submission verification without leaking tip contents.

### 1. Per-Submission Receipt
Upon receiving a genuine submission, the server computes $H(\text{ciphertext}) = \text{SHA-256}(\text{ciphertext})$ and issues a signed receipt containing:
- `submission_id` and UTC timestamp.
- Payload hash $H(\text{ciphertext})$.
- Ed25519 digital signature from the server's proof key.
- Server key fingerprint and public key.
- Assigned Merkle batch metadata (`batch_id`, `batch_number`, `leaf_index`).

### 2. Spam & Honeypot Proof Prevention
- To prevent browser autofill false positives, honeypot inputs use dynamic, randomly-suffixed field names per page load (e.g. `hp_<random>`).
- Submissions flagged as spam (honeypot triggered or fill time under 2000 ms) are discarded silently without database persistence or file storage.
- **No Signed Receipts for Spam:** Discarded submissions return a generic `201 Created` envelope to prevent bot adaptation, but **omit the `"proof"` field completely**. The server never generates Ed25519 signatures over unpersisted or discarded submissions.

### 3. Append-Only Merkle Tree Batching (RFC 6962)
- **Leaf Hashing:** $\text{LeafNode} = \text{SHA-256}(0\text{x}00 \mathbin{\Vert} \text{payload\_hash})$.
- **Internal Node Hashing:** $\text{ParentNode} = \text{SHA-256}(0\text{x}01 \mathbin{\Vert} \text{LeftChild} \mathbin{\Vert} \text{RightChild})$.
- **Periodic Sealing:** Open batches are sealed on a regular interval. The computed root is signed with the server's Ed25519 key and published at `GET /api/v1/portal/:slug/merkle-roots`.
- **Inclusion Proofs:** Submitters can retrieve $O(\log N)$ sibling proof paths at `GET /api/v1/submit/:slug/proof/:id`.
- **Offline Verifier:** Receipts can be validated using the standalone zero-dependency offline verifier (`/verify-receipt.html`).

---

## 4. Metadata Retention & Privacy

### Plaintext Fields Retained in Database
| Data | Location | Purpose |
|------|----------|---------|
| Anonymous Name | `Submission.AnonymousName` | Pseudonymous handle (e.g. "Velvet Raven-ETYH") |
| Status & Priority | `Submission.Status`, `Priority` | Workflow triage |
| Timestamps | `CreatedAt`, `UpdatedAt` | Queue sorting and retention expiration |
| File Metadata | `SubmissionFile.FileName`, `FileSize`, `MimeType` | Attachment listing |
| Organization Data | `Organization.Name`, `Email`, `PublicKey`, `Slug` | Dashboard account & routing |
| Internal Notes | `Submission.InternalNotes` | Authenticated staff notes |
| Active Sessions | `Session.ID`, `OrganizationID`, `ExpiresAt`, `LastActiveAt` | Session revocation tracking |

### Explicitly Excluded (Zero-Retention)
- **No IP Addresses:** Client IP addresses are never logged or persisted to disk or database. Rate limiting utilizes in-memory keys without writing IPs to persistent logs. Verified continuously via automated static code audits (`no_ip_logging_test.go`).
- **No User-Agent Strings:** Browser identifiers are not recorded.
- **No Cookies:** No session or tracking cookies are issued. Authentication is token-based.
- **No Third-Party Telemetry or CDN Leaks:** No external scripts, fonts, analytics, or trackers are embedded. Content Security Policy (`CSP`) strictly restricts all network calls to `'self'`, preventing the browser from making out-of-band requests that would leak the client's IP to third parties.
- **No Request Body Logging:** Raw request payloads are never logged.
- **Outbound Notification Protection:** Outbound notifications (webhooks and email alerts) transmit only public metadata (submission ID, timestamp, portal slug). Submitter IP headers (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`) are never forwarded or reflected.

### Transport-Layer IP Concealment & Tor Onion Routing
In standard TCP/IP networking, transport-layer packet headers necessarily contain routing IP addresses visible to local network operators (ISPs, public Wi-Fi, firewalls) and edge ingress proxies. To ensure client IPs are not exposed during transport:
1. **Tor Onion Service (v3 `.onion`):** BurnerBox is architected to operate behind a Tor hidden service. When accessed via `.onion`, traffic traverses 3 encrypted Tor relay hops. Neither the user's ISP, intermediate relays, nor the BurnerBox server can see the client's real IP address (incoming connections terminate from the local Tor daemon at `127.0.0.1`).
2. **`Onion-Location` Header:** When configured with `ONION_LOCATION`, the backend automatically emits the `Onion-Location: <onion-address>` response header, prompting Tor Browser users to switch seamlessly to the end-to-end anonymized onion service.
3. **No-Referrer Policy:** All HTTP responses enforce `Referrer-Policy: no-referrer`, ensuring URLs and portal identifiers are never transmitted in subsequent HTTP requests.

---

## 5. Data Retention & Automatic Expiration

| Entity | Retention Duration | Mechanism |
|--------|-------------------|-----------|
| Ephemeral Rooms | 1 hour to 7 days (creator selected) | Hard-deleted along with all messages by background worker every 60s |
| Room Self-Destruct Messages | 10 seconds to 10 minutes | Purged by background worker |
| Anonymous Submissions | **Configurable: 1 to 3650 days** (or indefinite if unset) | Hard-deleted along with disk files, replies, and logs by hourly worker |
| Submission Files | Tied to submission retention lifecycle | Securely deleted from disk (`os.Remove`) when submission expires |
| Organization Accounts | User-controlled (permanent deletion on-demand) | Admin can permanently hard-delete via `DELETE /api/v1/dashboard/account` (requires admin password and TOTP if enabled). Hard-deletes org and all associated data: submissions, disk files, replies, notes, thread messages, activity, Merkle batches and leaves, sessions, team members, dead man's switch, and settings. |

---

## 6. Authentication, Sessions & Rate Limiting

- **Password Hashing:** Argon2id with 64 MB memory, 3 iterations, 2 parallelism, 16-byte cryptographically random salt, and 32-byte key.
- **Two-Factor Authentication (2FA):** TOTP (RFC 6238) with secrets encrypted at rest (AES-256-GCM).
- **Stateful Sessions:** JWTs are bound to database session records (`sessions` table). Protected routes verify session existence, revocation timestamp, and expiry.
- **Session Revocation:** Users can view active sessions, revoke specific remote sessions, or revoke all other sessions.
- **Account Deletion:** Self-serve permanent account deletion is supported via `DELETE /api/v1/dashboard/account` (admin role only, requiring password verification and 6-digit TOTP validation if 2FA is active). The deletion transaction hard-deletes the organization record, all submissions, encrypted files on disk, replies, notes, thread messages, activity logs, Merkle batches and leaves, active sessions, team members, dead man's switch configurations, and portal settings.
- **Dedicated Rate Limiting:**
  - Login: 5 attempts per 15 minutes per IP+email.
  - 2FA Verification: 5 attempts per 15 minutes per IP+pending token.
  - Organization Signup: 5 attempts per hour per IP.
  - Check-Replies: 30 requests per 15 minutes per IP.
  - Rooms: 100 requests per minute globally.
- **Transport Security:** Production frontend builds enforce HTTPS for `API_URL` to protect authentication credentials in transit.

---

## 7. Known Limitations & Unresolved Tasks

### Architectural Limitations
1. **Non-Image File Metadata:** PDFs, Office documents, and videos cannot be automatically stripped on the server without document corruption. Submitters should sanitize document metadata before attaching.
2. **In-Memory Rate Limiting:** Rate limiter tracking structures reside in memory and reset if the application process restarts.
3. **Merkle Log Equivocation:** Signed Merkle roots verify batch integrity, but detecting split-view attacks currently relies on public root inspection; a distributed gossip/witness network is not yet implemented.

### Unresolved Items (Requiring Human Input)

> [!IMPORTANT]
> **TODO (Requires Human Input) — Security Contact & Vulnerability Disclosure:**
> A verified security contact email address or encrypted communication channel (e.g. `security@yourdomain.com` or designated PGP key) must be defined before production launch.

> [!IMPORTANT]
> **TODO (Requires Human Input) — Legal & Regulatory Compliance:**
> Review jurisdiction-specific requirements (such as GDPR, CCPA, or whistleblower protection directives) including designation of legal data controllers and formal data subject access/erasure workflows.
