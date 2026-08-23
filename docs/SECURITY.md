# BurnerBox Security Documentation

This document describes the current security properties of BurnerBox as implemented, not as originally designed. Features marked as incomplete are known gaps, not future promises.

## What is encrypted end-to-end

### Room messages (ephemeral secure rooms)

Room messages are encrypted end-to-end. The encryption key is generated in the browser when a room is created, embedded in the share link URL fragment (`#key=...`), and never sent to the server. The server stores and transmits only ciphertext (NaCl `crypto_secretbox`). Anyone who compromises the server cannot read room messages without the key.

**Caveat:** The key is embedded in the URL. If the URL is intercepted (e.g., browser history, network proxy, referrer header), the key is compromised. The URL fragment is not sent in HTTP requests, but it may appear in browser history, logs, or be leaked by the browser to intermediary pages.

### Submission messages (anonymous tips)

When using the web frontend, submission messages are encrypted end-to-end. The browser generates an ephemeral key pair and encrypts the message with the organization's public key (NaCl `crypto_box`). The server stores only ciphertext and encryption metadata.

**Caveat: the backend does not enforce encryption.** The `POST /api/v1/submit/:slug` endpoint accepts plaintext in the `message_text` field and stores it directly. The frontend always encrypts, but any API client (curl, script) can submit plaintext that the server stores unencrypted. TODO: enforce `encrypted_message` on the server when plaintext is submitted.

### Submission replies

When a submission has a reply key, the organization's reply is encrypted with the submitter's public key (NaCl `crypto_box`). The server stores only ciphertext. Without the reply key (stored in the submitter's browser), replies are unreadable.

**Caveat:** The `Reply.MessageText` field is still stored alongside encrypted replies. TODO: stop persisting plaintext in this field when encryption is available.

### Thread messages (follow-up conversation)

Thread messages follow the same E2EE path as replies. The submitter encrypts with the organization's public key; the organization encrypts with the submitter's reply public key. The server stores only ciphertext.

## Proof of submission

Each submission returns a cryptographic receipt: the server signs the SHA-256 hash of the encrypted payload using a server-held Ed25519 keypair. The receipt includes the hash, signature, timestamp, and key fingerprint.

The submitter can download this receipt as a text file and independently verify it against the server's public key (`GET /api/v1/proof-key`).

**What this proves:** The encrypted payload existed at the stated time and was received by the server.

**What this does NOT prove:** That the server did not also store the plaintext (it cannot prove this), or that the server will not delete the submission later.

**Key management:** The Ed25519 keypair is auto-generated on first startup and stored in `data/proof_key.json`. If this file is deleted, a new key is generated and old proofs can no longer be verified against the new key.

## What is NOT encrypted end-to-end

### File uploads (submission attachments)

Files uploaded with submissions are encrypted with AES-256-GCM on the server using a server-held master key (`FILE_ENCRYPTION_KEY`). The server can decrypt all files. This protects against raw disk compromise but is **not** end-to-end encryption — the server operator can read file contents.

### Internal notes

Internal notes on submissions are stored as plaintext in the database. These are only accessible to authenticated organization members via the dashboard API.

## Metadata the server retains

The following information is stored in the database in plaintext:

| Data | Where | Risk |
|------|-------|------|
| Submission anonymous name | `Submission.AnonymousName` | Pseudonymous, not linked to real identity |
| Submission status | `Submission.Status` | unread/read/actioned/flagged |
| Submission timestamps | `Submission.CreatedAt`, `UpdatedAt` | Can reveal when tips were submitted |
| Organization name + email | `Organization.Name`, `Email` | Required for org login |
| Room code | `Room.RoomCode` | Random 16-hex string |
| Room sender tags | `RoomMessage.SenderTag` | Anonymous adjective-noun names |
| Room creation/expiry times | `Room.CreatedAt`, `ExpiresAt` | |
| File original names | `SubmissionFile.FileName` | **TODO: original filenames can be identifying** |
| File sizes | `SubmissionFile.FileSize` | |
| File MIME types | `SubmissionFile.MimeType` | |

## What is NOT retained

- **No IP addresses** — the server never reads, logs, or stores client IP addresses
- **No User-Agent strings** — never logged or stored
- **No cookies** — no session cookies, no tracking cookies, no `Set-Cookie` headers
- **No analytics or tracking** — no third-party scripts, no telemetry, no fingerprinting
- **No WebSocket metadata** — WebSocket connections are not logged or persisted beyond the in-memory hub
- **No HTTP request bodies** — request bodies are parsed but never logged

## Data retention

| Data type | Retention | Deletion mechanism |
|-----------|-----------|-------------------|
| Room messages | Until room expiry or self-destruct | Background goroutine runs every 60 seconds, hard-deletes expired rooms and self-destructed messages |
| Ephemeral rooms | 1 hour to 7 days (user-selected at creation) | Hard-deleted by background goroutine when `ExpiresAt` passes |
| Submissions | **Indefinite** | No automatic TTL or cleanup. Submissions persist until manually deleted by the organization. TODO: add configurable retention policies. |
| Submission files | **Indefinite** | Tied to submission lifetime. Stored on disk at `uploads/submissions/<uuid>/`. |
| Organization accounts | **Indefinite** | No account deletion mechanism implemented. TODO: add account deletion endpoint. |

## Image metadata stripping

When images are uploaded as submission attachments, the server attempts to strip EXIF data, GPS coordinates, camera information, and other embedded metadata by re-encoding the image (JPEG at quality 95, PNG re-encoded, GIF re-encoded but loses animation).

**Known limitations:**
- Non-image files (PDF, DOCX, MP4, ZIP) are not metadata-stripped and may contain embedded author information, creation dates, GPS data in videos, or other identifying metadata.
- If metadata stripping fails, the original (unstripped) file is saved anyway. This is a known gap — TODO: fail the upload if stripping fails.
- The file's original filename is preserved in the database. A filename like `whistleblower-evidence.pdf` is not sanitized.

## Authentication

- Organization passwords are hashed with Argon2id (64MB memory, 3 iterations, 2 parallelism, 16-byte salt, 32-byte key)
- JWT tokens are used for dashboard authentication with a pending-2FA token mechanism for two-step login
- TOTP secrets are encrypted at rest with AES-256-GCM using a separate key (`TOTP_ENCRYPTION_KEY`)
- Auth endpoints are rate-limited to 5 attempts per 15 minutes per IP+email
- Room chat endpoints are rate-limited to 100 requests per minute globally

## Known security gaps

1. **Plaintext submissions accepted by backend** — the API does not require encryption, so plaintext tips can be stored unencrypted
2. **Files are not E2EE** — server-side encryption only; the server can decrypt all files
3. **Non-image file metadata not stripped** — PDFs, Office documents, videos can retain identifying metadata
4. **Original filenames stored** — can be identifying
5. **Submissions have no TTL** — stored indefinitely with no automatic cleanup
6. **Private keys stored in plaintext localStorage** — browser extension or XSS could extract them; should be encrypted with user-derived key
7. **No account deletion** — organizations cannot delete their accounts or data
8. **Rate limiter is in-memory** — resets on server restart
9. **CORS and CSP not configured for production** — currently allows localhost origins only

## Responsible disclosure

If you discover a security vulnerability in BurnerBox, please report it responsibly:

**Contact:** TODO: Add a security contact email or encrypted communication channel before production deployment.

**Process:**
1. Do not publicly disclose the vulnerability until a fix is available
2. Provide a clear description of the vulnerability, steps to reproduce, and potential impact
3. Allow reasonable time for the maintainers to respond and remediate
4. If the vulnerability involves user data exposure, coordinate disclosure timing with the maintainers

**Scope:** This disclosure process covers the BurnerBox application code. Vulnerabilities in third-party dependencies should be reported to the upstream maintainer.

## Audit status

As of August 2026, BurnerBox has not undergone a formal external security audit. This document reflects a code-level review by the development team. A professional penetration test and code audit should be conducted before any production deployment handling real whistleblower data.
