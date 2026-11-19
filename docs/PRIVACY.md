# BurnerBox Privacy Policy

**Effective date:** November 5, 2026

This document explains in plain language how BurnerBox handles your data. It describes the system as implemented in code.

---

## What BurnerBox Is

BurnerBox is an open-source anonymous whistleblowing and secure communication platform. It enables individuals to submit encrypted tips to organizations without revealing their identity, and provides ephemeral end-to-end encrypted chat rooms for real-time collaboration.

---

## What We Do NOT Collect

- **We do not log your IP address:** The server never records or writes client IP addresses to logs or databases. Rate limiting relies strictly on transient in-memory counters that are never written to disk or logs.
- **We do not leak your IP via third parties:** All fonts, scripts, and assets are hosted locally on the application server. Our strict Content Security Policy forbids third-party network connections (no Google Fonts, CDNs, or tracking pixels), preventing external entities from logging your IP address when you load the site.
- **We do not use cookies:** No session cookies, no tracking cookies, and no third-party cookies. Authentication is performed via standard bearer tokens.
- **We do not use analytics or third-party trackers:** No Google Analytics, telemetry libraries, tracking pixels, or external scripts are loaded.
- **We do not log your User-Agent:** Your browser type, version, and operating system are never recorded.
- **We do not track browsing behavior:** No page view tracking, click streams, or session profiling exist.
- **Transport Security & Onion Routing:** To prevent your IP address from being visible to your local internet provider (ISP) during network transport, BurnerBox supports Tor Onion Services (v3 `.onion`). When accessed via Tor Browser, your traffic is routed across 3 encrypted Tor relays, and the server receives connections from the local Tor daemon (`127.0.0.1`), completely hiding your client IP in transit. Clearnet requests emit an `Onion-Location` header to notify Tor Browser users of the onion service.

---

## What We DO Store

### 1. Anonymous Submissions (Tips)
- **Encrypted Message Content:** When submitting a tip to an organization with encryption enabled, your message is encrypted in your browser using either libsodium or OpenPGP. The server rejects plaintext submissions and stores only ciphertext and encryption metadata.
- **Random Pseudonym:** You are assigned a randomly generated pseudonym (e.g. `Velvet Raven-ETYH`). This is the sole identifier associated with your submission.
- **Reply Keys:** If you enable replies, an encryption keypair is generated locally in your browser. The private key is encrypted with a passphrase before being stored in your browser's local storage. The server stores only your reply public key.
- **File Attachments:** Files are encrypted client-side in your browser before upload. On the server, file magic bytes are checked, image EXIF/metadata is stripped (failing closed if stripping cannot complete), and files are stored encrypted on disk with AES-256-GCM.
- **Cryptographic Receipts:** Legitimate submissions receive a signed Ed25519 cryptographic receipt and Merkle log inclusion proof verifying acceptance. Submissions caught by honeypots or timing checks are discarded without signed receipts.

### 2. Ephemeral Secure Rooms
- **End-to-End Encryption:** Messages are encrypted in your browser using a symmetric key embedded solely in the URL fragment (`#key=...`). The server stores and relays only ciphertext.
- **Self-Destruct Messages:** Messages set with self-destruct timers (10 seconds to 10 minutes) are permanently wiped from the database once their timer expires.
- **Room Expiration:** Rooms expire between 1 hour and 7 days. Once expired, a background worker hard-deletes the room and all messages in an unrecoverable database transaction.

### 3. Organization Accounts
- **Account Credentials:** We store the organization name, contact email, and an Argon2id-hashed password.
- **Encryption Configuration:** Organizations store their encryption public key and, if 2FA is enabled, an AES-256-GCM encrypted TOTP secret.
- **Stateful Sessions:** Active login sessions are tracked in the database to allow organizations to view active sessions, revoke specific devices, or revoke all other sessions. IP addresses are never recorded in session records.
- **Account Deletion:** Administrators can permanently hard-delete their organization via `DELETE /api/v1/dashboard/account` (requiring password and 2FA TOTP verification). Deletion completely wipes the organization, submissions, attached files on disk, replies, notes, thread messages, Merkle tree records, sessions, team members, and settings.

---

## Data Retention & Automatic Expiration

| Data Category | Retention Period | Deletion Mechanism |
|---------------|------------------|---------------------|
| Room messages | 10 seconds to 7 days | Hard-deleted upon self-destruct or room expiration |
| Chat rooms | 1 hour to 7 days | Hard-deleted by background worker every 60 seconds |
| Anonymous tips (submissions) | **Configurable: 1 to 3650 days** | Hard-deleted along with attached files and replies by hourly cleanup worker |
| Submission files | Same as associated tip | Removed from storage disk (`os.Remove`) upon tip expiration |
| Organization accounts | User-controlled (permanent deletion on-demand) | Hard-deleted on-demand via `DELETE /api/v1/dashboard/account` (admin password + TOTP confirmation); permanently wipes organization, submissions, disk files, replies, threads, Merkle logs, sessions, and team memberships |

---

## Your Encryption Keys

- **Organization Private Keys:** Generated in the browser upon signup. The private key is encrypted at rest with a password-derived key (Argon2id + secretbox) or OpenPGP passphrase before being saved to browser `localStorage`.
- **Submitter Reply Keys:** Stored in browser `localStorage` encrypted at rest with a passphrase.
- **Room Keys:** Generated locally in the browser, embedded in the URL fragment, and never transmitted to the server.

The server never has access to unencrypted private keys. If you lose your password or passphrase, encrypted content cannot be decrypted by anyone, including the server operators.

---

## Unresolved Items Requiring Human Input

> [!IMPORTANT]
> **TODO (Requires Human Input) — Privacy & Security Contact:**
> Add an official privacy and security contact email address or encrypted communication channel before production deployment.

> [!IMPORTANT]
> **TODO (Requires Human Input) — Jurisdiction-Specific Legal Review:**
> Review regulatory requirements for production deployments in specific legal jurisdictions (including GDPR, CCPA, and regional whistleblower regulations), establishing formal data controller designations and data subject rights procedures.

---

## Open Source Verification

BurnerBox is open source. You can audit the codebase directly to verify that all cryptographic and privacy assurances described here match the running application.
