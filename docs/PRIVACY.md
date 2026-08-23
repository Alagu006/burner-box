# BurnerBox Privacy Policy

**Effective date:** August 17, 2026

This is a plain-language summary of how BurnerBox handles your data. It is not a legal document — it is written to be understood by anyone.

## What BurnerBox is

BurnerBox is an anonymous whistleblowing platform. It lets people submit tips to organizations without revealing their identity. It also provides ephemeral, encrypted chat rooms for real-time communication.

## What we do NOT collect

- **We do not log your IP address.** The server never reads, stores, or logs your IP address. This applies to all endpoints: submissions, room chat, authentication, and everything else.
- **We do not use cookies.** No session cookies, no tracking cookies, no advertising cookies. Zero cookies are set by the server.
- **We do not use analytics or trackers.** No Google Analytics, no Mixpanel, no Hotjar, no Facebook Pixel, no telemetry of any kind.
- **We do not log your User-Agent.** Your browser type, operating system, and device information are never recorded.
- **We do not track your browsing behavior.** There are no session histories, no page view logs, no click tracking.

## What we DO store

### Anonymous submissions (tips)

When you submit a tip through the web interface:
- Your message is encrypted in your browser before it is sent. The server receives only ciphertext.
- You are assigned a random anonymous name (e.g., "calm-harbor"). This is the only identifier linked to your submission.
- If you choose to enable replies, a decryption key is generated in your browser and stored in your browser's local storage. The server never receives this key.
- Files you attach are encrypted on the server using a server-held key. **The server can decrypt your files.** Client-side encryption for files is not yet implemented. TODO: implement client-side file encryption before production.

### Ephemeral secure rooms

When you join a chat room:
- Your messages are encrypted in your browser using a shared key that never leaves your device.
- You are assigned a random anonymous name for the duration of the session.
- The server stores only encrypted messages. It cannot read your messages.
- Messages can be set to self-destruct after 10 seconds, 1 minute, 5 minutes, or 10 minutes.
- The room itself expires after a time you choose (1 hour to 7 days). When it expires, the room and all its messages are permanently deleted from the database. There is no recovery mechanism.
- The encryption key is embedded in the URL after the `#` symbol. The part of the URL after `#` is never sent to the server, but it may appear in browser history.

### Organization accounts

Organizations that sign up for a dashboard:
- We store the organization name, email address, and a hashed password (Argon2id).
- We store the organization's encryption public key and (if enabled) an encrypted TOTP secret.
- Dashboard activity (viewing submissions, sending replies) is not logged beyond a minimal HTTP request log that shows only the method, path, and status code (e.g., "POST /api/v1/dashboard/submissions - 200"). No IP addresses, no user identifiers.

## How long data is kept

| What | How long |
|------|----------|
| Chat room messages | Until the room expires or the message self-destructs. Maximum 7 days. |
| Chat rooms | 1 hour to 7 days, depending on what the room creator chose. Hard-deleted when expired. |
| Anonymous tips (submissions) | Indefinitely, until the organization deletes them. There is no automatic expiration. TODO: add configurable retention periods. |
| Tip attachments (files) | Same as the tip they are attached to. Indefinite. |
| Organization accounts | Indefinitely. No account deletion is implemented yet. TODO: add account deletion. |

## What happens when data is deleted

When a chat room expires, the server runs a database transaction that deletes all messages in that room and then deletes the room itself. This is a hard delete — the data is removed from the database and cannot be recovered.

When a tip is deleted by an organization, the associated files are removed from disk and the database records are removed.

## Your encryption keys

- **Organization keys:** Generated when an organization signs up. The private key is stored in your browser's local storage. The server only has the public key. If you lose the private key, encrypted submissions cannot be decrypted.
- **Reply keys:** Generated when you submit a tip and enable replies. The private key is stored in your browser's local storage. The server only has the public key.
- **Room keys:** Generated in your browser when you create a room. Embedded in the share link URL. Never sent to the server.

**Important:** Your private keys are stored in plain text in your browser's local storage. If your browser is compromised (malicious extension, XSS attack, physical access to your device), an attacker could extract these keys. TODO: encrypt private keys with a user-derived password before storing them.

## Open source

BurnerBox is open source. You can audit the code yourself to verify the claims in this policy. The source code repository is the authoritative reference for how the system works.

## Changes to this policy

If this policy changes, the updated version will be committed to the repository with a new effective date. There is no notification mechanism for policy changes — check the repository for the latest version.

## Contact

TODO: Add a privacy contact email or encrypted communication channel before production deployment.

## Jurisdiction-specific notes

**TODO:** This privacy policy is written for general applicability. Before deploying in production, review whether specific jurisdictions require additional disclosures (e.g., GDPR requires a named data controller, specific legal bases for processing, and data subject rights). The current policy does not address GDPR compliance, CCPA compliance, or other jurisdiction-specific privacy regulations.
