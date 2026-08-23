# BurnerBox Pre-Launch Checklist

Complete every item before exposing the platform to real users. Check each box as you go.

---

## Secrets & Encryption

- [ ] **JWT_SECRET** generated with `openssl rand -base64 64` and stored in Fly secrets (not in any repo, `.env`, or config file)
- [ ] **TOTP_ENCRYPTION_KEY** generated with `openssl rand -base64 32`, stored securely outside the repo
- [ ] **FILE_ENCRYPTION_KEY** generated with `openssl rand -base64 32`, stored securely outside the repo
- [ ] `backend/.env` removed from git history (it contains real Supabase credentials and encryption keys)
  ```bash
  git filter-branch --force --index-filter \
    'git rm --cached --ignore-unmatch backend/.env' \
    --prune-empty --tag-name-filter cat -- --all
  ```
  Or use `git filter-repo` (preferred) if available.
- [ ] `.env` is in `.gitignore` and has not been re-committed
- [ ] All three encryption keys backed up in a password manager or offline vault
- [ ] Rotate keys immediately if they were ever committed to a public or shared repo

## Backend (Fly.io)

- [ ] `fly secrets set` completed for all 4 required secrets (DATABASE_URL, JWT_SECRET, TOTP_ENCRYPTION_KEY, FILE_ENCRYPTION_KEY)
- [ ] Server starts without `Fatal` errors — check `fly logs`
- [ ] Health check passes: `curl https://api.your-domain.com/api/health` returns `{"status":"alive"}`
- [ ] `DELETE /api/v1/dashboard/submissions/:id/files/:fileId` route is wired (currently dead code — register in `main.go` before launch)
- [ ] `govulncheck ./...` run against backend — no HIGH/CRITICAL advisories remaining
  ```bash
  go install golang.org/x/vuln/cmd/govulncheck@latest
  govulncheck ./...
  ```

## Frontend (Cloudflare Pages)

- [ ] `VITE_API_URL` set in Cloudflare Pages build environment pointing to production API
- [ ] No hardcoded `localhost` URLs remain in source (only in `src/lib/api.js` fallback)
- [ ] `npm audit` run — no HIGH/CRITICAL vulnerabilities
  ```bash
  cd frontend && npm audit
  ```
- [ ] CSP `connect-src` includes the production WSS URL (auto-derived from `API_URL` on server)
- [ ] Cloudflare Pages custom domain configured (if applicable)

## CORS & Security Headers

- [ ] `CORS_ORIGINS` set to production domain only (e.g. `https://your-domain.pages.dev`)
- [ ] CORS does NOT use wildcards (`*`) — this app handles whistleblower data
- [ ] `Content-Security-Policy` `frame-ancestors 'none'` confirmed in production response headers
- [ ] `Strict-Transport-Security` header enabled (Cloudflare does this automatically on HTTPS)
- [ ] Helmet CSP `connect-src` includes `wss://` for WebSocket connections in production

## Database

- [ ] PostgreSQL connection uses `sslmode=require` (or equivalent for your provider)
- [ ] Database backups configured (daily automated + weekly manual test restore)
- [ ] `DATABASE_URL` not committed to any repo — only in Fly secrets
- [ ] AutoMigrate confirmed working — all 7 tables exist (Organization, TeamMember, Submission, SubmissionFile, Reply, Room, RoomMessage)

## Warrant Canary

- [ ] `docs/WARRANT_CANARY.md` reviewed by legal counsel (or at minimum by someone who understands the jurisdiction-specific implications)
- [ ] Canary includes a realistic staleness threshold (current: 90 days)
- [ ] Canary is accessible at `GET /api/v1/canary` — verify:
  ```bash
  curl https://api.your-domain.com/api/v1/canary | jq .last_updated
  ```
- [ ] Canary publish date is set to today's date before launch

## Security Documentation

- [ ] `docs/SECURITY.md` is accurate to the **current** codebase, not the original aspirational feature list. Specifically:
  - [ ] Correctly states files are NOT E2EE (server-side AES-256-GCM only)
  - [ ] Correctly states internal notes are plaintext
  - [ ] Correctly lists all 9 known security gaps
  - [ ] Correctly describes what metadata IS retained (sender tags, timestamps, filenames, etc.)
  - [ ] No claims about features that don't exist (e.g. Tor support, file E2EE)
- [ ] `docs/PRIVACY.md` reviewed — no false promises about data collection or encryption
- [ ] Security disclosure contact email/channel configured (currently a TODO in SECURITY.md)

## Functional Verification

- [ ] Organization signup works end-to-end (signup → login → dashboard)
- [ ] Anonymous submission works (submit → check replies → receive encrypted reply)
- [ ] File upload works (submit with attachment → download from dashboard → decryption succeeds)
- [ ] Image metadata stripping confirmed working (upload EXIF-tagged JPEG → download → verify EXIF removed)
- [ ] Ephemeral room works (create → join from 2 browsers → send messages → burn timer fires)
- [ ] Room self-destruct confirmed (wait for expiry → messages deleted from DB)
- [ ] 2FA setup/verify/disable works end-to-end
- [ ] Team invite/remove works
- [ ] Quick Exit button works (click and keyboard shortcut Esc)
- [ ] CSP violation reports configured (add `report-uri` directive before production)

## Operational

- [ ] `fly autoscale` configured appropriately (min 0, max 3+ for production)
- [ ] Monitoring/alerting set up for:
  - [ ] Health check failures
  - [ ] Server error rate (>1% 5xx)
  - [ ] Database connection failures
  - [ ] Disk usage on uploads volume
- [ ] Log aggregation configured (Fly.io logs, or external like Datadog/Grafana)
- [ ] Incident response plan documented (who to contact, how to rotate secrets, how to shut down)
- [ ] Rate limiting tested under load (global: 100 req/min, login: 5/15min, 2FA: 5/15min, replies: 30/15min)

## Pre-Launch Review

- [ ] Security test suite passes: `go test ./internal/security/ -v`
- [ ] No `console.error` or `console.log` calls with encryption metadata in frontend
- [ ] No IP addresses, User-Agent strings, or file contents in any log line
- [ ] `.env` file with real credentials is NOT in git history
- [ ] All TODO comments in code reviewed — critical ones addressed, rest documented as known gaps
