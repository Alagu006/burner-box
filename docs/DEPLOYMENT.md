# BurnerBox Deployment Guide

This document covers deploying the BurnerBox backend to Fly.io, the frontend to Cloudflare Pages, and optionally setting up a Tor hidden service.

---

## Prerequisites

- [Fly CLI](https://fly.io/docs/hands-on/install-flyctl/) installed and authenticated (`fly auth login`)
- [Cloudflare account](https://dash.cloudflare.com/) with Pages enabled
- A PostgreSQL database (Supabase, Neon, Railway, or self-hosted)
- OpenSSL for generating encryption keys

---

## 1. Generate Encryption Keys

Run these **once** and store the outputs in a password manager or secrets vault. Never commit them to the repo.

```bash
# JWT signing secret (64 bytes, base64-encoded)
openssl rand -base64 64

# TOTP encryption key (32 bytes, base64-encoded)
openssl rand -base64 32

# File encryption key (32 bytes, base64-encoded)
openssl rand -base64 32

# Proof-of-submission & Merkle batch signing key (32-byte Ed25519 seed, base64-encoded)
openssl rand -base64 32
```

You will set these as Fly secrets in step 3.

---

## 2. Backend → Fly.io

### 2a. Create the Fly app

```bash
cd backend
fly launch --no-deploy
```

This generates `fly.toml` from the existing file. If `fly launch` asks to modify `fly.toml`, decline — the committed version is already configured.

If you already have a `fly.toml`, skip this step and just set the app name:

```bash
fly apps create burnerbox-api
```

### 2b. Create a persistent volume for file uploads

```bash
fly volume create burnerbox_uploads --region iad --size 1
```

This 1GB encrypted volume is mounted at `/app/uploads` inside the container. Increase size as needed.

### 2c. Set secrets

```bash
fly secrets set \
  DATABASE_URL="postgresql://user:password@host:5432/dbname" \
  JWT_SECRET="<output from openssl rand -base64 64>" \
  TOTP_ENCRYPTION_KEY="<output from openssl rand -base64 32>" \
  FILE_ENCRYPTION_KEY="<output from openssl rand -base64 32>" \
  PROOF_SIGNING_PRIVATE_KEY="<output from openssl rand -base64 32>" \
  PROOF_SIGNING_KEY_ID="bb-prod-2026-v1" \
  CORS_ORIGINS="https://your-domain.pages.dev" \
  API_URL="https://api.your-domain.com"
```

**Required secrets:**
| Secret | Purpose |
|--------|---------|
| `DATABASE_URL` | PostgreSQL connection string (include `?sslmode=require` for cloud DBs) |
| `JWT_SECRET` | HMAC key for signing JWT tokens |
| `TOTP_ENCRYPTION_KEY` | AES-256 key for encrypting TOTP secrets at rest |
| `FILE_ENCRYPTION_KEY` | AES-256 key for encrypting uploaded files at rest |
| `PROOF_SIGNING_PRIVATE_KEY` | Base64-encoded Ed25519 32-byte seed or 64-byte private key for receipts and Merkle root signing |

**Optional secrets:**
| Secret | Default | Purpose |
|--------|---------|---------|
| `PROOF_SIGNING_KEY_ID` | `key_<fingerprint>` | Human-readable identifier for the active signing key (e.g. `bb-prod-2026-v1`) |
| `PROOF_HISTORICAL_PUBLIC_KEYS` | _(empty)_ | JSON array of retired verification keys for historical receipt validation |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated allowed origins |
| `API_URL` | _(empty)_ | Public URL of this API (used for CSP WebSocket directives) |
| `SUBMISSION_URL_PREFIX` | `http://localhost:5173/submit` | URL prefix for submission links |
| `SUPER_ADMIN_TOKEN` | _(empty)_ | Token for super-admin dashboard (`/api/v1/admin/stats`) |
| `SMTP_HOST` | _(empty)_ | SMTP server host for email notifications |
| `SMTP_PORT` | _(empty)_ | SMTP server port (e.g. 587) |
| `SMTP_USER` | _(empty)_ | SMTP username / sender address |
| `SMTP_PASS` | _(empty)_ | SMTP password |

The server **refuses to start** if any required secret is missing. This is intentional — a misconfigured production server is worse than a failed startup.

### 2d. Deploy

```bash
fly deploy
```

This builds the Docker image (multi-stage: Go build → Alpine runtime) and deploys it. The first deploy takes 2-5 minutes.

### 2e. Verify

```bash
fly status
fly logs

# Test health endpoint
curl https://api.your-domain.com/api/health
# Expected: {"status":"alive","message":"BurnerBox API with PostgreSQL","version":"0.1.0"}
```

### 2f. Database migrations

The server runs GORM AutoMigrate on startup, which creates/updates tables automatically. No manual migration step is needed.

---

## 3. Frontend → Cloudflare Pages

### 3a. Set the API URL environment variable

In the Cloudflare Pages dashboard:

1. Go to **Settings → Builds & deployments → Build variables**
2. Add a new variable:
   - **Variable name:** `VITE_API_URL`
   - **Value:** `https://api.your-domain.com` (your Fly.io API URL)
   - **Environment:** Production (and Preview if desired)

This replaces all hardcoded `localhost:8080` URLs at build time via `src/lib/api.js`.

### 3b. Connect the Git repository

1. Go to **Cloudflare Pages → Create a project → Connect to Git**
2. Select the BurnerBox repository
3. Configure the build:
   - **Framework preset:** SvelteKit
   - **Build command:** `cd frontend && npm install && npm run build`
   - **Build output directory:** `frontend/.svelte-kit/output`
   - **Root directory:** `frontend`

### 3c. Deploy

Push to the connected branch (typically `main`). Cloudflare Pages will automatically build and deploy.

For manual deploys:
```bash
cd frontend
npm install
VITE_API_URL=https://api.your-domain.com npm run build
npx wrangler pages deploy .svelte-kit/output/client --project-name=burnerbox-frontend
```

### 3d. Custom domain (optional)

1. In Cloudflare Pages → **Settings → Custom domains**
2. Add your domain (e.g. `your-domain.com`)
3. Update `CORS_ORIGINS` on Fly.io to include the new domain
4. Update `CSP` connect-src if needed (the server auto-builds wss:// from `API_URL`)

---

## 4. Tor Hidden Service (Optional)

A Tor `.onion` address allows submitters to access the platform without revealing their IP to any network observer, even if they don't trust the exit node.

### 4a. Install Tor

```bash
# Debian/Ubuntu
sudo apt install tor

# macOS
brew install tor
```

### 4b. Configure torrc

Edit `/etc/tor/torrc` (or `~/.tor/torrc` for a local setup):

```
# BurnerBox hidden service
HiddenServiceDir /var/lib/tor/burnerbox/
HiddenServicePort 80 127.0.0.1:8080

# Optional: also expose the frontend
HiddenServicePort 443 127.0.0.1:443
```

### 4c. Start Tor and get the .onion address

```bash
sudo systemctl restart tor
# or: tor

# The .onion address is in:
cat /var/lib/tor/burnerbox/hostname
# Output looks like: abc123def456....onion (56 characters)
```

### 4d. Verify the .onion address out-of-band

**This step is critical.** An attacker who controls the Tor entry node could serve a different `.onion` address to the first user who connects. Verify the address through a trusted channel:

1. Generate the `.onion` address on a trusted machine
2. Verify it with at least one other person via a separate channel (Signal, in-person, phone call)
3. Publish the verified address on multiple independent channels

Until verified, the `.onion` address should be treated as **untrusted**.

### 4e. Serve the frontend through Tor (optional)

For a full Tor setup, proxy both the API and frontend through Tor:

```
HiddenServiceDir /var/lib/tor/burnerbox/
HiddenServicePort 80 127.0.0.1:8080    # API
HiddenServicePort 443 127.0.0.1:443    # Frontend (via nginx/caddy reverse proxy)
```

Or point the frontend directly at the `.onion` API URL:

```
VITE_API_URL=http://abc123...onion
```

---

## 5. Updating Secrets

To rotate encryption keys without downtime:

```bash
# Rotate TOTP key (existing TOTP secrets will need re-setup by orgs)
fly secrets set TOTP_ENCRYPTION_KEY="$(openssl rand -base64 32)" --keep-unset

# Rotate file key (existing files will become unreadable — back up first)
fly secrets set FILE_ENCRYPTION_KEY="$(openssl rand -base64 32)" --keep-unset

# Apply (restarts machines)
fly secrets list
```

**Warning:** Rotating `FILE_ENCRYPTION_KEY` makes all previously encrypted files unreadable. Export/decrypt files before rotating. Rotating `TOTP_ENCRYPTION_KEY` forces all orgs to re-enable 2FA.

---

## 6. Database Backups

### Supabase (if using Supabase)
- Automatic daily backups on paid plans
- Manual backup: Dashboard → Database → Backups → Create backup

### Encrypted backups with age (recommended)

BurnerBox includes backup/restore scripts that encrypt the database dump with [age](https://github.com/FiloSottile/age) before storing it:

```bash
# Install age (if not already installed)
# macOS: brew install age
# Linux: sudo apt install age

# Set environment
export DATABASE_URL="postgresql://user:pass@host:5432/dbname"
export BACKUP_PASSPHRASE="your-secret-passphrase"

# Create encrypted backup
cd scripts
chmod +x backup.sh restore.sh
./backup.sh
# Output: burnerbox_backup_YYYYMMDD_HHMMSS.age

# Restore from backup
./restore.sh burnerbox_backup_YYYYMMDD_HHMMSS.age
```

**Security notes:**
- Store `BACKUP_PASSPHRASE` in a separate secrets manager from the backup file
- The encrypted backup is safe to store on untrusted infrastructure
- The passphrase must never be committed to version control

### PostgreSQL (plain pg_dump)

```bash
pg_dump "$DATABASE_URL" > backup_$(date +%Y%m%d).sql
```

Schedule with cron:
```
0 2 * * * pg_dump "$DATABASE_URL" | gzip > /backups/burnerbox_$(date +\%Y\%m\%d).sql.gz
```

---

## Troubleshooting

| Symptom | Likely cause |
|---------|-------------|
| Server exits immediately with `Fatal` log | Missing required secret — check `fly secrets list` |
| CORS errors in browser | `CORS_ORIGINS` doesn't match the frontend domain |
| WebSocket connection fails | CSP `connect-src` missing the WSS URL — ensure `API_URL` is set |
| Files not persisting across deploys | Volume not attached — check `fly volume list` |
| `403` on TOTP endpoints | Rate limiter hit — wait 15 minutes or check IP |
