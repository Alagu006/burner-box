# 🔥 BurnerBox

Secure, anonymous, ephemeral communication platform.

## Features (In Development)
- 📨 **Anonymous Submissions** — Whistleblower dropbox with metadata stripping
- 💬 **Secure Rooms** — End-to-end encrypted, self-destructing chat rooms
- 🕵️ **Tor Support** — .onion hidden service
- 🔒 **Zero Knowledge** — Server never sees unencrypted content

## Tech Stack
| Layer | Technology |
|-------|------------|
| Frontend | SvelteKit + Tailwind CSS |
| Backend | Go + Fiber |
| Database | SQLite (Turso) |
| Storage | Cloudflare R2 |

## Getting Started (Windows)

### Prerequisites
- Go 1.21+ (https://go.dev/dl/)
- Node.js 20+ (https://nodejs.org/)
- Git

### Backend
```powershell
cd backend
go run cmd/server/main.go

Runs on: http://localhost:8080

Frontend
powershell
cd frontend
npm install
npm run dev
Runs on: http://localhost:5173

Status
🚧 Early Development — Building MVP features

Author
Alagu006

text

---

### 📦 Step 6: First Local Commit

In your root `burner-box` folder:

```powershell
git add .
git commit -m "Prompt 1: Initial setup - Go backend + SvelteKit frontend running locally on Windows"