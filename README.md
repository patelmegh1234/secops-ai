# SecOps-AI 🛡️

> **Autonomous, event-driven Security Operations Agent** — ingests container vulnerability scan alerts, generates verified code fixes inside an isolated Docker sandbox, and requests human approval via Slack before opening GitHub Pull Requests.

[![CI](https://github.com/YOUR_ORG/secops-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_ORG/secops-ai/actions/workflows/ci.yml)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688)](https://fastapi.tiangolo.com)
[![Next.js 14](https://img.shields.io/badge/Next.js-14-black)](https://nextjs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SecOps-AI Pipeline                          │
│                                                                     │
│  GitHub CI / Trivy / Bandit                                         │
│         │ POST /webhooks/{scanner}                                  │
│         ▼ (< 200ms — 202 Accepted)                                  │
│  ┌─────────────────┐    Celery/Redis     ┌────────────────────────┐ │
│  │  FastAPI (ASGI) │ ──────────────────► │   Celery Worker        │ │
│  │  Rate-limited   │                     │                        │ │
│  │  HMAC-verified  │                     │  1. Parse CVE payload  │ │
│  └─────────────────┘                     │  2. CrewAI Triage      │ │
│                                          │  3. CrewAI Patch (4o)  │ │
│  ┌─────────────────┐                     │  4. CrewAI Guardrail   │ │
│  │  Next.js (Vercel│ ◄── WebSocket ──── │  5. Docker Sandbox     │ │
│  │  Dashboard       │    Real-time feed  │  6. Slack Alert        │ │
│  └─────────────────┘                     └────────────────────────┘ │
│                                                    │                │
│                                          ┌─────────▼──────────────┐ │
│                                          │  Human Approves/Rejects│ │
│                                          │  in Slack (Block Kit)  │ │
│                                          └─────────┬──────────────┘ │
│                                                    │                │
│                                          ┌─────────▼──────────────┐ │
│                                          │  GitHub PR Created     │ │
│                                          │  Branch + Commit + PR  │ │
│                                          └────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | FastAPI 0.111 (async) + Uvicorn |
| **Agent Pipeline** | CrewAI 0.55 + GPT-4o (patch) + GPT-4o-mini (triage/guardrail) |
| **Task Queue** | Celery 5.4 + Redis |
| **Database** | PostgreSQL 15 (SQLAlchemy 2.0 async) |
| **Sandbox** | Docker (network-disabled, 30s timeout) |
| **GitHub** | PyGithub — branch + commit + PR |
| **Slack** | slack-sdk Block Kit — interactive approval cards |
| **Dashboard** | Next.js 14 App Router + Tailwind CSS + Recharts |
| **Deployment** | Vercel (dashboard) + Railway (backend) |
| **DB Hosting** | Supabase PostgreSQL |
| **Redis Hosting** | Upstash |

## ⚡ Latency Budget

| Stage | Target |
|-------|--------|
| Webhook receipt → 202 Accepted | **< 200ms** |
| Triage Agent (GPT-4o-mini) | < 3s |
| Patch Agent (GPT-4o) | < 8s |
| Guardrail Agent (GPT-4o-mini) | < 4s |
| Docker Sandbox Verification | < 30s |
| Slack Alert Delivery | < 1s |
| **Total End-to-End** | **< 47 seconds** |

## Quick Start (Local)

### Prerequisites
- Docker Desktop running
- Python 3.11+
- Node.js 20+
- Poetry (`pip install poetry`)

### 1. Clone & configure
```bash
git clone https://github.com/YOUR_ORG/secops-ai.git
cd secops-ai
cp .env.example .env
# Edit .env with your actual API keys
```

### 2. Start the full stack
```bash
cd backend
docker compose up --build
```

This starts:
- **PostgreSQL** on `localhost:5432`
- **Redis** on `localhost:6379`
- **FastAPI API** on `localhost:8000`
- **Celery Worker** (processes vulnerability tasks)
- **Flower** (task monitoring) on `localhost:5555`

### 3. Start the dashboard
```bash
cd dashboard
npm install
npm run dev
```
Dashboard available at `http://localhost:3000`

### 4. Test with a sample webhook
```bash
# Generate HMAC signature
SECRET="your-github-webhook-secret"
PAYLOAD=$(cat backend/tests/fixtures/trivy_payload.json)
SIG=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print "sha256="$2}')

# Send webhook
curl -X POST http://localhost:8000/webhooks/trivy \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: $SIG" \
  -d "$PAYLOAD"

# Response: {"status":"accepted","task_id":"..."}
```

Watch the Celery worker process it, and check Slack for the approval card!

## Deployment

### Dashboard → Vercel
1. Import `dashboard/` folder to [Vercel](https://vercel.com)
2. Set env vars: `NEXT_PUBLIC_API_URL`, `NEXT_PUBLIC_WS_URL`
3. Auto-deploys on every push to `main`

### Backend → Railway
1. Connect `backend/` to [Railway](https://railway.app)
2. Set all env vars from `.env.example`
3. Railway auto-builds from `Dockerfile` and deploys

### Database → Supabase
1. Create a project at [supabase.com](https://supabase.com)
2. Get the connection string (Session mode, port 5432)
3. Set `DATABASE_URL` in Railway env vars

### Redis → Upstash
1. Create a Redis database at [upstash.com](https://upstash.com)
2. Get the `redis://` URL
3. Set `REDIS_URL`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`

## Slack App Setup

1. Go to [api.slack.com/apps](https://api.slack.com/apps) → Create New App
2. **OAuth & Permissions** → Add scopes: `chat:write`, `chat:write.public`
3. **Interactivity & Shortcuts** → Enable → Set Request URL:
   ```
   https://your-railway-app.railway.app/slack/actions
   ```
4. Install app to workspace → Copy **Bot Token** (`xoxb-...`)
5. **Basic Information** → Copy **Signing Secret**
6. Set both in `.env`

## GitHub Webhook Setup

1. Go to your repo → **Settings** → **Webhooks** → Add webhook
2. Payload URL: `https://your-railway-app.railway.app/webhooks/github`
3. Content type: `application/json`
4. Secret: match `GITHUB_WEBHOOK_SECRET` in `.env`
5. Select events: **Code scanning alerts**, **Dependabot alerts**

## Security

- ✅ All webhook endpoints validate HMAC-SHA256 signatures
- ✅ Slack callbacks validated with `X-Slack-Signature`
- ✅ Docker sandbox runs with `network_disabled=True`
- ✅ No source code leaves the system (zero-retention API calls)
- ✅ Secrets managed via environment variables (never committed)
- ✅ Rate limiting: 30 requests/minute on webhook endpoints
- ✅ CORS restricted to allowlisted origins only
- ✅ JWT authentication on dashboard API endpoints

## Running Tests

```bash
cd backend
poetry run pytest tests/ -v --cov=src
```

## License

MIT © 2024 SecOps-AI
