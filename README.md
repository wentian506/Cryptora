# CRYPTORA — Cryptographic Risk & Migration Intelligence

**Encrypt. Protect. Trust.** · Team KRYPTX · SIH PS-26164

Black-theme, evidence-backed crypto discovery → CBOM → quantum-risk → hybrid/PQC
migration platform. Scanning runs **in the browser** (source never uploaded);
sign-in syncs results to **your own backend + MySQL**.

## Run it (2 terminals)

```bash
# 1. backend (auth + persistence) → http://localhost:8000
cd backend && pip install -r requirements.txt
DEV_MODE=true uvicorn app.main:app --port 8000

# 2. frontend → http://localhost:5173
cd frontend && npm install && npm run dev
```

Open the frontend → landing page → **Launch App** (demo works fully offline) or
**Sign in** (email / Google / phone OTP) to save scans to your account.

First screen is the **landing page**. The dashboard is a **14-step workflow sidebar**
(numbered 1–14 + finding-count badges): Discovery → CBOM → DepGraph → Certs →
Risk → Agility → Break → Attack → Roadmap → Validate → Drift → Reports → AI → Hidden.

Highlights: **live scan terminal** + SCANNING badge, **8-layer engine card**
(regex / AST-lite / secrets / entropy / manifests / containers / ASN.1 / binary
strings), **two-pane CBOM** (matched text + line-in-context + explainable 0–10 score
with business-context controls), **SBOM export**, **ZIP report bundle**, radial
dependency graph, Mosca presets, exposure/agility gauges, attack-surface network
map, per-file byte-entropy chart, and AI suggestion chips. Scan options skip
lockfiles/minified noise by default (disclosed). Fully responsive: laptop, tablet,
and phone (hamburger nav, stacked panes, scrollable tables/graphs).

## Upload center (all computed live, zero sample data)

Files/ZIP · Folder · GitHub repo URL · Paste Code · Link/URL · Certificates ·
Dockerfile · Containers · Binaries/Docs — see the in-app drawer for details.

## Deploy it → `deploy/` folder

| Path | What |
|---|---|
| `deploy/DEPLOYMENT.md` | **Start here** — 3 options: Docker prod, static demo, manual VPS |
| `deploy/deploy.sh` | One command: `./deploy/deploy.sh` → full stack on :8080 |
| `docker-compose.prod.yml` | nginx+SPA → FastAPI → MySQL 8 (healthchecks, volumes) |
| `deploy/nginx.conf` | SPA fallback + `/api` proxy + caching |
| `deploy/.env.example` | All secrets documented (`GOOGLE_CLIENT_ID`, `DEV_MODE`, …) |
| `deploy/mysql-init.sql` | Database bootstrap |
| `frontend/Dockerfile` · `backend/Dockerfile` | Prod images |
| `frontend/netlify.toml` | Static-demo deploy (no backend needed) |

Downloadable bundle: `cryptora-deploy-bundle.zip` (repo minus node_modules/dist).

## Status & honesty → `IMPLEMENTATION_STATUS.md`

Implemented / Partial / Roadmap ledger. Auth (PBKDF2 + JWT + Google verify +
hashed OTP), ownership checks, audit log, and reports are real and tested;
Google/SMS light up when you add provider keys (otherwise clearly labelled).
