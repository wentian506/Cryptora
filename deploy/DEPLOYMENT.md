# CRYPTORA — Deployment Guide

All files used to deploy live in this folder (`deploy/`) plus the Dockerfiles
and compose files at the repo root. Three deployment options:

## Option A — Full production (recommended): Docker Compose

Runs **frontend (nginx) + backend (FastAPI) + MySQL** with healthchecks.

```bash
# from repo root
cp deploy/.env.example deploy/.env
nano deploy/.env        # set JWT secret + MySQL passwords + domain
./deploy/deploy.sh
# → App at http://localhost:8080
```

What each file does:

| File | Purpose |
|---|---|
| `docker-compose.prod.yml` | Prod stack: `web` (nginx+SPA) → `backend` (uvicorn) → `mysql` (8.0, volume) |
| `docker-compose.yml` | Local dev stack (Vite dev + backend scaffold) |
| `deploy/nginx.conf` | SPA fallback, `/api` proxy, gzip, asset caching |
| `deploy/.env.example` | Every secret/env var documented; copy to `deploy/.env` |
| `deploy/mysql-init.sql` | Creates `cryptora` database (tables auto-created by backend) |
| `deploy/deploy.sh` | One-command build + health-checked startup |
| `frontend/Dockerfile` | Multi-stage: node build → nginx serve |
| `backend/Dockerfile` | Python 3.12 + uvicorn |

Public HTTPS: put Caddy/Nginx/Cloudflare in front of port 8080, set
`FRONTEND_ORIGIN=https://your-domain`, and set the app's backend URL field
(on the Sign-in page) to `https://your-domain` — the SPA calls same-origin `/api`.

## Option B — Static demo (Netlify / Vercel / GitHub Pages)

The scanner runs fully in-browser, so the frontend deploys with **zero backend**.
Sign-in is optional; "Continue without account" gives the full scan experience.

```bash
cd frontend && npm install && npm run build   # → dist/
# Netlify: base=frontend, command="npm run build", publish="frontend/dist"
# (frontend/netlify.toml already contains this)
```

Point the app at a hosted backend by entering its URL on the Sign-in page.

## Option C — Manual VPS

```bash
# backend
cd backend && pip install -r requirements.txt
export DATABASE_URL="mysql+pymysql://cryptora:SECRET@127.0.0.1:3306/cryptora"
export CRYPTORA_JWT_SECRET="$(openssl rand -hex 32)"
uvicorn app.main:app --host 127.0.0.1 --port 8000
# frontend: serve frontend/dist via any static server + proxy /api → 8000
```

## Enabling Google Sign-In

1. Google Cloud Console → APIs & Services → Credentials → Create **OAuth client ID (Web)**.
2. Authorized JavaScript origins: your domain (e.g. `https://cryptora.example.com`).
3. Set `GOOGLE_CLIENT_ID` in `deploy/.env`, restart backend.
4. The app's Google tab lights up; tokens are verified server-side via tokeninfo.

## Enabling real SMS OTP

Set `TWILIO_*` (or MSG91) vars and wire the sender in `backend/app/auth.py`
(`otp_request` — marked hook). Without a provider, `DEV_MODE=true` echoes the
test code to the requester (local testing only, never in prod).

## Backup / update

```bash
# backup mysql volume
docker compose -f docker-compose.prod.yml exec mysql \
  mysqldump -ucryptora -p"$MYSQL_PASSWORD" cryptora > backup.sql
# update to new version
git pull && docker compose --env-file deploy/.env -f docker-compose.prod.yml up -d --build
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Backend unreachable` in app | Backend not running / wrong Backend URL on Sign-in page |
| Google tab "not configured" | `GOOGLE_CLIENT_ID` empty — email/phone still work |
| OTP "provider not configured" | Set `DEV_MODE=true` for local tests, or add SMS vars |
| MySQL won't start | Check `MYSQL_*` in `deploy/.env`; delete volume `mysql-data` to reset (wipes data) |
| Port 8080 busy | Change `ports:` in `docker-compose.prod.yml` |
