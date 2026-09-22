# CRYPTORA — Deployment Guide

**Team KRYPTX · SIH PS-26164 · "Encrypt. Protect. Trust."**
Version 1.0 · 20 Sep 2026 · Works with `cryptora-deploy-bundle.zip`

---

## 1. What you are deploying

| Piece | Technology | Port (dev) | Port (prod) |
|---|---|---|---|
| Frontend — scan engine + all 15 UI steps | React 18 + Vite 5 (static SPA after build) | 5173 | 8080 (via nginx) |
| Backend — auth, projects, saved scans, audit | FastAPI + Uvicorn (Python 3.12) | 8000 | 8000 (internal, proxied as `/api`) |
| Database — users, projects, scans | SQLite file (dev) / MySQL 8 (prod) | — | 3306 (internal only) |

**Key architectural fact:** the cryptographic scan engine runs **100% in the browser**. The backend only stores accounts, projects and saved scan metadata — it never sees your source code. That is why the app works fully offline-capable for scanning, and why deployment is simple.

```
                    ┌──────────────────────────────────┐
  Browser           │  React SPA (port 5173 dev / 8080  │   Scan engine runs HERE
  (your laptop)     │  prod via nginx)                  │   (JS, in-page, no upload)
                    └───────┬──────────────────┬───────┘
                            │                  │ GitHub REST + raw.githubusercontent
                            │ /api (auth,      │ (only when YOU
                            │ projects, scans) │  scan a repo)
                    ┌───────▼──────┐   ┌───────▼────────┐
  Server            │ FastAPI :8000 │   │ api.github.com │  (public internet)
                    └───────┬──────┘   └────────────────┘
                            │ SQL
                    ┌───────▼──────┐
                    │ MySQL 8 /    │
                    │ SQLite (dev) │
                    └──────────────┘
```

### Folder map (inside the bundle)

```
cryptora/
├── frontend/               # React app (npm run dev / npm run build)
│   ├── src/                # engine (lib/) + UI (components/, pages)
│   ├── Dockerfile          # multi-stage: node build → nginx serve
│   └── netlify.toml        # static-hosting config
├── backend/                # FastAPI app (app/main.py), requirements.txt, Dockerfile
├── deploy/
│   ├── deploy.sh           # one-command production deploy
│   ├── .env.example        # copy to .env and fill secrets
│   ├── nginx.conf          # prod reverse proxy (/api → backend)
│   ├── mysql-init.sql      # DB bootstrap
│   └── DEPLOYMENT.md       # short-form notes
├── docker-compose.yml      # local dev stack
├── docker-compose.prod.yml # production stack (web + backend + mysql)
├── demo-fixtures/          # sample files for practice scans
├── README.md
└── IMPLEMENTATION_STATUS.md
```

---

## 2. Prerequisites

| Option | You need |
|---|---|
| A — Local demo/dev | Node.js 20+, Python 3.11+, internet (for GitHub repo scans) |
| B — Docker production (recommended) | Docker Engine 24+ with `docker compose` plugin |
| C — VPS / cloud host | Ubuntu 22.04+ VM (1 vCPU / 2 GB RAM minimum), a domain (for HTTPS) |
| D — Split hosting | A static host (Netlify/Vercel) + a Python host (Render/Railway/VPS) |

No paid APIs, no license keys, no GPU. Total prod image footprint ≈ 600 MB.

---

## 3. Option A — Local run (5 minutes, for development & jury demo)

```bash
# 1. Unzip the bundle and enter it
unzip cryptora-deploy-bundle.zip && cd cryptora

# 2. Backend (terminal 1)
cd backend
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
# → http://localhost:8000/health  should return {"status":"ok",...}
# → http://localhost:8000/docs    interactive API docs

# 3. Frontend (terminal 2)
cd frontend
npm install
npm run dev
# → http://localhost:5173
```

The app auto-connects to `http://localhost:8000` — no configuration needed.
The database is a local SQLite file created automatically on first run.

**Smoke test (do this before any demo):**
1. Open `http://localhost:5173` → Executive Overview loads.
2. Click **Upload / Analyze → Paste Code** → paste any code → **Scan**.
3. You must land on Step 1 Discovery with a live log and findings (if crypto is present).
4. Click every sidebar step 1–14; each must render with zero console errors (F12 → Console).

---

## 4. Option B — Docker production (recommended, one command)

```bash
unzip cryptora-deploy-bundle.zip && cd cryptora

# 1. Create secrets file
cp deploy/.env.example deploy/.env

# 2. Fill the secrets (see §6). At minimum:
#    MYSQL_ROOT_PASSWORD, MYSQL_PASSWORD, CRYPTORA_JWT_SECRET, FRONTEND_ORIGIN
nano deploy/.env        # or any editor

# 3. Build + start everything
./deploy/deploy.sh
# → App:     http://localhost:8080
# → Health:  http://localhost:8080/health
# → API docs:http://localhost:8080/docs
```

What `deploy.sh` does: checks Docker → creates `.env` if missing → `docker compose -f docker-compose.prod.yml up -d --build` → waits for backend health → prints URLs.

**Useful commands:**

```bash
docker compose -f docker-compose.prod.yml logs -f            # follow logs
docker compose -f docker-compose.prod.yml logs backend       # backend only
docker compose -f docker-compose.prod.yml ps                 # status
docker compose -f docker-compose.prod.yml down               # stop (data kept in mysql-data volume)
docker compose -f docker-compose.prod.yml down -v            # stop AND wipe database
docker compose -f docker-compose.prod.yml up -d --build backend  # redeploy backend only
```

**Updating to a new bundle version:** stop → replace `frontend/` + `backend/` folders → `up -d --build` → verify `/health`. The MySQL volume survives.

---

## 5. Option C — Public VPS deployment (Ubuntu 22.04, ~20 minutes)

```bash
# 1. On the VPS: install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && newgrp docker

# 2. Copy the bundle up and deploy
scp cryptora-deploy-bundle.zip user@YOUR_SERVER:/opt/
ssh user@YOUR_SERVER
cd /opt && unzip -o cryptora-deploy-bundle.zip && cd cryptora
cp deploy/.env.example deploy/.env
nano deploy/.env     # set FRONTEND_ORIGIN=https://cryptora.yourdomain.com + secrets
./deploy/deploy.sh

# 3. Add HTTPS with Caddy (simplest reverse proxy, auto-TLS)
sudo apt install -y caddy
sudo tee /etc/caddy/Caddyfile <<'EOF'
cryptora.yourdomain.com {
    reverse_proxy localhost:8080
}
EOF
sudo systemctl reload caddy
```

Point your domain's A-record at the VPS first. Caddy fetches a Let's Encrypt certificate automatically. The app detects same-origin `/api` by itself — set `FRONTEND_ORIGIN` to the public URL so backend CORS/login redirects match.

**Minimum firewall (ufw):** allow 22, 80, 443; deny 8080/8000/3306 from the internet (Caddy talks to 8080 locally).

---

## 6. Option D — Split hosting (static frontend + hosted backend)

Useful when the jury/college network blocks your VPS, or for a free-tier demo:

1. **Backend** → Render / Railway / any VPS running `backend/` (`uvicorn app.main:app --host 0.0.0.0 --port 8000`, or their Docker deploy using `backend/Dockerfile`). Note the public URL, e.g. `https://cryptora-api.onrender.com`.
2. **Frontend** → Netlify / Vercel: drag-drop `frontend/dist` after `npm run build`, or connect the repo (build command `npm run build`, publish dir `dist`; `netlify.toml` is already configured).
3. In the app, open **Sign in** → **Backend URL** field → paste the backend URL → Save. Every browser remembers its own setting; scanning works even with no backend at all.

---

## 7. Environment variables reference (`deploy/.env`)

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `MYSQL_ROOT_PASSWORD` | ✅ prod | — | MySQL root (min 32 random chars) |
| `MYSQL_DATABASE` | ✅ prod | `cryptora` | App database name |
| `MYSQL_USER` | ✅ prod | `cryptora` | App DB user |
| `MYSQL_PASSWORD` | ✅ prod | — | App DB password (min 32 random chars) |
| `CRYPTORA_JWT_SECRET` | ✅ prod | dev-only | Signs login tokens — `openssl rand -hex 32` |
| `CRYPTORA_JWT_TTL` | no | `86400` | Login token lifetime (seconds) |
| `FRONTEND_ORIGIN` | ✅ public | `http://localhost:8080` | Public app URL (CORS + links) |
| `DEV_MODE` | no | `false` | `true` = echo OTP codes in API response (demos only!) |
| `GOOGLE_CLIENT_ID` | no | empty | Enables Google Sign-In tab (OAuth client ID) |
| `DATABASE_URL` | auto | composed | Full SQLAlchemy URL — compose file builds it for you |

Generate secrets with: `openssl rand -hex 32` (run twice — root + user + JWT = three values).

---

## 8. Verification checklist (run after every deploy)

- [ ] `GET /health` returns `{"status":"ok","service":"cryptora-api",...}`
- [ ] `GET /api/config` returns JSON (google/otp flags)
- [ ] App loads at the public URL with no console errors
- [ ] Paste-Code scan → lands on Discovery → findings render → all 15 sidebar steps render
- [ ] GitHub scan of a small public repo completes (tests outbound internet)
- [ ] Sign up → log in → save a scan to a project → reload → scan restorable (tests DB)
- [ ] Reports page → **Print / Download PDF** produces the executive report
- [ ] (prod) HTTP → HTTPS redirect works; `/docs` is reachable (disable in prod if desired)

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `vite: not found` / blank page locally | `node_modules` missing | `cd frontend && npm install` |
| `No module named uvicorn` | pip packages missing | `pip install -r backend/requirements.txt` |
| Sidebar "does nothing" | Stale cached preview / old tab | Hard refresh (`Ctrl+Shift+R`); use the current preview URL |
| Every page says "No scan yet" | No scan has been run (by design) | Upload / Analyze → run any scan first |
| Scan drawer shows an error on GitHub repos | Rate limit (60 req/hr/IP, unauthenticated) | Wait an hour, use a smaller repo, or scan via ZIP upload |
| Sign-in says "Backend unreachable" | API down or wrong Backend URL | Check `:8000/health`; on Sign-in page set the correct Backend URL |
| `docker compose` mysql keeps restarting | Bad/changed `MYSQL_PASSWORD` with old volume | `down -v` (wipes DB) or restore the original password |
| Backend healthy but app shows demo mode | `FRONTEND_ORIGIN` mismatch / CORS | Set `FRONTEND_ORIGIN` to the exact public URL, redeploy backend |
| Google tab says "not configured" | `GOOGLE_CLIENT_ID` empty | Expected — email + phone auth still work; add the ID to enable |
| OTP code never arrives by SMS | No SMS provider configured | Expected in this build — use `DEV_MODE=true` for demos (code is echoed) |
| Port 8080 already in use | Clash with another service | Change `"8080:80"` mapping in `docker-compose.prod.yml` |

**Log triage order:** `docker compose logs backend` → `logs web` → `logs mysql` → browser devtools Console → backend `/docs` "Try it out".

---

## 10. Security & maintenance notes

- **Never commit `deploy/.env`.** Rotate `CRYPTORA_JWT_SECRET` if ever exposed (forces all users to re-login — safe).
- **Backups:** `docker run --rm -v cryptora_mysql-data:/data -v $(pwd):/b alpine tar czf /b/mysql-backup.tgz /data` — schedule weekly.
- The scanner **never executes** uploaded code (static inspection only) and redacts secret *values* from display — but treat scan *results* as sensitive (they describe real vulnerabilities) and serve only over HTTPS in public deployments.
- Keep images fresh: `docker compose -f docker-compose.prod.yml pull && up -d` monthly; rebuild after bundle updates.
- Resource sizing: 1 vCPU / 2 GB RAM comfortably serves a 50-user classroom demo; scanning load lives in each visitor's browser, not your server.

---

## 11. Demo-day quick start (jury presentation)

1. Boot the stack **30 minutes early**; run the §8 checklist; keep a terminal with `logs -f backend` hidden but handy.
2. Pre-run one impressive scan (e.g. `postquantdev/postquant`) so every step is populated even if venue Wi-Fi dies — then run a **live** Paste-Code scan on stage to prove it's real.
3. Have `demo-fixtures/` ready for offline file-upload scans.
4. Talking order: Landing → Upload → Discovery live log → Overview numbers → CBOM evidence → Break-first → Roadmap → Reports PDF → Sign-in/cloud save.
5. If GitHub rate-limits you on stage: smile, switch to the ZIP-upload tab — "this is exactly why we support offline evidence capture."

*Good luck, Team KRYPTX. Encrypt. Protect. Trust.*
