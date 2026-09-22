# CRYPTORA — Deployment Folder (Team KRYPTX · SIH PS-26164)

## Fastest path (production, one command)
```bash
cp deploy/.env.example deploy/.env
nano deploy/.env     # set MYSQL_* + CRYPTORA_JWT_SECRET + FRONTEND_ORIGIN
./deploy/deploy.sh   # → app live at http://localhost:8080
```

## Local demo path (5 minutes)
```bash
cd backend && pip install -r requirements.txt && python -m uvicorn app.main:app --port 8000
cd frontend && npm install && npm run dev   # → http://localhost:5173
```

## What's inside
| Path | Contents |
|---|---|
| `frontend/` | React 18 + Vite app (scan engine + 15 UI steps), PWA manifest, Dockerfile, netlify.toml |
| `backend/` | FastAPI API (auth, projects, scans), requirements.txt, Dockerfile |
| `deploy/` | `deploy.sh`, `.env.example`, `nginx.conf`, `mysql-init.sql`, notes |
| `docker-compose.yml` / `docker-compose.prod.yml` | Dev stack / prod stack (web + backend + mysql) |
| `demo-fixtures/` | Sample files for practice scans |
| `docs/CRYPTORA_Deployment_Guide.md` | Full deployment manual (all options, env vars, troubleshooting) |
| `docs/CRYPTORA_Project_Report.html` + `.pdf` | Jury report: what/why/how/stack/differences/Q&A + every screenshot |
| `README.md`, `IMPLEMENTATION_STATUS.md` | Project overview + build status |

Works on mobile + laptop (responsive + hamburger nav). Scanning works even with no backend (local demo mode).
Full instructions: open `docs/CRYPTORA_Deployment_Guide.md`. Live ports: app 5173 (dev) / 8080 (prod), API 8000.
