#!/usr/bin/env bash
# CRYPTORA one-command production deploy: frontend + backend + MySQL.
# Run from the repo ROOT:  ./deploy/deploy.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "── CRYPTORA deploy ─────────────────────────────"
command -v docker >/dev/null || { echo "❌ docker not found. Install Docker Desktop / docker engine first."; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "❌ 'docker compose' not found."; exit 1; }

if [ ! -f deploy/.env ]; then
  echo "→ creating deploy/.env from example — EDIT IT before going public."
  cp deploy/.env.example deploy/.env
fi

echo "→ building + starting (this takes a few minutes first time)…"
docker compose --env-file deploy/.env -f docker-compose.prod.yml up -d --build

echo "→ waiting for backend health…"
for i in $(seq 1 40); do
  if curl -sf http://localhost:8080/health >/dev/null 2>&1; then break; fi
  sleep 3
done

echo ""
echo "✅ CRYPTORA is live:"
echo "   App:     http://localhost:8080  (→ set FRONTEND_ORIGIN + reverse proxy for public HTTPS)"
echo "   Health:  http://localhost:8080/health"
echo "   API docs:http://localhost:8080/docs"
echo ""
echo "Logs:  docker compose -f docker-compose.prod.yml logs -f"
echo "Stop:  docker compose -f docker-compose.prod.yml down"
