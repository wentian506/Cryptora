# CRYPTORA — Implementation Status (honest ledger)

## IMPLEMENTED ✅ (working, tested)

- Landing page (hero, how-it-works, platform, PQC, security/trust, contact)
- Auth: email signup/login (PBKDF2 210k + HS256 JWT), Google ID-token verify
  (server-side tokeninfo + audience check), phone OTP (SHA-256 hash, 10-min
  expiry, 5/hr rate limit) — Google/SMS need provider keys, otherwise labelled
- Persistence: User → Org → Project → Scan → Finding + audit log; SQLite dev,
  MySQL prod (`DATABASE_URL`); ownership check on every read/write (IDOR-safe —
  tested: cross-user read → 404, no token → 401, wrong password → 401)
- Cloud sync UI: save/restore/delete scans per project when signed in
- Reports page: executive report + Print/Download-PDF + Findings CSV +
  Report/CBOM JSON exports (all from live scan)
- 14-step sidebar (numbered, count badges), live scan log + SCANNING badge,
  8-layer engine telemetry, PQC detection (ML-KEM/ML-DSA/SLH-DSA), TLS-version
  split, file-level byte entropy, lockfile/minified skip options, two-pane CBOM
  with explainable scores, SBOM + ZIP exports, radial graphs, Mosca presets,
  exposure/agility gauges, attack-surface map, entropy chart, AI chips +
  methodology notes; responsive laptop/tablet/phone layouts
- Black UI (15 pages incl. Reports), 9-mode upload center, deterministic in-browser scanner,
  risk engine + Mosca, PQC/hybrid recs (FIPS 203/204/205), CycloneDX CBOM,
  dep graph, kanban, drift snapshots, rescan validation, local AI explainer
- Deploy kit: `deploy/` (compose prod, nginx, .env.example, init.sql, deploy.sh,
  DEPLOYMENT.md) + Dockerfiles + Netlify static config + demo fixtures

## PARTIAL / PROTOTYPE 🟡

- AST: JS/TS + Python AST-lite; full tree-sitter AST for Java/C/C++/Go/Rust = roadmap
- Binary analysis: static strings/format/hash only (no disassembly)
- Google/GIS: real flow, needs GOOGLE_CLIENT_ID. SMS OTP: hook ready, needs
  provider keys (DEV_MODE echo for local tests, prod default off)
- DB migrations: auto-create on boot; Alembic migration chain = roadmap
- RBAC roles exist in schema (owner/admin/analyst/developer/viewer); single-user
  enforcement today, multi-user org invites = roadmap

## ROADMAP 🔴 (not implemented — never faked in UI)

- Isolated scanner workers (queue, retries, sandbox, resource limits)
- GitHub OAuth app (demo uses public read-only fetch), transitive dep resolution
- Container image pull-scan, cloud LLM explanations, team invites, PDF-server render
