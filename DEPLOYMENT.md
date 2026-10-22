# Sentinel — Deployment Guide

A full-stack deployment of **Sentinel** runs two containers on a single host:

| Service   | Image            | Role                                                       |
|-----------|------------------|------------------------------------------------------------|
| frontend  | nginx:alpine     | Serves the Vite build, reverse-proxies `/api` → backend     |
| backend   | python:3.12-slim | FastAPI / uvicorn, SQLite on a named volume                |

The nginx config (`frontend/nginx.conf`) provides an SPA fallback (so client routes like `/findings/123` survive a refresh) and proxies `/api/` to the backend container — meaning the frontend is fully same-origin and `window.SENTINEL_API_BASE` can stay blank.

---

## Prerequisites

- **Docker Engine** ≥ 20.10
- **Docker Compose** v2 (`docker compose` plugin — run `docker compose version` to confirm)
- Open host port **8080** (frontend). The backend (8000) is bound to `127.0.0.1` only — it is reachable via the `/api` proxy, never directly exposed to the internet.

---

## Quick start (local single-host)

```bash
# 1. (optional) generate a local .env from the template
copy .env.example .env      # Windows
cp .env.example .env        # macOS / Linux

# 2. build & launch everything in the background
docker compose up --build -d

# 3. tail logs while it warms up
docker compose logs -f

# 4. open the app
#    http://localhost:8080
```

First boot builds the two images (a few minutes). The backend healthcheck must pass before nginx starts accepting `/api` traffic — `depends_on: condition: service_healthy` handles that automatically.

**Demo login** (defined in `backend/app/api/auth.py`):
- email: `demo.user@example.com`
- password: `DemoPass123!`  *(or any email with the password `demo`)*

---

## Daily operations

```bash
# stop (keeps the data volume + containers)
docker compose stop

# start again
docker compose start

# rebuild after a code change
docker compose up --build -d

# tear down containers (data volume is preserved by default)
docker compose down

# tear down AND delete the SQLite data volume
docker compose down -v
```

---

## Configuration

All runtime knobs live in `.env` (see `.env.example` for the full catalogue).

| Variable         | Default                              | Purpose                                              |
|------------------|--------------------------------------|------------------------------------------------------|
| `FRONTEND_ORIGIN`| `http://localhost:8080`              | CORS allow-list entry for the backend.               |
| `DATABASE_URL`   | `sqlite:////app/data/sentinel.db`    | SQLAlchemy URL; the host path is the volume mount.   |
| `ZAP_ENABLED`    | `false`                              | `true` enables real OWASP ZAP scans (needs a ZAP).   |
| `ZAP_API_URL`    | `http://zap:8080`                    | ZAP daemon address (only when `ZAP_ENABLED=true`).   |
| `ALLOW_LIST`     | *(empty)*                            | Comma-separated scanner target allow-list.           |
| `SENTINEL_API_BASE` | *(empty)*                         | Frontend override; leave blank for same-origin `/api`.|

> **Scanning safely:** `ZAP_ENABLED=false` is intentional — the backend mocks scanner output so you can demo the entire UI without touching third-party hosts. Flip it to `true` only when you own the target and have a ZAP instance reachable from the backend container.

---

## Production hardening checklist

Before exposing Sentinel to the public internet:

1. **TLS** — put a reverse proxy / load balancer (Caddy, Traefik, Cloudflare, ALB) in front of nginx to terminate HTTPS. Set `FRONTEND_ORIGIN` to your real `https://` URL.
2. **Database** — swap SQLite for Postgres: add a `postgres` service to `docker-compose.yml`, set `DATABASE_URL`, and remove the `sentinel-data` SQLite volume.
3. **Secrets** — the demo auth token (`demo-token-12345`) and seed password (`DemoPass123!`) are **not for production**. Replace the auth module with real credential hashing + per-user tokens before launch.
4. **Resource limits** — add `deploy.resources.limits` (CPU/memory) to each service in `docker-compose.yml`.
5. **Scanners** — leave `ZAP_ENABLED=false` unless you have a hardened ZAP setup and explicit permission to scan the configured targets.
6. **Backups** — the `sentinel-data` volume contains all scan/user state; set up periodic volume snapshots (e.g. `docker run --rm -v sentinel-data:/data alpine tar czf - /data > backup.tgz`).

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `docker compose` is "not recognized" | Install the Compose v2 plugin (Docker Desktop bundles it) or upgrade Docker Engine. |
| Frontend loads but `/api/*` returns 502/504 | Backend container failed its healthcheck. Run `docker compose logs backend` and check `DATABASE_URL` / missing env vars. |
| Refresh on `/findings/123` 404s | You're not serving through the bundled nginx config. Ensure `frontend/nginx.conf` is copied into the image (it is, via the Dockerfile). |
| CORS error in browser console | Set `FRONTEND_ORIGIN` in `.env` to the exact origin you load the app from (scheme + host + port). |
| Changes not reflected after rebuild | `docker compose build --no-cache` then `up -d`. |
| Want to reset all data | `docker compose down -v` (the `-v` deletes the data volume). |
