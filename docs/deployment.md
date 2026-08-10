# Deployment guide

## Prerequisites
- Docker + Docker Compose (or Python 3.11+, PostgreSQL 14+, Redis 6+).
- Secrets from `python -m app.scripts.gen_keys`.

## 1. Configure
```bash
cp .env.example .env
python -m app.scripts.gen_keys      # paste keys into .env
```
Production settings:
```
APP_ENV=production
APP_DEBUG=false
ENABLE_LIVE_COLLECTORS=false        # flip to true only when ready
CORS_ORIGINS=https://your-frontend.example
```
Add provider API keys (`ABUSEIPDB_API_KEY`, `OTX_API_KEY`, …) only when enabling
live collection.

## 2. Run with Docker Compose
```bash
docker compose up --build -d
docker compose ps
docker compose logs -f api
```
Services: `db` (Postgres), `redis`, `api`, `worker` (Celery), `beat`
(scheduler), `nginx` (reverse proxy on :80).

## 3. Database migrations
The API auto-creates tables only in non-production. In production use Alembic:
```bash
docker compose exec api alembic revision --autogenerate -m "init"
docker compose exec api alembic upgrade head
```

## 4. TLS / HTTPS
Terminate TLS at Nginx (enable the 443 block in `deploy/nginx.conf`) with certs
from your CA / Let's Encrypt. HSTS is emitted by the app.

## 5. Health & readiness
- Liveness: `GET /api/v1/health`
- Readiness: `GET /api/v1/ready` (env + live-collector flag)
- The image ships a Docker `HEALTHCHECK`.

## 6. Scaling & observability
- Run multiple `api` and `worker` replicas.
- Move the rate limiter and auth stores to Redis across replicas.
- Ship structured JSON logs to your log stack; request timing is emitted via
  `x-response-time-ms`.

## 7. Backups & DR
- Back up PostgreSQL regularly.
- **Back up `MASTER_ENCRYPTION_KEY` securely** — without it, encrypted provider
  keys cannot be recovered.

## CI/CD
`.github/workflows/ci.yml` runs lint, format check, type check, tests with an
80% coverage gate, and a Docker build on every push/PR.
