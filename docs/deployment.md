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
(scheduler), `nginx` (reverse proxy on :80). Every service restarts unless
stopped and runs with `no-new-privileges`.

> **Terminate TLS before exposing this.** nginx listens on :80 only — the
> stack cannot ship a certificate — so tokens and API keys would travel in
> clear text. Mount certificates and uncomment the TLS server block at the
> bottom of `deploy/nginx.conf`, or put a TLS-terminating load balancer in
> front and forward `X-Forwarded-Proto`.

## 2b. Create the first administrator
Admins are minted from a shell, not over HTTP:
```bash
docker compose exec api python -m app.scripts.create_admin --email you@example.com
```
Set `TIP_ADMIN_PASSWORD` to avoid the interactive prompt in automation. Running
it again promotes and re-enables an existing account, which is also how you
recover if the last admin is locked out.

## 3. Database migrations
The API auto-creates tables only in non-production; in production the schema
comes from Alembic. The `api` service runs `alembic upgrade head` before
uvicorn starts, so a fresh stack migrates itself. To apply migrations by hand
(or to check where a database stands):
```bash
docker compose exec api alembic upgrade head
docker compose exec api alembic current
```
After changing a model, generate the next revision against a running database
and commit it:
```bash
docker compose exec api alembic revision --autogenerate -m "describe the change"
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
