# Contributing

Thanks for taking a look. This is how I work on the project locally.

## Setup

```bash
make install           # pip install -e ".[dev]"
cp .env.example .env
make keys              # fills MASTER_ENCRYPTION_KEY and JWT_SECRET_KEY
```

With `APP_ENV=production` the application refuses to start unless both keys are
set (and `JWT_SECRET_KEY` is at least 32 characters), so generate them before
anything else.

Bring the stack up with Postgres and Redis:

```bash
make up                # docker compose up --build
make down
```

Or run the API alone against a local database:

```bash
make run               # uvicorn app.main:app --reload
make worker            # celery worker
make beat              # celery beat
```

## Before you push

Everything below runs in CI, so run it locally first:

```bash
make lint    # ruff check app tests
make type    # mypy app
make cov     # pytest with coverage
```

`make check` runs all three. `make format` fixes formatting in place.

## Conventions

- **Layers** — routers call services, services call repositories, repositories
  own the SQLAlchemy session. A router never touches the ORM directly.
- **Offline by default** — no code path may reach the network unless
  `ENABLE_LIVE_COLLECTORS` is on. New collectors ship a bundled sample so the
  test suite and a fresh clone both run with no outbound traffic.
- **Outbound requests** — anything that fetches a user-supplied URL goes
  through the SSRF guard in `app/core/ssrf.py`. No exceptions, including
  webhooks.
- **Types** — everything in `app/` is typed; mypy runs over the whole package.
- **Scoring** — the engine stays pure and deterministic: same indicator in,
  same score and same per-signal contributions out. No clock, no I/O.
- **Secrets** — encrypted at rest, redacted in logs. Never log a raw API key,
  token or indicator payload that could carry one.
- **Tests** — add tests with the change. External HTTP is always mocked.
- **Commits** — short imperative subject, a body explaining the *why*.

## Adding a collector

1. Implement the source in `app/collectors/providers.py`.
2. Add a bundled sample to `app/collectors/samples.py`.
3. Register it in `app/collectors/registry.py` — one line.
4. Cover it in `tests/test_collectors_enrichment.py`.

## Project layout

See [`docs/architecture.md`](docs/architecture.md) for the layer diagram and the
request flow, and [`docs/security.md`](docs/security.md) for the threat model.
