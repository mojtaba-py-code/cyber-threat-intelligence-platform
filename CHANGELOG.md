# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-09-06

### Security
- **Spreadsheet formula injection in the CSV export.** Indicator tags were
  unvalidated free text and were written straight into the export, so a tag
  beginning `=`, `+`, `-` or `@` — arriving from an imported vendor report —
  became a live formula when an analyst opened the file. Tags are now
  constrained to a label character set on the way in, and every exported cell
  is neutralised on the way out so rows stored before that validation are
  covered too. Markdown exports escape table pipes.
- **Enrichment now honours the SSRF guard it advertised.** The engine built a
  guard and never called it, while the README, the architecture diagram and the
  architecture guide all said enrichment ran behind it. Live DNS resolution
  goes through it: `OUTBOUND_ALLOWED_HOSTS` is enforced, and answers in private
  space are discarded rather than written into an enrichment record.
- **SSRF guard refuses shared address space.** `ip_is_public` tested a list of
  flags that does not include `100.64.0.0/10` (RFC 6598 carrier-grade NAT), so
  the guard would fetch from it — the range cloud platforms use for internal
  services. It now requires `is_global` as well.
- **A role change or a disabled account takes effect immediately.** The
  principal's role came from the bearer token, so a demotion did nothing until
  the token expired, and no path checked whether the account was still enabled.
  Both are now read from the account row on every request, as the API-key path
  already did.
- **The login lockout no longer disappears during a Redis outage.** Read paths
  returned "not locked" when the backend was unreachable, turning a cache
  outage into unlimited password guessing. Every operation now degrades onto an
  in-process counter instead.
- A JWT without a `role` claim is rejected rather than defaulting to the
  writable `analyst` role.

### Added
- **User administration** (`/api/v1/admin/*`, gated on `admin:manage`): list
  accounts, change a role, enable or disable an account. The `admin` role and
  its permission existed but nothing granted the role and no endpoint required
  the permission, so neither could ever be used.
- `python -m app.scripts.create_admin` mints or recovers the first
  administrator out-of-band — an endpoint that grants admin is an endpoint an
  attacker can call. The service refuses to demote or disable the last active
  admin, or to let an admin remove their own access.
- **Encryption-key rotation is reachable from configuration.**
  `MASTER_ENCRYPTION_KEY` accepts a comma-separated list: the first key
  encrypts, the rest only decrypt. `MultiFernet` rotation was implemented but
  only ever handed a single key.
- CI: per-job timeouts and a concurrency group; the base image is pinned by
  digest and tracked by Dependabot's new `docker` ecosystem.
- Tests that pin the dependency manifests together and assert the base image
  stays digest-pinned.
- Initial Alembic revision covering every table, column, index, unique
  constraint and foreign key, so a production database can be created without
  the application's development-only `create_all` path.
- The `api` container runs `alembic upgrade head` before starting uvicorn.
- CI job that searches the entire git history for committed credentials, and a
  weekly schedule so the dependency and static-analysis audits re-run even when
  nothing is pushed.

### Changed
- nginx: `limit_req_status 429` instead of nginx's default 503; the SSE route
  has its own connection-open limit; duplicate security headers are hidden from
  the upstream so each is sent once; the health probe is an exact-match
  location so neighbouring paths are not also exempted.
- Compose: every service restarts unless stopped and runs with
  `no-new-privileges`; `beat` gets the same `DATABASE_URL` override as the rest
  (it was inheriting a `localhost` DSN pointing at its own container); `worker`
  and `beat` wait for healthy dependencies.
- `REGISTRATION_DEFAULT_ROLE` is validated against the role enum — a typo
  silently downgraded every new account to read-only.
- HSTS is only sent on requests that arrived over TLS, and the root endpoint
  advertises `/docs` only when the docs are actually served.
- Search terms are escaped for `LIKE`, so `%` and `_` match literally.
- Removed a rate-limit exemption for `/metrics`, which does not exist.
- `dnspython` is no longer used: guarded resolution goes through the standard
  library, removing an import that was declared in neither manifest and present
  only transitively.
- `.gitignore` now also covers certificates, PKCS#12 keystores, SSH private
  keys and `credentials.json`.
- The test suite mints its encryption key at run time instead of carrying a
  committed one.
- `.env.example` leaves the interactive API docs on, so the quick start's link
  to `/docs` works on a fresh checkout. Production forces them off regardless
  of the setting, which is where hiding the API map actually matters.
- The README's Python badge now matches the `>=3.11` floor the package
  declares, instead of claiming 3.12.

### Fixed
- Production start-up refuses a configuration that lets anyone self-register
  into the writable `analyst` role; open registration in production must hand
  out the read-only `viewer` role or be disabled.
- Comma-separated list settings (`CORS_ORIGINS`, `OUTBOUND_ALLOWED_HOSTS`,
  `TRUSTED_PROXY_CIDRS`) load again. pydantic-settings treats a list field as
  complex and JSON-decodes it at the source, before any validator runs, so the
  values shipped in `.env.example` — including an empty one — aborted start-up
  with a decode error. Both the documented quick start and `docker compose up`
  failed on a fresh checkout; the tests missed it because they never set those
  variables. The fields opt out with `NoDecode` and are covered by tests that
  load the real `.env.example`.

## [1.1.0] - 2026-08-14

### Added
- Bandit and pip-audit stages in the pipeline, auditing the resolved dependency
  tree rather than only the direct requirements.
- Repository documentation: security policy, contributing guide, code of
  conduct, issue forms and README badges and dashboard screenshots.

### Changed
- Dependency floors raised past releases with published CVEs.
- GitHub Actions pinned to full commit SHAs and the workflow token scoped to
  read-only.

## [1.1] - 2026-08-10

### Added
- Indicator extraction, normalisation and defanging across the supported IOC
  types.
- Offline-first feed collectors with retry and circuit breaking, and a
  provider-backed enrichment pipeline.
- Configurable risk-scoring engine and an indicator correlation graph
  (neighbours, pivots, attack chains, subgraph export).
- STIX 2.1 and MISP import/export.
- REST API with JWT authentication, API keys, RBAC, bulk operations and a live
  SSE stream, plus a server-rendered analyst dashboard.
- Celery workers, maintenance scripts, container image, Compose stack and Nginx
  reverse-proxy configuration.
- Test suite and a CI pipeline running ruff, mypy, pytest and bandit.
- Architecture, security and deployment guides.

[Unreleased]: https://github.com/mojtaba-py-code/cyber-threat-intelligence-platform/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/mojtaba-py-code/cyber-threat-intelligence-platform/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/mojtaba-py-code/cyber-threat-intelligence-platform/compare/v1.1...v1.1.0
[1.1]: https://github.com/mojtaba-py-code/cyber-threat-intelligence-platform/releases/tag/v1.1
