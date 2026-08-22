# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial Alembic revision covering every table, column, index, unique
  constraint and foreign key, so a production database can be created without
  the application's development-only `create_all` path.
- The `api` container runs `alembic upgrade head` before starting uvicorn.
- CI job that searches the entire git history for committed credentials, and a
  weekly schedule so the dependency and static-analysis audits re-run even when
  nothing is pushed.

### Changed
- `.gitignore` now also covers certificates, PKCS#12 keystores, SSH private
  keys and `credentials.json`.
- The test suite mints its encryption key at run time instead of carrying a
  committed one.

### Fixed
- Production start-up refuses a configuration that lets anyone self-register
  into the writable `analyst` role; open registration in production must hand
  out the read-only `viewer` role or be disabled.

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
- Configurable risk-scoring engine, correlation graph and campaign clustering.
- STIX 2.1 and MISP import/export.
- REST API with JWT authentication, API keys, RBAC, bulk operations and a live
  SSE stream, plus a server-rendered analyst dashboard.
- Celery workers, maintenance scripts, container image, Compose stack and Nginx
  reverse-proxy configuration.
- Test suite and a CI pipeline running ruff, mypy, pytest and bandit.
- Architecture, security and deployment guides.

[Unreleased]: https://github.com/mojtaba-py-code/cyber-threat-intelligence-platform/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/mojtaba-py-code/cyber-threat-intelligence-platform/compare/v1.1...v1.1.0
[1.1]: https://github.com/mojtaba-py-code/cyber-threat-intelligence-platform/releases/tag/v1.1
