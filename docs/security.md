# Security model

Security is a primary design goal — both *of* the platform and *for* the analyst
handling hostile data. This document describes the controls.

## Handling hostile input safely

- **Defanging.** Indicators are stored and displayed in defanged form
  (`hxxp://evil[.]com`) so they can never be accidentally clicked or resolved;
  input is refanged only for classification.
- **SSRF guard** (`app/core/ssrf.py`). Any fetch of a *user-supplied* URL is
  validated first: only `http(s)`, and the host must resolve **exclusively** to
  public unicast addresses — loopback, private, link-local (incl. the
  `169.254.169.254` cloud-metadata endpoint), reserved, multicast and
  unspecified ranges are rejected. The test is Python's `is_global`, which
  carries IANA's special-purpose registry, *plus* those explicit flags: the
  registry is what rules out `100.64.0.0/10` (RFC 6598 carrier-grade NAT), which
  is neither "private" nor "loopback" and is exactly where cloud platforms put
  internal services. An optional operator allow-list narrows this further.
  Fixed provider API hosts bypass the guard (they are not user input).
- **Guarded resolution for enrichment.** Live DNS enrichment resolves a
  submitted host, which is user input even though nothing is fetched, so it
  goes through the same guard: the allow-list is enforced and answers in
  private space are discarded instead of being written into an enrichment
  record, where they would map the internal network for whoever submitted the
  indicator.
- **Offline-first.** With `ENABLE_LIVE_COLLECTORS=false` (default) the platform
  makes no outbound calls at all — collectors and enrichers serve bundled,
  clearly-labelled sample/heuristic data.

## Authentication & authorization

- **Passwords:** Argon2id (64 MiB, t=3) with transparent rehash-on-verify.
- **JWTs:** access + refresh with a `type` claim and unique `jti`; type
  confusion rejected on decode. Refresh tokens are **rotated** (one-time use) via
  a revocation store. **Logout revokes both** the refresh token and the current
  access token, and every request checks the access `jti` against the store, so
  logout ends the session immediately rather than lingering until expiry.
- **API keys:** generated once, stored only as a SHA-256 hash with a non-secret
  prefix; verified in constant time. Both bearer tokens and `X-API-Key` resolve
  to a role for RBAC. Deactivating a user (`is_active = false`) immediately
  disables their API keys as well.
- **RBAC:** explicit permission model (viewer / analyst / admin); endpoints
  check fine-grained permissions (e.g. `ioc:write`). A principal's role and
  enabled state are read from its account row on **every** request, not taken
  from the bearer token, so a demotion or a disabled account takes effect on
  the next call rather than lingering for the life of the token.
- **Administration** (`admin:manage`, `/api/v1/admin/*`): list accounts, change
  a role, disable an account. The first admin is minted out-of-band with
  `python -m app.scripts.create_admin`, so no HTTP path grants privilege. The
  service refuses to demote or disable the last active admin, and refuses to
  let an admin remove their own access, so an installation cannot be stranded.
- **Brute-force protection:** per-account lockout after repeated failures
  (`429` + `Retry-After`), complementing the per-IP rate limiter. Login runs a
  decoy Argon2 verify for unknown users to resist enumeration. The lockout is
  **Redis-backed in production** so it applies across every replica — a
  per-process counter would let an attacker simply spread attempts over the
  fleet. A cache outage does **not** disable the lockout: every operation falls
  back to an in-process counter, so protection narrows from fleet-wide to
  per-replica (what a single instance has anyway) instead of disappearing.
  Logins keep working and the degradation is logged.

## Secrets & data at rest

- Provider API keys are held as `SecretStr` (never rendered) and are encrypted
  with `SecretCipher` (Fernet via `MultiFernet`) when stored. Rotation is driven
  from configuration: `MASTER_ENCRYPTION_KEY` accepts a comma-separated list
  whose first entry encrypts and whose remaining entries only decrypt, so a
  retired key keeps existing ciphertext readable until `SecretCipher.rotate`
  has re-encrypted it.
- Structured logs run through a redaction processor that masks known-sensitive
  keys, so secrets cannot leak even if accidentally bound.
- Audit logs store only non-sensitive metadata.

## Web & transport hardening

- Security headers on every response (`X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Content-Security-Policy`, `Strict-Transport-Security`).
- **CSP with a per-response nonce for the dashboard.** The API-wide policy is
  `default-src 'self'`, which blocks inline code. The dashboard is a single
  self-contained file, so instead of weakening the policy with `'unsafe-inline'`
  — which would equally authorise any *injected* script — each response mints a
  fresh nonce carried only by its own `<style>` and `<script>` blocks. The page
  therefore contains no inline event handlers or `style=` attributes: behaviour
  is wired by one delegated listener over `data-action`.
- CORS restricted to a configured allow-list (wildcard rejected in production).
- **Interactive docs are off in production** (`EXPOSE_API_DOCS`), so an
  unauthenticated visitor is not handed a map of every endpoint.
- **Source addresses behind a proxy.** `X-Forwarded-For` is honoured only when
  the immediate peer is inside `TRUSTED_PROXY_CIDRS`, and only the right-most
  untrusted hop is taken. Trusting it unconditionally would let any client forge
  a source address and step around the per-IP rate limiter; ignoring it entirely
  behind Nginx would put every caller in one bucket, so one noisy client could
  throttle the whole platform.
- The dashboard escapes every server-derived value before inserting it into the
  DOM (XSS defence); indicator input is strictly validated/normalised.
- The live alert stream authenticates by **header** (bearer or `X-API-Key`),
  never a token in the query string, which would leak credentials into proxy
  and access logs.
- TLS terminated at Nginx in production.

## Deployment posture

- The bundled Compose stack publishes **only Nginx**. PostgreSQL and Redis are
  reachable on the internal network alone — a published Redis with no password
  is a well-known route to full host compromise — and the API binds to loopback
  so it cannot be reached around the proxy.
- `POSTGRES_PASSWORD` and `REDIS_PASSWORD` have no defaults: Compose refuses to
  start until the operator sets them, which is deliberate.

## Resource limits

- Documents submitted to `/iocs/extract` and `/iocs/bulk` are capped at 128 KB
  and 1000 indicators. Scanning is linear but not free, so size is what bounds
  the cost of a submission.
- That scan runs **off the event loop** (`asyncio.to_thread`); left inline, one
  large document would stall every other request handled by that worker.
- SSE subscribers get a bounded queue that drops its oldest events, so a stalled
  client cannot grow memory or apply back-pressure to ingest.

## Injection & validation

- All persistence uses SQLAlchemy parameterised queries — no string-built SQL.
- Pydantic v2 validates every request; unknown indicators, bad sources and weak
  passwords are rejected at the boundary.
- Internal exceptions are mapped to sanitised JSON; stack traces never reach
  clients.
- **Spreadsheet formula injection.** Indicator tags arrive from imported
  reports and the CSV export exists to be opened in Excel or LibreOffice, so a
  tag beginning `=`, `+`, `-`, `@`, tab or CR would be a live formula on the
  analyst's machine. Tags are constrained to a label character set on the way
  in, and every exported cell is neutralised with a leading apostrophe on the
  way out — the export is defended even for rows written before that
  validation existed. Markdown exports escape table pipes for the same reason.
- **Search terms are escaped for `LIKE`**, so `%` and `_` match literally
  instead of silently behaving as wildcards.

## Production fail-fast

The app refuses to start in production without `MASTER_ENCRYPTION_KEY`, a strong
`JWT_SECRET_KEY`, `APP_DEBUG=false`, and a non-wildcard `CORS_ORIGINS`.

## Known limitations

- **The shipped Compose stack terminates HTTP, not HTTPS.** It cannot ship a
  certificate, so `deploy/nginx.conf` listens on :80 and the TLS server block is
  commented out. Bearer tokens and API keys cross the network in clear text
  until you terminate TLS — with that block once certificates are mounted,
  or at a load balancer in front of nginx. HSTS is only emitted on requests that
  actually arrived over TLS, so it never appears on a plain-HTTP response where
  a browser would ignore it anyway.
- The default **rate limiter** is still per-process (the login throttle and the
  token revocation store are Redis-backed in production). Add a per-IP login
  throttle and a shared rate limiter for multi-replica setups.
- Alert webhooks are validated by the SSRF guard and gated behind
  `ENABLE_LIVE_COLLECTORS`, but an operator with `alert:manage` can still point
  one at any *public* host; treat that permission as trusted.
- **Open registration** grants the `analyst` (write) role by default for the
  offline demo. In production set `REGISTRATION_DEFAULT_ROLE=viewer` or
  `ALLOW_OPEN_REGISTRATION=false` so anonymous users cannot write indicators.
- The SSRF guard validates at request time but does not pin the connection, so
  it is not a complete defence against DNS rebinding.
- Offline GeoIP/reputation are deterministic heuristics, not real intelligence;
  enable live collectors with proper API keys for production data.
- PDF/Excel report formats are out of scope (JSON/CSV/Markdown/STIX/MISP are
  provided).
- The live alert bus is per-process: with several replicas a client sees the
  alerts raised by the worker it is connected to. Redis pub/sub behind the same
  interface is the multi-replica upgrade.
