# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| < 1.1   | :x:                |

Security fixes are applied to `main` and released from there.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub's
[Report a vulnerability](https://github.com/mojtaba-py-code/cyber-threat-intelligence-platform/security/advisories/new)
form, or by email to **mojtaba.python@gmail.com**.

Include what you can:

- the affected version, tag or commit,
- what the issue is and what an attacker gains from it,
- steps or a minimal proof of concept that reproduces it.

## What to expect

- Acknowledgement within **72 hours**.
- An initial assessment within **7 days**.
- A fix and a published advisory once a patch is ready.
- Credit in the advisory, if you want it.

## Scope

In scope: the code in this repository — the API surface, the authentication and
authorization layer, the SSRF guard, the collectors and enrichers, the masking
and encryption helpers, and anything that handles a request or a secret.

Out of scope:

- Vulnerabilities in third-party dependencies — report those upstream; if this
  project's use of a dependency is what makes it exploitable, that *is* in scope.
- Findings that require an attacker to already control the host or the process.
- The bundled sample intelligence. It is synthetic data used so the platform
  runs with no outbound traffic; the indicators in it are illustrative.

## Notes for operators

This platform is **offline-first on purpose**. Collectors and enrichers make no
outbound requests until an operator sets `ENABLE_LIVE_COLLECTORS=true`, and any
fetch of a user-supplied URL is screened by the SSRF guard against private,
loopback, link-local and cloud-metadata destinations. Turning live collection on
widens the attack surface — set `OUTBOUND_ALLOWED_HOSTS` when you do.

Before deploying:

- Generate real values for `MASTER_ENCRYPTION_KEY` and `JWT_SECRET_KEY` with
  `make keys`. With `APP_ENV=production` the application refuses to start
  unless both are set and `JWT_SECRET_KEY` is at least 32 characters. That
  check does **not** run in `development` or `staging` — treat a staging
  deployment as production and set the keys there too.
- Keep `EXPOSE_API_DOCS=false` on any internet-facing instance.
- Set `TRUSTED_PROXY_CIDRS` to your actual proxy range. Client-IP handling —
  and therefore rate limiting and lockout — depends on it being correct.
- Provider API keys belong in the environment, never in the repository.

See [`docs/security.md`](docs/security.md) for the full threat model.
