## What this changes

<!-- One or two sentences. Link the issue it closes, if there is one. -->

## Why

<!-- The problem this solves. Skip if the "what" already makes it obvious. -->

## How it was verified

<!--
Which tests you added or ran, and anything you checked by hand. If the change
touches collectors, enrichers or anything that makes an outbound request, say
how you tested it with `ENABLE_LIVE_COLLECTORS` both off and on.
-->

## Checklist

- [ ] `ruff check app tests` and `ruff format --check app tests` pass
- [ ] `mypy app` passes
- [ ] `pytest` passes and coverage stays above the 80 % floor
- [ ] New behaviour has a test; a bug fix has a test that fails without the fix
- [ ] Anything fetching a user-supplied URL still goes through the SSRF guard
- [ ] Offline-first still holds: no outbound call without `ENABLE_LIVE_COLLECTORS`
- [ ] A schema change ships with an Alembic migration
- [ ] Docs updated if the change is user-visible (README, `docs/`)
- [ ] No real indicators, API keys or customer data in the diff — sample feeds only
