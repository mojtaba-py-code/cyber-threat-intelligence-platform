# Architecture

## Guiding principles

- **Clean layering.** Dependencies point inward: `api → services → repositories
  → models`. The domain (indicator/scoring/correlation/enrichment) never imports
  web or ORM specifics.
- **Dependency inversion.** Services depend on the `Collector` port and
  repository classes, not on a concrete provider or SQL. Implementations are
  injected in `app/api/deps.py`.
- **Offline-first & safe by default.** Outbound behaviour is gated at single
  choke points (`CollectorFactory`, the enrichers' `live_enabled`, the SSRF
  guard) so the platform is fully runnable and testable without network access.

## Layers

### Indicator core (`app/ioc`)
Pure parsing/classification and (de)fanging. `classify_indicator` refangs input,
then applies strict, ordered rules to detect the `IOCType` and return a
normalised canonical value.

### Collectors (`app/collectors`)
The `Collector` **port** plus offline-first providers. `OfflineFirstCollector`
decides offline vs live from the server policy and key availability; live
implementations perform the real request and normalise it into
`CollectedIndicator`. `registry.py` is the single source of truth for sources;
`factory.py` enforces the live/offline policy and injects keys.

### Enrichment (`app/enrichment`)
Per-facet enrichers (GeoIP/ASN, DNS, reputation) merged by `EnrichmentEngine`,
which also derives `ScoreSignals`. User-controlled fetches pass through the SSRF
guard (`app/core/ssrf.py`).

### Scoring (`app/scoring`)
A pure, weighted 0–100 engine mapping signals to a `ThreatLevel` and returning
per-signal contributions for explainability.

### Correlation (`app/correlation`)
Directed, typed edges stored in `correlation_edges` and materialised in-process
with networkx (`ThreatGraph`) for neighbours, pivots and attack chains.

### Ingest at document scale (`app/ioc/extract.py`)
Analysts receive intelligence as prose, spreadsheets or bundles, not as single
values. The extractor harvests candidates from free text, CSV columns and STIX
patterns, consuming each matched span exactly once (so a URL never also yields
its own host) and rejecting filename-shaped "domains". Every candidate is still
validated by `classify_indicator`, so the extractor can only ever be
over-eager, never wrong about a type. `POST /iocs/extract` previews;
`POST /iocs/bulk` imports, one SAVEPOINT per indicator.

### Sharing (`app/sharing`)
Export mappings to **STIX 2.1** bundles and **MISP** events, written explicitly
rather than via heavy SDKs. Object ids are UUIDv5 over the identifying property,
so re-exporting the same indicator produces the same id and consumers
deduplicate instead of accumulating copies.

### Live stream (`app/core/events.py`)
A per-process publish/subscribe bus. Alerts created during ingest are published
and delivered to connected operators over Server-Sent Events. Each subscriber
has a **bounded** queue that drops its oldest events, so a stalled browser tab
can never apply back-pressure to the request that raised the alert, nor grow
memory without limit. Fanning out across replicas is a Redis pub/sub swap behind
the same interface.

### Services / Repositories / API
Services own business logic and the unit-of-work boundary (the request session
commits on success). Repositories isolate persistence. Routers are thin and
check RBAC permissions.

## Request lifecycle (submit an IOC)

```
POST /iocs
  → RequestContext + RateLimiter middleware
  → require(ioc:write) (RBAC over JWT or X-API-Key)
  → IOCService.upsert
       → classify_indicator (refang + type)
       → EnrichmentEngine.enrich (geo/dns/reputation, SSRF-guarded)
       → EnrichmentEngine.signals_from → compute_threat_score
       → IOCRepository upsert + EnrichmentRepository upsert
       → auto-correlate (url→domain, domain→resolved IPs)
       → AuditRepository record
       → AlertService.evaluate_ioc → alert rows + EventBus.publish → SSE clients
  → session.commit → IOCDetailOut
```

## A note on long-lived connections

`GET /stream/alerts` authenticates like every other endpoint and then hands its
pooled database connection back **before** the stream starts. An SSE connection
lives for hours; holding the session for its lifetime would let a handful of
watching analysts exhaust the pool and stall the rest of the API.

## Design patterns

| Pattern | Where |
| --- | --- |
| Port/Adapter | `Collector`, provider collectors |
| Factory | `CollectorFactory` |
| Repository | `app/repositories/*` |
| Service layer | `app/services/*` |
| Strategy | enrichers, indicator dispatch |
| Circuit breaker / Retry | `app/core/resilience.py` |

## Extending: add a collector

1. Implement a `Collector` (subclass `OfflineFirstCollector`, add `_collect_live`).
2. Register it in `COLLECTOR_CLASSES` and add a `CollectorInfo` to the registry.
3. Add offline samples in `samples.py`. Done — factory and API pick it up.

## Database schema (core tables)

- `users`, `api_keys` — identity & machine access.
- `iocs` — indicators (type+value unique, score/level, tags, timestamps).
- `enrichments` — per-provider enrichment payloads (1 per ioc+provider).
- `correlation_edges` — directed typed relationships between entity refs.
- `threat_actors`, `alert_rules`, `alerts`, `audit_logs`.
