# Roadmap

## Phase 0 — Evidence-first core (current)

- Source registry with terms review and host allowlists.
- Canonical security/infrastructure entities.
- Cases with explicit scope.
- Source-linked observations and local SQLite persistence.
- Authenticated API; no external fetchers or active scans.

## Phase 1 — Connector contract and source health

- Define a connector interface with bounded query inputs and per-source budgets.
- Add fixture-based contract tests and connector health/last-success tracking.
- Start with a small number of keyless, terms-reviewed public sources.
- Preserve publication time, collection time, response hash, parser version, and
  source citation for every observation.

## Phase 2 — Entity graph and investigation UX

- Add relationship types, confidence, and derivation evidence.
- Add case timeline, graph pivots, saved searches, and source comparison.
- Export reproducible case bundles with citations and hashes.

## Phase 3 — Scale and integrations

- Benchmark SQLite against realistic workloads; migrate to PostgreSQL only when
  measured limits require it.
- Add optional STIX/MISP/OpenCTI adapters and a read-only adapter for the
  existing Threat Intelligence Platform.
- Add event bus/search storage only when connector volume justifies operations
  complexity.

## Phase 4 — Optional AI analyst

- Retrieval only over evidence the user is authorized to see.
- Cite every factual statement to observation IDs and source URLs.
- Label hypotheses, preserve contradictory evidence, and never fabricate
  attribution or confidence.
- Keep source authorization and collection policy deterministic; AI cannot
  bypass them.

## Guardrails for every phase

- Respect provider terms, licenses, rate limits, and access controls.
- No private-person dossiers, doxxing, or covert surveillance.
- No active checks without explicit owner authorization and a scoped allowlist.
- Keep evidence provenance attached through normalization, correlation, and
  export.
