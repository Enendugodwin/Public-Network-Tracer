# Architecture

## MVP flow

```text
Analyst / reviewed source adapter
              │
              ▼
 Authenticated FastAPI control plane
   ├── Source registry (terms reviewed)
   ├── Case workspace and scope
   └── Observation intake + validation
              │
              ▼
 SQLite evidence store (local MVP)
   ├── Canonical entities
   ├── Source-linked observations
   └── Cases / entity relationships
```

The current version records analyst- or fixture-provided evidence. It does not
fetch arbitrary URLs. Future connectors must be registered, respect source
terms/rate limits, only access allowed hosts, and emit observations with
provenance.

## Core records

- **Source:** identifier, publisher name, base URL, allowed hosts, terms URL,
  license, collection mode, rate limit, and a terms-reviewed flag.
- **Entity:** typed/canonical identifier for a domain, IP, URL, hash, CVE, ASN,
  organization, malware family, threat-actor group, or certificate fingerprint.
- **Observation:** a claim linking an entity to a source citation, timestamps,
  optional content hash, confidence, and a bounded analyst summary.
- **Case:** an investigation question and explicit entity scope, linked to
  entities and observations.

The same entity can be observed by multiple sources. Evidence is not silently
merged: source, time, confidence, and citation remain attached to each
observation.

## Trust boundaries

- The API requires an environment-provided API key; it has no built-in default
  credential.
- Source registration requires an explicit terms review before enabling use.
- Evidence references must use HTTPS and the citation host must match the
  registered source allowlist.
- Requests and summaries are size-bounded. The API accepts references and
  short summaries, not full-page crawls.
- The current app performs no network collection and no active scanning.
- Private-person identity/contact attributes are deliberately outside the MVP
  schema. Future general-purpose identity research would require a separate
  privacy/legal review and explicit user scope.

## Production gaps

SQLite is for local development only. Before multi-user or hosted use, add
PostgreSQL migrations, authentication/authorization with user and case-level
access control, tenant isolation, rate limiting, retention/deletion workflows,
backups, secret management, and structured audit logs. Add connector-specific
egress controls before enabling any automated collection.
