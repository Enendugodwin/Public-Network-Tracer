# Architecture

```text
Static dashboard (Cloudflare Workers Assets)
                   │ same-origin POST
                   ▼
            Stateless Worker API
       ┌───────────┼───────────┐
       ▼           ▼           ▼
  DNS over HTTPS  RDAP    Team Cymru ASN
       │                       │
       └───────────┬───────────┘
                   ▼
        Optional Shodan Host API
                   │
   Live HTTP HEAD + TCP connect (default)
                   ▼
             JSON response
```

No result is written to KV, D1, R2, a database, or a queue. Each request enriches the input independently and returns source links, request time, and confidence. The UI does not keep a search history. A short-lived per-isolate cache (120 s) deduplicates repeat lookups; it is process memory only, lost with the isolate, and never holds live probe results.

## Pipeline

```text
input ─┬─ resolve DNS ─┬─ TCP connect
       │               └─ enrichment (RDAP, Cymru, Shodan)
       └─ HTTP HEAD
                 │
                 ▼
        assemble → codes → JSON
```

Stages start concurrently; TCP and enrichment await only the DNS step. Every non-success path returns a typed failure code so callers can distinguish "no DNS", "refused", "timeout", and "TLS error" without string matching. A `diagnosis` layer then combines the HTTP status, edge/WAF header signatures, and TCP port evidence into a cause and an evidence list.

## Trust boundaries

- Only public IPs and fully-qualified public DNS names are accepted; localhost, private/reserved ranges, unsupported protocols, embedded credentials, and nonstandard ports are rejected.
- Public data requests go only to fixed provider endpoints. User input is never used as a provider URL.
- Active checks are **on by default**, because the product is an access-troubleshooting tool for network teams. The safety model is boundedness rather than an allowlist: one HTTP request (`HEAD`, or `GET` when body capture is requested), at most 16 TCP connects, no response bodies unless explicitly requested, no crawling, no banner grabbing, and a per-client rate limit.
- Response-body capture is opt-in and bounded to 16 KB. The body is never persisted, is decoded only for textual content types, and is rendered in the dashboard as inert text via `textContent` — never as markup — so a hostile page cannot inject script.
- Redirects are revalidated at every hop against the public-target rules, so a redirect cannot be used to reach a private address.
- Extra TCP ports beyond `80`/`443` require explicit operator opt-in via `EXTRA_PORTS`.
- The displayed source IP is the visitor's `CF-Connecting-IP` observed at the edge. It is a label, not a probe origin: the probes egress from the checker's network.
- No CORS wildcard, query logging, user-supplied request headers, response-body storage, or crawl is implemented.
- API keys stay in Worker secrets. The client never receives the Shodan key.
- An isolate-local rate limit is only defense in depth; deployment operators must configure Cloudflare's edge rate limiting.

## Known limits

- Workers Fetch does not reveal the negotiated TLS protocol version.
- The probe source is Cloudflare's egress. A true from-your-IP test would require an agent running at that IP and is explicitly out of scope.
- Workers cannot send ICMP, so no ping is offered.
- Some servers omit `Content-Length` on `HEAD`, so that field can be blank even on success.
- Domain DNS resolution is checked immediately before a scoped HTTP request, but the platform's fetch resolver performs its own resolution. Use Cloudflare egress protections if you need a stricter guarantee.
- Public provider terms, quotas, and availability apply. `rdap.org` occasionally rate-limits; affected fields are shown as unavailable rather than inferred.
