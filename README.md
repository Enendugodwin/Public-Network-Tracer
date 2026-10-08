# Public Network Tracer

A stateless, serverless lookup for network teams: enter a **public IP, domain, or URL** and see whether it is reachable, **why it is not**, and the public network context behind it.

The app lives in [`edge-lookup/`](edge-lookup/README.md).

## Live

| | URL |
|---|---|
| Dashboard (GitHub Pages) | https://enendugodwin.github.io/Public-Network-Tracer/ |
| Worker API + dashboard (same-origin) | https://public-network-tracer.enendugodwin.workers.dev |
| Health check | https://public-network-tracer.enendugodwin.workers.dev/healthz |

The Worker serves the dashboard itself, so that URL needs no CORS. The Pages copy is static and calls the Worker cross-origin, using the origin allowlisted in `ALLOWED_ORIGIN`.

Try `example.com` (reachable), `openai.com` (403 → `waf_block`), `8.8.8.8` (`:80` closed), or a typo'd domain (`DNS_NO_RECORDS`).

## What it does

One lookup runs live reachability checks and pairs them with public data:

| Check | Default | Notes |
|---|---|---|
| DNS (A/AAAA) | Always | Cloudflare DNS-over-HTTPS |
| HTTP `HEAD` | Always | Any public target; one request, bounded redirects |
| TCP `80`, `443` | Always | "Can we reach the site?" |
| Response body | Off | Dashboard toggle; switches to `GET`, first 16 KB |
| Extra TCP ports | Off | Opt in via `EXTRA_PORTS` |
| Shodan host data | Off | Server key via `SHODAN_API_KEY`, or bring your own in the dashboard's **Options** |

### Reading the response body

Tick **Fetch response body** to see what the destination actually returned. That switches the probe from `HEAD` to `GET` and captures the first 16 KB, which is usually enough to tell a WAF challenge page from a real application error.

The captured body is reported as `contentType`, `bytesRead`, `truncated`, `textual`, `title`, and `markers` — where markers flag things like *Cloudflare challenge*, *Bot-check interstitial*, *CAPTCHA present*, or *Access-denied page*. Markers feed the diagnosis evidence, so a blocked site explains itself.

Safety: the body is capped at 16 KB, never stored, and rendered in the dashboard as **inert text** (`textContent`, never `innerHTML`) so a hostile page cannot inject markup or script. Binary content types are not decoded at all.

Enrichment: RDAP (IP, ASN, domain registration), Team Cymru ASN/prefix/country, reverse DNS, and optional Shodan ports, services, and certificate fingerprints.

Every result is then analysed, not just displayed:

- **Security findings** — each with what was seen, *why it matters*, a recommendation, and its evidence
- **Internet posture score** — HTTP, TLS, headers, DNS, infrastructure (informational, not a vulnerability verdict)
- **Full DNS picture** — A, AAAA, CNAME, MX, NS, TXT, CAA, SOA, plus PTR and the resolver's DNSSEC flag
- **IP intelligence** — ASN, BGP prefix, organization, reverse DNS, hosting type, abuse contact
- **Redirect chain** and grouped security/caching/application headers
- **Export & sharing** — copy report, JSON/CSV/TXT download, and `?target=` shareable URLs
- **Recent lookups** — kept in your browser's localStorage only; the server stores nothing

There is no database, queue, or server-side history. It does not crawl pages, fetch response bodies unless asked, or grab banners.

## Why a site is unreachable

Every result carries a typed failure code and a `diagnosis` explaining the likely cause with evidence:

| Category | Meaning |
|---|---|
| `waf_block` | Blocking status **and** an edge/WAF signature (Cloudflare, Sucuri, Akamai, Imperva, AWS WAF, Azure Front Door, Fastly, Vercel, F5) |
| `blocked_response` | Blocking status with no edge signature — origin-side rule |
| `filtered_or_offline` | Nothing answers; a timeout rather than a refusal indicates a firewall/blocklist drop |
| `refused` | Network path fine, nothing listening (destination not available) |
| `http_layer_timeout` | Ports open but HTTP timed out — app, proxy, or load balancer |
| `tls` | TCP connected, TLS failed |
| `dns` / `policy` | Name did not resolve, or resolves to a private address |
| `redirect` | Redirect loop or unsafe destination |

Example: `openai.com` returns 403 with `server: cloudflare` → `waf_block`; `discord.com` returns 200 → `reachable`. A Cloudflare signature alone is never treated as a block, only alongside a blocking status.

## Hosting

Two deploy targets, both driven from this repository:

| Target | Driven by | Live at |
|---|---|---|
| Worker API + dashboard | Cloudflare Workers (Git-connected build) | https://public-network-tracer.enendugodwin.workers.dev |
| Static dashboard | [`.github/workflows/pages.yml`](.github/workflows/pages.yml) → GitHub Pages | https://enendugodwin.github.io/Public-Network-Tracer/ |

**GitHub Pages cannot run the Worker** — it is static only. The Pages copy therefore calls the API cross-origin, which requires both ends to agree:

- `edge-lookup/wrangler.jsonc` → `ALLOWED_ORIGIN` = `https://enendugodwin.github.io` (exact match, never a wildcard; empty means no cross-origin access)
- `edge-lookup/public/config.js` → `TRACER_API_BASE` = the Worker origin. A repository variable named `TRACER_API_BASE` overrides this file during the Pages build.

If either is missing, the dashboard loads but every lookup fails: with no API base it asks `github.io` for `/api/lookup`, and without the Worker's allowlist the browser blocks the cross-origin call.

### Cloudflare build settings

The app lives in a subdirectory, so the build **must** run from there:

| Field | Value |
|---|---|
| Root directory | `edge-lookup` |
| Build command | *(leave empty — `wrangler` bundles the TypeScript itself)* |
| Deploy command | `npx wrangler deploy` |

Pointing the build at the repo root fails with `Could not detect a directory containing static files`, and it will also try to `pip install` the Python prototype.

GitHub Actions runs the test suite on push and pull requests. It does not deploy the Worker.

## Layout

```text
edge-lookup/          The tracer: Cloudflare Worker + static dashboard
  src/index.ts        Lookup pipeline, failure codes, diagnosis
  src/index.test.ts   Test suite
  public/             Dashboard (HTML/CSS/JS)
src/osint_platform/   Separate evidence-first OSINT prototype (Python/FastAPI)
tests/                Tests for the Python prototype
docs/                 Architecture and roadmap for the Python prototype
```

`edge-lookup/` and the Python prototype are independent; the tracer does not use the prototype.

## Development

Tracer (Node 20.18.1+):

```sh
cd edge-lookup
npm install
npm run dev          # http://127.0.0.1:8787
npm test
npm run typecheck
```

Python prototype (Python 3.11+): see [`README`](docs/architecture.md) and `pyproject.toml`; run `pytest`.

## Safety

Only public targets are accepted. Private, loopback, link-local, and reserved addresses are rejected, and a name resolving to a private address is refused rather than probed — as are redirects that leave for a private destination.

The safety model is boundedness: one HTTP request (`HEAD`, or `GET` when body capture is requested), at most 16 TCP connects, response bodies only on request and capped at 16 KB, no crawling, and per-client rate limits — **30 lookups/minute**, or **10 response-body fetches/minute** on a separate budget so the expensive path cannot exhaust the normal one. Extra ports beyond 80/443 require explicit opt-in.
