# Public Network Tracer

A stateless, serverless lookup for network teams: enter a **public IP, domain, or URL** and see whether it is reachable, **why it is not**, and the public network context behind it.

The app lives in [`edge-lookup/`](edge-lookup/README.md).

## What it does

One lookup runs live reachability checks and pairs them with public data:

| Check | Default | Notes |
|---|---|---|
| DNS (A/AAAA) | Always | Cloudflare DNS-over-HTTPS |
| HTTP `HEAD` | Always | Any public target; one request, bounded redirects |
| TCP `80`, `443` | Always | "Can we reach the site?" |
| Extra TCP ports | Off | Opt in via `EXTRA_PORTS` |
| Shodan host data | Off | Opt in via `SHODAN_API_KEY` |

Enrichment: RDAP (IP, ASN, domain registration), Team Cymru ASN/prefix/country, and optional Shodan ports, services, and certificate fingerprints.

There is no database, queue, saved search history, or permanent cache. It does not crawl pages, fetch response bodies, or grab banners.

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

The repository is on GitHub, but **GitHub Pages cannot run this app** — the lookup needs a serverless runtime. Deploy the Worker to Cloudflare yourself:

```sh
cd edge-lookup
npm install
npx wrangler login
npx wrangler deploy
```

The `pages` workflow can additionally publish the **dashboard** to GitHub Pages. Because Pages is static-only, the UI then calls the Worker cross-origin, which requires two settings:

- Worker var `ALLOWED_ORIGIN` = `https://<user>.github.io` (exact match, no wildcard)
- Repository variable `TRACER_API_BASE` = the deployed Worker origin

Without `TRACER_API_BASE`, the Pages dashboard loads but lookups fail — there is no same-origin API. See [`edge-lookup/README.md`](edge-lookup/README.md#hosting-the-dashboard-on-github-pages) for the step-by-step.

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

Only public targets are accepted. Private, loopback, link-local, and reserved addresses are rejected, and a name resolving to a private address is refused rather than probed. The safety model is boundedness: one `HEAD`, at most 16 TCP connects, no bodies, no crawling, and a per-client rate limit. Extra ports beyond 80/443 require explicit opt-in.
