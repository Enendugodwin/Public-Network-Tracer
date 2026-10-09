# Signal — Stateless Internet Lookup

A network-operations troubleshooting tool: a single lookup of a public IP, domain, or HTTP(S) URL that answers **"can we reach this site from the public internet?"** It runs live HTTP and TCP reachability checks and pairs them with DNS, RDAP, Team Cymru ASN, and optional Shodan host data.

> Hosting note: this repo lives on GitHub, but the app itself must run on Cloudflare — GitHub Pages is static-only and cannot run the Worker API. Deployment is manual (below).

There is no database, queue, saved search history, or permanent result cache. Requests to the target are one HTTP `HEAD` and a TCP connect to a small web-port list. It does not crawl pages, fetch bodies, or grab banners. Shodan port data is historical third-party data, not a live scan.

## What gets checked

| Check | Default | Notes |
|---|---|---|
| DNS (A/AAAA) | Always | Cloudflare DNS-over-HTTPS |
| HTTP `HEAD` | Always | Any public target; one request, bounded redirects |
| TCP `80`, `443` | Always | "Can we reach the site?" |
| Extra TCP ports | Off | Opt in via `EXTRA_PORTS` |
| Shodan | Off | Opt in via `SHODAN_API_KEY` |

Public targets only. Private, loopback, link-local, and reserved addresses are rejected outright, and a target that resolves to a private address is refused rather than probed.

## Request source

A lookup can originate from one of two places, chosen in the **Request source** control:

| Source | Runs where | What it can see |
|---|---|---|
| **Cloudflare Probe** (default) | The Worker's edge network | Live HTTP, TCP, DNS, TLS, RDAP/ASN and optional Shodan — the full result |
| **Browser Probe** | Your own browser, via the Fetch API | Reachability and whatever CORS exposes — status, final URL, redirect flag and readable headers only |

Browser Probe never routes the request through the Worker, and the Worker is never used as a silent fallback: if a browser probe fails, the dashboard says so and offers a **Retry with Cloudflare Probe** button instead.

Browser Probe outcomes are explicit:

| Outcome | Meaning |
|---|---|
| `http_response` | The browser sent the request **and** read the response (status and headers are shown) |
| `browser_policy_blocked` | The request reached the network, but the browser hid the response (CORS / opaque response) — **not** proof the target is offline |
| `opaque_response` | Forced no-cors: the request was delivered, but the opaque response hides the status and headers (reachability only) |
| `network_failure` | The request failed at the network or browser level; the exact cause is not exposed to JavaScript |
| `timeout` | No response within the browser probe timeout |

The Fetch API cannot report the resolved IP, TLS handshake details, or every header, and a CORS error can occur even when the destination received the request. Browser Probe never fabricates a status code: a failed CORS-visible fetch is classified with a single opaque (`mode: "no-cors"`) request, so a browser probe makes at most **two** requests, sends **no** destination cookies or credentials (`credentials: "omit"`), and stores nothing.

A **Force no-cors (opaque)** switch, shown only when Browser Probe is selected, sends just one opaque `no-cors` request and reports the `opaque_response` outcome — useful for confirming delivery to a target that does not send CORS headers, at the cost of not being able to read the status or any headers.

The probe runs in a **temporary popup window** (`public/probe.html`). The dashboard opens it, that page performs the request from the browser and `postMessage`s the result back to the originating tab — same-origin only, matched by a per-run token — where it is rendered. If the popup is blocked, or does not report within 25 seconds, the probe falls back to running in the dashboard page itself. (A popup pointed straight at the cross-origin target could not script itself, so it could never report back; that is why the popup is an origin-served probe page.)

### CORS Relaxer (optional)

With the scoped **CORS Relaxer** extension (`cors-relaxer/`) installed and this dashboard's origin in its **My site** list, the extension marks the page and the dashboard shows a *CORS Relaxer detected* chip. Because the response headers are then rewritten for requests this dashboard initiates, the probe's CORS fetch can read cross-origin status, headers and body in full. Without it, cross-origin reads fall back to the opaque/`browser_policy_blocked` outcomes.

Because Browser Probe fetches arbitrary destinations, the dashboard's `connect-src` CSP (set by the Worker when it serves the page) allows any `http(s)` origin. Scripts and styles stay same-origin, and remote content is only ever rendered as inert text.

## Result and failure codes

When a site is not reachable, the response carries an explicit code instead of an empty panel. The dashboard shows it on the HTTP status row, in the panel badge, and inline on closed TCP ports.

| Code | Meaning |
|---|---|
| `DNS_NO_RECORDS` | The hostname did not resolve to a public address |
| `DNS_PRIVATE` | The hostname resolved to a private or reserved address |
| `DNS_FAILURE` | DNS resolution failed |
| `PRIVATE_ADDRESS` | The target (or a redirect) is private/reserved |
| `REDIRECT_UNSUPPORTED` | A redirect pointed somewhere unsafe or unsupported |
| `REDIRECT_LIMIT` | Too many redirects |
| `CONNECT_TIMEOUT` | No response before the timeout |
| `TLS_ERROR` | The TLS handshake failed |
| `CONNECTION_REFUSED` | The port refused the connection |
| `NETWORK_ERROR` | The connection could not be established |
| `NO_RESPONSE` | No HTTP response was returned |

`overview.reachable` is a boolean summary so a dashboard or script can branch without parsing codes. A rejected input (private address, bad URL) is still an HTTP `400` with an `error` message.

## Why a site is unreachable

Beyond the raw code, every response carries a `diagnosis` object that explains the likely cause and the evidence behind it. This is what separates "the site is down" from "you are being blocked".

| Category | Severity | Meaning |
|---|---|---|
| `reachable` | ok | Answered with a non-error status |
| `waf_block` | warn | Blocking status **and** an edge/WAF signature present |
| `blocked_response` | warn | Blocking status, no edge signature — origin-side rule |
| `auth_required` | warn | `401` |
| `client_rejected` | warn | Other `4xx` |
| `origin_error` | bad | `5xx` — destination up, application failing |
| `filtered_or_offline` | bad | No answer on the web ports; timeout is the signature of a firewall/blocklist drop |
| `http_layer_timeout` | bad | Ports open but HTTP timed out — app, proxy, or load balancer |
| `refused` | bad | Network path fine, nothing listening (destination not available) |
| `tls` | bad | TCP connected, TLS failed |
| `dns` / `policy` | bad / warn | Name did not resolve, or resolves to a private address |
| `redirect` | bad | Redirect loop or unsafe destination |

Edge/WAF detection reads response headers for Cloudflare (`cf-ray`, `cf-mitigated`, `server: cloudflare`), Sucuri, Akamai, Imperva, AWS (`x-amzn-waf-action`, `awselb`), Azure Front Door, Fastly, Vercel, and F5 BIG-IP. A signature alone does not mean blocked — Cloudflare fronts plenty of healthy sites — so it is only reported as a block when the status is also `403`, `406`, `429`, `451`, or `503`.

```jsonc
"diagnosis": {
  "category": "waf_block",
  "severity": "warn",
  "title": "Blocked at the edge / WAF",
  "summary": "The site is reachable, but an edge or WAF layer refused the request…",
  "evidence": ["HTTP 403", "open ports: :443", "edge: Cloudflare"]
}
```

## Performance

Lookups overlap their work rather than running in sequence: DNS, the HTTP `HEAD`, the TCP connects, and the enrichment calls all start immediately, and TCP/enrichment begin as soon as the address is known. A short-lived, per-isolate cache (120 s) deduplicates repeat lookups of the same target, which is what makes a recheck fast. The live `HEAD` and TCP checks are never cached, so a recheck reflects current reachability.

## What "source IP" means

The dashboard shows **your public IP as observed by the checker** (Cloudflare's `CF-Connecting-IP` header, captured server-side) and labels it as the source. Be clear about the limit: the actual HTTP and TCP probes are sent from **the checker's edge network, not from your own IP**. A serverless Worker cannot originate packets from an arbitrary address, and a browser cannot open raw TCP sockets. So this answers *"is the target reachable from the public internet?"* — it is not a from-your-machine traceroute.

Locally this field reads *"unavailable in local dev"*. That is expected: `wrangler dev` does not set `CF-Connecting-IP` (verified — the request carries no `CF-Connecting-IP`, `X-Forwarded-For`, or `CF-Ray`). The header is populated by Cloudflare's edge only after you deploy.

**Local fallback (privacy note):** when the edge header is absent, the browser asks Cloudflare's own trace endpoint (`https://www.cloudflare.com/cdn-cgi/trace`) for its public IP and labels the result *"detected by your browser"*. This only happens when the edge value is missing — i.e. in local development. Once deployed, the authoritative `CF-Connecting-IP` is used and the browser makes no third-party call. The endpoint is allowlisted in the page's `connect-src` CSP; remove it there and delete `detectBrowserPublicIp` in `public/app.js` if you want zero third-party calls.

## Run locally

Requires Node.js 20.18.1+ and npm.

```sh
npm install
cp .dev.vars.example .dev.vars   # optional: add SHODAN_API_KEY locally
npm run dev
```

Open the local URL printed by Wrangler. Every check runs out of the box.

## Optional configuration

```jsonc
// wrangler.jsonc vars
"EXTRA_PORTS": "8080,8443"   // 80 and 443 are always probed; capped at 16 total
```

Use this deliberately: the defaults are the web ports a network team needs for access troubleshooting. Adding ports makes the tool probe further, so only list ports you intend to test.

Optional Shodan enrichment is server-side:

```sh
npx wrangler secret put SHODAN_API_KEY
```

The key is never sent to the browser. Without it, the app still uses DNS, RDAP, and Team Cymru's public ASN-over-DNS response. Respect each provider's terms and rate limits.

### Bring your own Shodan key

Users can supply their own key from the dashboard's **Options** dropdown instead of relying on a server-configured one. The key is sent as an `X-Shodan-Key` request header and used for that request only:

- never written to storage, logs, or the cache — and **never memoised**, so one caller's key can never serve another caller's results
- never echoed in a response or in a source URL
- held in memory by default; only saved to `localStorage` if the user ticks *Remember in this browser*
- format-checked before use; a malformed value is ignored rather than forwarded

Because this is a caller-supplied secret transiting the Worker, the Worker must be trusted with it — a self-hosted deployment keeps that trust boundary entirely inside your own account.

## Sources and limitations

- **DNS:** Cloudflare DNS-over-HTTPS.
- **IP/domain registration:** RDAP.
- **ASN/prefix/country:** Team Cymru origin ASN DNS service over Cloudflare DoH; RDAP is used for the ASN organization name where available.
- **Observed services and certificates:** optional Shodan Host API; ports, concise product/version labels, and certificate fingerprints/summary metadata are returned, never raw service banners.
- **HTTP:** one bounded request per lookup — `HEAD` by default, or `GET` when body capture is requested. Small redirect limit with revalidation at every hop. Workers' Fetch API does not expose the negotiated TLS version, so the UI reports HTTPS without claiming a TLS version.
- **Response body (opt-in):** first 16 KB only, never stored, decoded as text only for textual content types, and rendered as inert text. Challenge/interstitial markers are extracted and feed the diagnosis.
- **TCP reachability:** TCP connect checks to a bounded port list (default `80`, `443`; extras via `EXTRA_PORTS`, capped at 16). A refused or filtered port is reported as closed, never as open. There is no ICMP, so no ping.

  **Known limitation:** Workers cannot open raw TCP to Cloudflare's own IP ranges, so Cloudflare-hosted destinations report refused even when the port is open. When HTTP succeeds but every TCP connect is refused, the result is marked `inconclusive` instead of `closed` — treat those ports as unavailable, not down.

The API returns source URLs, collection timestamps, and confidence labels with public-source results. It does not retain those results. The search target is sent to the configured public providers needed for lookup; do not submit secrets or credential-bearing URLs.

The in-isolate rate limiter is best-effort only. This is deployed on a public URL, so configure Cloudflare platform-level rate limiting/WAF rules on the Worker route before relying on it.

## Live deployment

| | URL |
|---|---|
| Worker API + dashboard (same-origin) | https://public-network-tracer.enendugodwin.workers.dev |
| Dashboard (GitHub Pages) | https://enendugodwin.github.io/Public-Network-Tracer/ |
| Health | https://public-network-tracer.enendugodwin.workers.dev/healthz |

## Deploy

The Worker is built and deployed by Cloudflare's Git-connected build on push to `main`. Manual deploys still work:

```sh
npx wrangler login
npx wrangler deploy
```

### Cloudflare build settings

The app is in a subdirectory, so the build must run from it:

| Field | Value |
|---|---|
| Root directory | `edge-lookup` |
| Build command | *(leave empty — `wrangler` bundles the TypeScript itself)* |
| Deploy command | `npx wrangler deploy` |

From the repo root the deploy fails with `Could not detect a directory containing static files`, and the build also runs a pointless `pip install` against the Python prototype next door.

On push and pull requests, the `edge-lookup` GitHub Actions workflow runs `npm ci`, `typecheck`, and tests on Node 20 and 22. It does not deploy.

## Hosting the dashboard on GitHub Pages

GitHub Pages is static-only and **cannot run the Worker**, so Pages hosts the dashboard while the Worker provides the API. That cross-origin split needs both ends configured — as they are in this repository:

1. **Worker accepts the Pages origin** — `wrangler.jsonc`:
   ```jsonc
   "ALLOWED_ORIGIN": "https://enendugodwin.github.io"
   ```
   Exact match, never a wildcard. Empty means no cross-origin access at all.
2. **Dashboard knows the API** — `public/config.js`:
   ```js
   window.TRACER_API_BASE = "https://public-network-tracer.enendugodwin.workers.dev";
   ```
   A repository variable named `TRACER_API_BASE` overrides this file during the Pages build.
3. **Pages source** — repository *Settings → Pages → Build and deployment → Source: GitHub Actions*.

If either side is missing, the dashboard loads but every lookup fails: with no API base it requests `/api/lookup` from `github.io`, and without the allowlist the browser blocks the cross-origin call.

Asset paths are relative, so the dashboard works both at the Worker root and under the Pages project subpath.

## Checks

```sh
npm run typecheck
npm test
```

## Project boundary

This directory is a standalone Cloudflare implementation. The existing Python evidence-ingest prototype in the parent project is unchanged and is not used by this app.
