# CORS Relaxer (scoped)

A Manifest V3 Chrome extension that lets **your site** read responses from other
sites by relaxing CORS response headers — but **only** for requests that your
site initiates. Every other website is unaffected. It is **deny-by-default**:
with no "my site" configured, no rules exist and nothing changes.

> **Authorization:** use only on domains you own or are explicitly authorized to
> assess. This is a client-side testing aid, not a way to access data a server
> refuses to give you.

## What it does

CORS is relaxed **only for requests initiated by your site** — every other
website is untouched. You configure one or more "my site" origins; a dynamic
`declarativeNetRequest` rule then matches requests whose `initiatorDomains` are
those sites. Destinations are any other site by default (optionally limited to a
list).

For each matching request, the response headers are rewritten:

- `Access-Control-Allow-Origin: *`
- `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`,
  `Access-Control-Expose-Headers`, `Access-Control-Max-Age`
- `Cross-Origin-Resource-Policy: cross-origin`

This makes the browser let **your site** read responses from other sites. For
Public Network Tracer, add its origin (e.g.
`public-network-tracer.enendugodwin.workers.dev`, and
`enendugodwin.github.io` for the Pages copy) under **My site**.

## UI

- **Enabled** — global on/off (badge shows `on` when a rule is active).
- **My site** — the origins allowed to bypass CORS. Add a domain/URL, toggle each
  on/off, or use **Add current site**.
- **Destinations** — optional limit; empty means any other site.
- **Recent matching requests** — observational log (method, status, URL) of
  requests from your site, so you can see what was affected.

## Install

1. `chrome://extensions` → enable **Developer mode**.
2. **Load unpacked** → select this `cors-relaxer` folder.
3. Approve the requested permissions.

## Limitations (important)

- It changes **this browser's enforcement only** — never the server's CORS
  policy. It cannot grant access to data the server withholds, and it cannot
  satisfy authentication you don't have.
- `Access-Control-Allow-Origin: *` does **not** satisfy credentialed requests.
  A probe must use `credentials: "omit"` (as Public Network Tracer's Browser
  Probe does).
- **Preflight:** non-simple requests (custom headers, non-simple methods) need a
  successful `OPTIONS` response. The rule rewrites CORS headers on it, but it
  cannot invent a `2xx` if the server doesn't answer preflight — so preflight
  can still fail. Simple `GET`/`HEAD` requests work best.
- CORS is one of several browser controls; this cannot bypass the others.
- It only affects requests **initiated by your configured sites**; other sites
  are untouched. Still, treat the "My site" list as security-relevant: only list
  sites you own or are authorized to test.
