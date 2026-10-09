# Browser-side checks (design)

Public Network Tracer measures reachability from two vantage points: the
Cloudflare Worker edge (**Cloudflare Probe**) and the user's own browser
(**Browser Probe**). The browser-side checks run **in the dashboard page
itself** — there are no popups.

However, there are browser security limitations to account for.

## How it works

1. **Origin website** — the user enters a target URL and clicks the run button.
2. **In-page request** — the dashboard validates the URL and sends the request
   from the browser (a CORS-visible fetch first, then a single opaque `no-cors`
   request to classify a failure).
3. **Collect results** — status where available, timing, redirects and errors.
4. **Render** — the result is shown inline on the dashboard.

## What it can retrieve

| Check | Possible from the browser page? |
| --- | --- |
| Send a request to the target | Yes |
| Measure response time | Yes |
| Read HTTP status code | Only when the response allows CORS |
| Read response headers/body | Only when the response allows CORS |
| Detect blocked/opaque responses | Yes (reported as unreadable, never a fabricated status) |
| Inspect all network requests and their status codes | Better handled by a browser extension |

Important: a browser request does **not** bypass CORS. The browser can display a
response while preventing JavaScript from reading it. A CORS error is **not**
proof the destination is offline.

## Options when a full read is needed

- **CORS Relaxer extension** (`cors-relaxer/`) — scoped so that only *your site*
  can read responses from other sites; enables full cross-origin status, headers
  and body for the Browser Probe. Deny-by-default, client-side only.
- **Browser Response Monitor extension** (`browser-response-monitor/`) —
  observes the browser's actual request metadata (status codes for every
  request) where permissions allow.

## Authorization

Only test targets you own or are explicitly authorized to assess.
