# Browser-side checks via a temporary page (design)

Yes. Your website can open a temporary page in a new browser tab, run checks from
that page, and send the results back to your original website. This is useful for
Public Network Tracer because you want to measure activity from the user's actual
browser rather than from Cloudflare.

However, there are browser security limitations to account for.

## How it would work

1. **Origin website** — the user enters a target URL and clicks **Test**.
2. **Temporary browser page** — opens the target and runs permitted browser-side checks.
3. **Collect results** — status where available, timing, redirects and errors.
4. **Return to origin website** — send results using `postMessage` or a controlled API.

## What can it actually retrieve?

| Check | Possible from a temporary page? |
| --- | --- |
| Open the target website | Yes |
| Measure page load timing | Yes, with browser API limitations |
| Read HTTP status code | Not reliably for arbitrary cross-origin navigation |
| Read response headers/body | Only when browser security permissions allow it |
| Detect navigation errors | Partially; browser error pages restrict access |
| Inspect all network requests and their status codes | Better handled by a browser extension |
| Send collected results to the origin site | Yes, using `postMessage` or an API |

Important: opening a page in a new tab does **not** bypass CORS. The browser can
display a response while preventing JavaScript on your temporary page from reading
that response.

## Best implementation for this project

Use a temporary page **plus** a lightweight browser extension when comprehensive
request-status capture is needed:

- **Temporary page** — handles the user interaction and runs ordinary
  browser-side tests.
- **Browser extension** — observes actual browser request metadata where
  permissions allow (`browser-response-monitor/`).
- **Origin website** — receives results and displays them in Public Network Tracer.
- **Cleanup** — close the temporary tab after results are returned or after a
  timeout.

Use `window.postMessage()` only between pages you control, verify `event.origin`
and the expected message format, and avoid sending sensitive page contents.

## Open decision

Before implementation: does the temporary page need to test **any public
website**, or only websites **you own or have permission to assess**?
