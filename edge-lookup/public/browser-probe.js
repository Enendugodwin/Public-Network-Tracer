// Browser-probe core.
//
// URL validation, the fetch logic and the outcome labels used by the dashboard
// (app.js). Exposes window.BrowserProbe.
(function () {
  const BROWSER_PROBE_TIMEOUT_MS = 15_000;
  const BROWSER_CLASSIFY_TIMEOUT_MS = 8_000;

  /**
   * Turn loosely typed input ("example.com") into a URL the browser can fetch.
   * Only HTTP and HTTPS are accepted, and embedded credentials are refused so a
   * probe never carries authentication the user did not intend.
   */
  function normalizeBrowserUrl(raw) {
    const value = String(raw ?? "").trim();
    if (!value) throw new Error("Enter a URL to probe from the browser.");
    const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : `https://${value}`;
    let url;
    try {
      url = new URL(candidate);
    } catch {
      throw new Error("That is not a valid URL.");
    }
    if (!["http:", "https:"].includes(url.protocol)) {
      throw new Error("Only HTTP and HTTPS URLs are supported.");
    }
    if (url.username || url.password) {
      throw new Error("URLs with embedded credentials are not accepted.");
    }
    return url;
  }

  function headersToObject(headers) {
    const result = {};
    headers.forEach((value, name) => {
      result[name] = value;
    });
    return result;
  }

  /** A fetch that aborts after `timeoutMs`, reporting whether the timer fired. */
  async function fetchWithTimeout(url, options, timeoutMs) {
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    try {
      const response = await fetch(url, { ...options, signal: controller.signal });
      return { response, timedOut: false, error: null };
    } catch (error) {
      return { response: null, timedOut: timedOut || error?.name === "AbortError", error };
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Send one request from this browser to the target, without the Worker.
   *
   * A CORS-visible fetch resolves only when the browser can read the response.
   * When it fails, a single opaque (`mode: "no-cors"`) request distinguishes
   * "the request reached the network but the response is unreadable" from "the
   * request never completed" — JavaScript cannot see that difference directly.
   * Neither attempt is routed through the Worker, and neither reads a status
   * code it is not allowed to see.
   */
  async function browserProbe(rawTarget, { forceNoCors = false } = {}) {
    const url = normalizeBrowserUrl(rawTarget);
    const requestedUrl = url.href;
    const startedAt = performance.now();
    const elapsed = () => Math.round(performance.now() - startedAt);
    const base = { source: "browser", requestedUrl, targetUrl: requestedUrl };
    const noCorsOptions = {
      method: "GET",
      mode: "no-cors",
      cache: "no-store",
      redirect: "follow",
      credentials: "omit",
    };

    // Forced opaque mode: one no-cors request only. The browser hides the status
    // and all headers, so this reports delivery (reachability) and nothing more.
    if (forceNoCors) {
      const opaque = await fetchWithTimeout(url.href, noCorsOptions, BROWSER_PROBE_TIMEOUT_MS);
      if (opaque.response) {
        return { ...base, success: true, outcome: "opaque_response", responseTimeMs: elapsed(), error: null };
      }
      if (opaque.timedOut) {
        return { ...base, success: false, outcome: "timeout", responseTimeMs: elapsed(), error: "Request timed out" };
      }
      return {
        ...base,
        success: false,
        outcome: "network_failure",
        responseTimeMs: elapsed(),
        error: opaque.error instanceof Error ? opaque.error.message : "Request failed",
      };
    }

    const first = await fetchWithTimeout(url.href, {
      method: "GET",
      mode: "cors",
      cache: "no-store",
      redirect: "follow",
      credentials: "omit",
    }, BROWSER_PROBE_TIMEOUT_MS);

    if (first.response) {
      return {
        ...base,
        success: true,
        outcome: "http_response",
        finalUrl: first.response.url || requestedUrl,
        statusCode: first.response.status,
        statusText: first.response.statusText,
        redirected: first.response.redirected === true,
        responseTimeMs: elapsed(),
        headers: headersToObject(first.response.headers),
      };
    }

    if (first.timedOut) {
      return { ...base, success: false, outcome: "timeout", responseTimeMs: elapsed(), error: "Request timed out" };
    }

    const second = await fetchWithTimeout(url.href, noCorsOptions, BROWSER_CLASSIFY_TIMEOUT_MS);

    if (second.response) {
      return {
        ...base,
        success: false,
        outcome: "browser_policy_blocked",
        responseTimeMs: elapsed(),
        error: "Response not readable (CORS or an opaque response)",
      };
    }
    if (second.timedOut) {
      return { ...base, success: false, outcome: "timeout", responseTimeMs: elapsed(), error: "Request timed out" };
    }
    return {
      ...base,
      success: false,
      outcome: "network_failure",
      responseTimeMs: elapsed(),
      error: first.error instanceof Error ? first.error.message : "Request failed",
    };
  }

  /** Human-readable meaning for each browser-probe outcome. */
  const BROWSER_OUTCOMES = {
    http_response: {
      severity: "ok",
      badge: "http_response",
      title: "HTTP response received",
      summary: "The browser sent the request and could read the response, including its status and headers.",
    },
    browser_policy_blocked: {
      severity: "warn",
      badge: "browser_policy_blocked",
      title: "Blocked from JavaScript by browser policy",
      summary: "The request reached the network, but the browser would not let this page read the response (CORS or an opaque response). The destination may still have received the request, so this is not proof it is offline or failing.",
    },
    opaque_response: {
      severity: "warn",
      badge: "opaque_response",
      title: "Request delivered — response is opaque",
      summary: "The forced no-cors request completed, so the destination received it. Because the request was sent opaque, the browser hides the status code and all response headers; treat this as reachability only.",
    },
    network_failure: {
      severity: "bad",
      badge: "network_failure",
      title: "Network request failed",
      summary: "The request failed at the network or browser level — offline, DNS failure, connection refused, TLS error, or a policy block. Browsers do not expose the exact cause to JavaScript, so treat this as indeterminate.",
    },
    timeout: {
      severity: "bad",
      badge: "timeout",
      title: "Request timed out",
      summary: "No response arrived within the browser-probe timeout. The destination may be slow, unreachable, or silently dropping the request.",
    },
  };

  window.BrowserProbe = {
    BROWSER_PROBE_TIMEOUT_MS,
    BROWSER_CLASSIFY_TIMEOUT_MS,
    normalizeBrowserUrl,
    headersToObject,
    fetchWithTimeout,
    browserProbe,
    BROWSER_OUTCOMES,
  };
})();
