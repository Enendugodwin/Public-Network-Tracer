// Temporary probe page.
//
// Opened by app.js as popup.html-style window (probe.html?target=…&token=…).
// It runs the shared browser probe, shows the result, and posts it back to the
// originating tab. The popup is same-origin (it is served by the dashboard's
// own origin), which is what lets it postMessage at all: a popup pointed at the
// cross-origin target could not script itself to report anything.
(function () {
  const params = new URLSearchParams(location.search);
  const target = params.get("target") || "";
  const token = params.get("token") || "";
  const forceNoCors = params.get("nocors") === "1";

  const MESSAGE_TYPE = "PIT_BROWSER_PROBE_RESULT";

  function setText(id, value, fallback = "—") {
    const node = document.getElementById(id);
    if (node) node.textContent = value == null || value === "" ? fallback : String(value);
  }

  function setTokens(id, values, emptyMessage) {
    const node = document.getElementById(id);
    if (!node) return;
    node.replaceChildren();
    const list = Array.isArray(values) ? values : [];
    if (!list.length) {
      const empty = document.createElement("span");
      empty.className = "muted";
      empty.textContent = emptyMessage;
      node.append(empty);
      return;
    }
    for (const value of list) {
      const token = document.createElement("span");
      token.className = "token";
      token.textContent = String(value);
      node.append(token);
    }
  }

  function render(probe) {
    const meta = (window.BrowserProbe?.BROWSER_OUTCOMES ?? {})[probe.outcome] ?? {};
    const readable = probe.outcome === "http_response";

    setText("target", probe.targetUrl || target);
    setText("outcome", meta.title || probe.outcome || "unknown");
    setText("status", readable ? `${probe.statusCode} ${probe.statusText ?? ""}`.trim() : "not accessible");
    setText("time", Number.isFinite(probe.responseTimeMs) ? `${probe.responseTimeMs} ms` : "—");
    setText("redirect", probe.redirected == null ? "unknown" : probe.redirected ? "yes" : "no");
    setTokens("headers", Object.entries(probe.headers ?? {}).map(([name, value]) => `${name}: ${value}`), "None accessible");

    const notice = document.getElementById("notice");
    if (notice) {
      const explain = meta.summary || probe.error || "";
      notice.hidden = !explain;
      notice.textContent = explain;
    }
  }

  /** Send the result back to the originating tab. Same-origin only. */
  function report(probe) {
    if (window.opener && !window.opener.closed) {
      try {
        window.opener.postMessage({ type: MESSAGE_TYPE, token, probe }, location.origin);
      } catch {
        /* the opener went away — the result is still shown here */
      }
    }
  }

  async function run() {
    setText("target", target);
    if (!window.BrowserProbe) {
      const probe = { source: "browser", success: false, outcome: "network_failure", requestedUrl: target, targetUrl: target, responseTimeMs: 0, error: "probe core failed to load" };
      render(probe);
      report(probe);
      return;
    }
    try {
      const probe = await window.BrowserProbe.browserProbe(target, { forceNoCors });
      render(probe);
      report(probe);
    } catch (error) {
      const probe = {
        source: "browser",
        success: false,
        outcome: "network_failure",
        requestedUrl: target,
        targetUrl: target,
        responseTimeMs: 0,
        error: error instanceof Error ? error.message : "Probe failed",
      };
      render(probe);
      report(probe);
    }
  }

  document.getElementById("openTarget")?.addEventListener("click", () => {
    try {
      window.open(target, "_blank", "noopener");
    } catch {
      /* popup blocker, or an invalid target */
    }
  });
  document.getElementById("closeWindow")?.addEventListener("click", () => window.close());

  run();
})();
