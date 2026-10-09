// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(resolve(here, "../public/index.html"), "utf8");
const appSource = readFileSync(resolve(here, "../public/app.js"), "utf8");
const probeCoreSource = readFileSync(resolve(here, "../public/browser-probe.js"), "utf8");

/** A complete-enough API payload for the renderer to consume. */
function fixture(overrides: Record<string, any> = {}) {
  return {
    target: { kind: "domain", host: "example.com", url: "https://example.com/" },
    probeSource: "cloudflare",
    lookupSource: { observedIp: "203.0.113.9", unavailableReason: null, probeOrigin: "edge, not your IP" },
    checkedAt: "2026-10-08T07:00:00.000Z",
    overview: { status: "200 OK", reachable: true, ip: "93.184.216.34", asn: "AS15133", organization: "Example Network", country: "US", responseTimeMs: 51, postureScore: 87, grade: "B" },
    http: {
      status: "complete",
      statusCode: 200,
      statusText: "OK",
      method: "HEAD",
      finalUrl: "https://example.com/",
      responseTimeMs: 51,
      contentLength: 1256,
      server: "ECS (dcc/DC)",
      tls: { enabled: true, version: null },
      redirects: [{ status: 301, from: "http://example.com/", to: "https://example.com/" }],
      redirectCount: 1,
      headerAnalysis: {
        security: { present: [{ name: "x-content-type-options", label: "X-Content-Type-Options", value: "nosniff" }], missing: [{ name: "content-security-policy", label: "Content-Security-Policy", why: "Limits XSS impact.", recommendation: "Add one." }], score: 9, max: 11 },
        caching: { "cache-control": "max-age=86000" },
        application: { "content-type": "text/html; charset=UTF-8", server: "ECS (dcc/DC)" },
      },
      body: null,
    },
    tcp: { status: "inconclusive", reason: "HTTP reached the host, but every raw TCP connect was refused.", checks: [] },
    diagnosis: { category: "reachable", severity: "ok", title: "Reachable", summary: "The site answered 200.", evidence: ["HTTP 200"] },
    posture: {
      score: 87,
      max: 100,
      grade: "B",
      categories: [
        { name: "HTTP", score: 20, max: 20, note: "responded 200" },
        { name: "TLS", score: 15, max: 20, note: "HTTPS in use" },
        { name: "Headers", score: 16, max: 20, note: "1/7 security headers" },
        { name: "DNS", score: 16, max: 20, note: "2 A · 2 AAAA · 0 CAA" },
        { name: "Infrastructure", score: 20, max: 20, note: "AS15133" },
      ],
    },
    findings: [
      { id: "no-csp", severity: "medium", title: "Missing Content-Security-Policy", detail: "No CSP is set.", why: "Main defence against XSS.", recommendation: "Add one.", evidence: ["HTTP 200", "header absent"], source: "Live HTTP request" },
      { id: "ipv6", severity: "info", title: "IPv6 enabled", detail: "Two AAAA records.", why: "Resilience.", recommendation: "None.", evidence: ["AAAA 2606::1"], source: "Cloudflare DoH" },
    ],
    registration: { registrar: "RESERVED-IANA", nameservers: ["a.iana-servers.net"], events: { registration: "1995-08-14T04:00:00Z", expiration: "2027-08-13T04:00:00Z" } },
    tls: { enabled: true, version: null, note: "Workers' fetch does not expose the negotiated TLS version." },
    network: {
      ip: "93.184.216.34",
      ipVersion: "IPv4",
      reverseDns: ["edge.example.com."],
      hostingType: "CDN (Fastly)",
      abuseContact: "abuse@example.net",
      asn: { asn: "AS15133", prefix: "93.184.216.0/24", country: "US", registry: "arin" },
      prefix: "93.184.216.0/24",
      organization: "Example Network",
      country: "US",
      networkName: "EDGECAST",
      range: "93.184.216.0 – 93.184.216.255",
      domain: null,
      dns: { A: ["93.184.216.34"], AAAA: ["2606:2800::1"], MX: ["0 ."], CAA: [], dnssec: ["validated"] },
      privateDnsAnswersFiltered: false,
      observedPorts: [80, 443, 8080],
      services: [":443/tcp https"],
      certificates: [],
      portSourceAvailable: true,
    },
    sources: [{ name: "Cloudflare DoH A", url: "https://cloudflare-dns.com/", collectedAt: "2026-10-08T07:00:00.000Z", publishedAt: null, contentSha256: null, confidence: 95, kind: "cached", freshness: "cached ≤ 120s" }],
    ...overrides,
  };
}

function loadPage() {
  const body = html.match(/<body[^>]*>([\s\S]*)<\/body>/i)?.[1] ?? html;
  document.body.innerHTML = body.replace(/<script[\s\S]*?<\/script>/gi, "");
  delete document.documentElement.dataset.corsRelaxer;
  // eslint-disable-next-line no-new-func
  new Function(probeCoreSource)();
  // eslint-disable-next-line no-new-func
  new Function(appSource)();
}

async function submitLookup(target: string) {
  const input = document.querySelector("#targetInput") as HTMLInputElement;
  input.value = target;
  document.querySelector("#lookupForm")!.dispatchEvent(new Event("submit", { cancelable: true }));
}

describe("dashboard rendering", () => {
  beforeEach(() => {
    localStorage.clear();
    loadPage();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete (window as any).TRACER_API_BASE;
    (globalThis as any).happyDOM?.setURL?.("http://localhost/");
  });

  it("renders summary, posture, findings, DNS, network and sources from an API result", async () => {
    vi.stubGlobal("fetch", async (url: string | URL) => {
      const value = String(url);
      if (value.includes("cdn-cgi/trace")) return new Response("ip=198.51.100.4\n", { status: 200 });
      if (value.includes("/api/lookup")) return Response.json(fixture());
      throw new Error(`unexpected fetch: ${value}`);
    });

    await submitLookup("example.com");

    await vi.waitFor(() => {
      expect(document.querySelector("#sumStatus")?.textContent).toContain("200");
    });

    expect(document.querySelector("#results")?.hasAttribute("hidden")).toBe(false);
    expect(document.querySelector("#sumIp")?.textContent).toBe("93.184.216.34");
    expect(document.querySelector("#sumPosture")?.textContent).toContain("87");
    expect(document.querySelector("#postureGrade")?.textContent).toBe("B");
    expect(document.querySelectorAll("#postureBars .posture-bar")).toHaveLength(5);
    expect(document.querySelectorAll("#findingsList .finding")).toHaveLength(2);
    expect(document.querySelector("#findingsCount")?.textContent).toContain("2");
    expect(document.querySelector("#dnsList")?.textContent).toContain("93.184.216.34");
    expect(document.querySelector("#dnssecState")?.textContent).toContain("DNSSEC AD");
    expect(document.querySelector("#networkPtr")?.textContent).toContain("edge.example.com.");
    expect(document.querySelector("#networkAbuse")?.textContent).toContain("abuse@example.net");
    expect(document.querySelector("#relAsn")?.textContent).toBe("AS15133");
    expect(document.querySelector("#securityHeaders")?.textContent).toContain("X-Content-Type-Options");
    expect(document.querySelector("#missingHeaders")?.textContent).toContain("Content-Security-Policy");
    expect(document.querySelector("#redirectChain")?.textContent).toContain("301");
    expect(document.querySelectorAll("#sourceList .source-item").length).toBeGreaterThan(0);
    // Active vs passive ports must stay distinct.
    expect(document.querySelector("#activePorts")?.textContent).toContain("not measurable");
    expect(document.querySelector("#passivePorts")?.textContent).toContain(":8080");
    // The TCP caution is surfaced, not silently swallowed.
    expect(document.querySelector("#diagnosis")?.textContent).toContain("Reachable");
  });

  it("uses the edge source IP when present and never calls the trace endpoint", async () => {
    const calls: string[] = [];
    vi.stubGlobal("fetch", async (url: string | URL) => {
      const value = String(url);
      calls.push(value);
      if (value.includes("/api/lookup")) return Response.json(fixture({ lookupSource: { observedIp: "9.9.9.9", probeOrigin: "edge" } }));
      throw new Error(`unexpected fetch: ${value}`);
    });

    await submitLookup("example.com");
    await vi.waitFor(() => expect(document.querySelector("#routeSource")?.textContent).toBe("9.9.9.9"));
    expect(calls.some((call) => call.includes("cdn-cgi/trace"))).toBe(false);
  });

  it("explains a missing API instead of failing silently", async () => {
    vi.stubGlobal("fetch", async () => new Response("<html>404</html>", { status: 404, headers: { "content-type": "text/html" } }));
    await submitLookup("example.com");
    await vi.waitFor(() => {
      expect(document.querySelector("#formStatus")?.textContent).toMatch(/No lookup API/i);
    });
    expect(document.querySelector("#results")?.hasAttribute("hidden")).toBe(true);
  });

  it("keeps local development on its own origin even when a remote API base is configured", async () => {
    (window as any).TRACER_API_BASE = "https://public-network-tracer.example.workers.dev";
    const calls: string[] = [];
    vi.stubGlobal("fetch", async (url: string | URL) => {
      calls.push(String(url));
      return Response.json(fixture());
    });

    await submitLookup("example.com");
    await vi.waitFor(() => expect(document.querySelector("#sumStatus")?.textContent).toContain("200"));

    // The regression: a configured base used to send localhost cross-origin to a
    // Worker that does not allowlist it, surfacing as "Could not reach the lookup API".
    expect(calls).toContain("/api/lookup");
    expect(calls.some((call) => call.startsWith("https://public-network-tracer.example.workers.dev"))).toBe(false);
  });

  it("treats a private LAN address as local development too", async () => {
    const happy = (globalThis as any).happyDOM;
    if (!happy?.setURL) return;
    happy.setURL("http://192.168.1.50:8787/");
    (window as any).TRACER_API_BASE = "https://public-network-tracer.example.workers.dev";

    const calls: string[] = [];
    vi.stubGlobal("fetch", async (url: string | URL) => {
      calls.push(String(url));
      return Response.json(fixture());
    });

    await submitLookup("example.com");
    await vi.waitFor(() => expect(document.querySelector("#sumStatus")?.textContent).toContain("200"));
    expect(calls).toContain("/api/lookup");
    expect(calls.some((call) => call.startsWith("https://public-network-tracer.example.workers.dev"))).toBe(false);
  });

  it("uses the configured base when the page is hosted on another origin", async () => {
    const happy = (globalThis as any).happyDOM;
    if (!happy?.setURL) return; // environment cannot simulate a different origin
    happy.setURL("https://enendugodwin.github.io/");
    (window as any).TRACER_API_BASE = "https://public-network-tracer.example.workers.dev";

    const calls: string[] = [];
    vi.stubGlobal("fetch", async (url: string | URL) => {
      calls.push(String(url));
      return Response.json(fixture());
    });

    await submitLookup("example.com");
    await vi.waitFor(() => expect(document.querySelector("#sumStatus")?.textContent).toContain("200"));
    expect(calls).toContain("https://public-network-tracer.example.workers.dev/api/lookup");
  });

  it("sends a user-supplied Shodan key as a header, and does not remember it by default", async () => {
    const init_headers: any[] = [];
    vi.stubGlobal("fetch", async (_url: string | URL, init?: RequestInit) => {
      init_headers.push(init?.headers);
      return Response.json(fixture());
    });

    (document.querySelector("#shodanKey") as HTMLInputElement).value = "abcdef1234567890abcdef1234567890";
    (document.querySelector("#saveShodanKey") as HTMLButtonElement).click();
    expect(document.querySelector("#optionsBadge")?.hasAttribute("hidden")).toBe(false);

    await submitLookup("example.com");
    await vi.waitFor(() => expect(document.querySelector("#sumStatus")?.textContent).toContain("200"));

    const sent = init_headers.find((headers) => headers && headers["X-Shodan-Key"]);
    expect(sent?.["X-Shodan-Key"]).toBe("abcdef1234567890abcdef1234567890");
    // Not remembered unless the user asked for it.
    expect(localStorage.getItem("pit.shodanKey.v1")).toBeNull();
  });

  it("remembers the Shodan key only when asked", async () => {
    vi.stubGlobal("fetch", async () => Response.json(fixture()));
    (document.querySelector("#shodanKey") as HTMLInputElement).value = "abcdef1234567890abcdef1234567890";
    (document.querySelector("#rememberShodanKey") as HTMLInputElement).checked = true;
    (document.querySelector("#saveShodanKey") as HTMLButtonElement).click();
    expect(localStorage.getItem("pit.shodanKey.v1")).toBe("abcdef1234567890abcdef1234567890");

    (document.querySelector("#clearShodanKey") as HTMLButtonElement).click();
    expect(localStorage.getItem("pit.shodanKey.v1")).toBeNull();
    expect(document.querySelector("#optionsBadge")?.hasAttribute("hidden")).toBe(true);
  });

  it("rejects a malformed Shodan key and sends no header", async () => {
    const init_headers: any[] = [];
    vi.stubGlobal("fetch", async (_url: string | URL, init?: RequestInit) => {
      init_headers.push(init?.headers);
      return Response.json(fixture());
    });

    (document.querySelector("#shodanKey") as HTMLInputElement).value = "not a real key";
    (document.querySelector("#saveShodanKey") as HTMLButtonElement).click();
    expect(document.querySelector("#shodanKeyStatus")?.textContent).toMatch(/does not look like/i);
    expect(document.querySelector("#optionsBadge")?.hasAttribute("hidden")).toBe(true);

    await submitLookup("example.com");
    await vi.waitFor(() => expect(document.querySelector("#sumStatus")?.textContent).toContain("200"));
    expect(init_headers.some((headers) => headers && headers["X-Shodan-Key"])).toBe(false);
  });

  it("records recent lookups in localStorage and clears them", async () => {
    vi.stubGlobal("fetch", async (url: string | URL) => {
      const value = String(url);
      if (value.includes("/api/lookup")) return Response.json(fixture());
      return new Response("ip=198.51.100.4\n", { status: 200 });
    });

    await submitLookup("example.com");
    await vi.waitFor(() => expect(document.querySelectorAll("#historyList .history-chip").length).toBe(1));
    expect(document.querySelector("#historyBlock")?.hasAttribute("hidden")).toBe(false);
    expect(localStorage.getItem("pit.history.v1")).toContain("example.com");

    (document.querySelector("#clearHistory") as HTMLButtonElement).click();
    expect(document.querySelectorAll("#historyList .history-chip")).toHaveLength(0);
    expect(document.querySelector("#historyBlock")?.hasAttribute("hidden")).toBe(true);
  });

  it("shows the selected request source in the results", async () => {
    vi.stubGlobal("fetch", async (url: string | URL) => {
      if (String(url).includes("/api/lookup")) return Response.json(fixture());
      return new Response("ip=198.51.100.4\n");
    });

    await submitLookup("example.com");
    await vi.waitFor(() => expect(document.querySelector("#results")?.hasAttribute("hidden")).toBe(false));
    expect(document.querySelector("#results .route-source .route-value")?.textContent).toBe("Cloudflare probe");
  });

  describe("request source: Browser Probe", () => {
    function selectProbeSource(value: "cloudflare" | "browser") {
      const radio = document.querySelector(`input[name="probeSource"][value="${value}"]`) as HTMLInputElement;
      radio.checked = true;
      radio.dispatchEvent(new Event("change", { bubbles: true }));
    }

    it("runs the request from the browser and never calls the Worker", async () => {
      const calls: Array<{ url: string; init?: RequestInit }> = [];
      vi.stubGlobal("fetch", async (url: string | URL, init?: RequestInit) => {
        calls.push({ url: String(url), init });
        return new Response("ok", { status: 200, statusText: "OK", headers: { "content-type": "text/html", server: "example" } });
      });

      selectProbeSource("browser");
      await submitLookup("https://example.com/");
      await vi.waitFor(() => expect(document.querySelector("#browserSumStatus")?.textContent).toContain("200"));

      expect(document.querySelector("#browserResults")?.hasAttribute("hidden")).toBe(false);
      expect(document.querySelector("#results")?.hasAttribute("hidden")).toBe(true);
      // The request went to the target, not to the Worker.
      expect(calls.some((call) => call.url.includes("/api/lookup"))).toBe(false);
      expect(calls[0]?.url).toBe("https://example.com/");
      expect(calls[0]?.init?.mode).toBe("cors");
      // No destination cookies or credentials are carried by default.
      expect(calls[0]?.init?.credentials).toBe("omit");
      expect(document.querySelector("#browserHttpStatus")?.textContent).toContain("200");
      expect(document.querySelector("#browserHeaders")?.textContent).toContain("content-type");
      // The selected source is always identified.
      expect(document.querySelector("#browserResults")?.textContent).toContain("Browser probe");
    });

    it("records the final URL and redirect status when the browser can read them", async () => {
      vi.stubGlobal("fetch", async () => {
        const response = new Response("ok", { status: 200, headers: { "content-type": "text/plain" } });
        Object.defineProperty(response, "url", { value: "https://example.com/final" });
        Object.defineProperty(response, "redirected", { value: true });
        return response;
      });

      selectProbeSource("browser");
      await submitLookup("example.com");
      await vi.waitFor(() => expect(document.querySelector("#browserHttpFinalUrl")?.textContent).toContain("/final"));
      expect(document.querySelector("#browserHttpRedirect")?.textContent).toBe("yes");
      expect(document.querySelector("#browserSumRedirect")?.textContent).toBe("yes");
    });

    it("reports a CORS/browser-policy block as unreadable, never as an HTTP status", async () => {
      vi.stubGlobal("fetch", async (_url: string | URL, init?: RequestInit) => {
        if (init?.mode === "no-cors") return new Response(null, { status: 200 });
        throw new TypeError("Failed to fetch");
      });

      selectProbeSource("browser");
      await submitLookup("https://example.com/");
      await vi.waitFor(() => expect(document.querySelector("#browserDiagnosisBadge")?.textContent).toBe("browser_policy_blocked"));

      expect(document.querySelector("#browserHttpStatus")?.textContent).toMatch(/not accessible/i);
      expect(document.querySelector("#browserHttpStatus")?.textContent).not.toContain("200");
      expect(document.querySelector("#browserSumStatus")?.textContent).toBe("No readable status");
      expect(document.querySelector("#browserSumReadable")?.textContent).toBe("No");
      expect(document.querySelector("#browserHeaders")?.textContent).toContain("opaque");
    });

    it("reports a network-level failure distinctly from a CORS block", async () => {
      vi.stubGlobal("fetch", async () => {
        throw new TypeError("Failed to fetch");
      });

      selectProbeSource("browser");
      await submitLookup("https://example.com/");
      await vi.waitFor(() => expect(document.querySelector("#browserDiagnosisBadge")?.textContent).toBe("network_failure"));
      expect(document.querySelector("#browserHttpError")?.textContent).toBe("network_failure");
    });

    it("rejects invalid URLs and non-HTTP protocols without sending a request", async () => {
      const calls: string[] = [];
      vi.stubGlobal("fetch", async (url: string | URL) => {
        calls.push(String(url));
        return new Response("ok");
      });

      selectProbeSource("browser");
      await submitLookup("https://");
      await vi.waitFor(() => expect(document.querySelector("#formStatus")?.textContent).toMatch(/valid URL/i));
      expect(calls).toHaveLength(0);
      expect(document.querySelector("#browserResults")?.hasAttribute("hidden")).toBe(true);

      await submitLookup("ftp://example.com/");
      await vi.waitFor(() => expect(document.querySelector("#formStatus")?.textContent).toMatch(/HTTP and HTTPS/i));
      expect(calls).toHaveLength(0);
    });

    it("offers an explicit Cloudflare retry instead of falling back silently", async () => {
      const calls: string[] = [];
      vi.stubGlobal("fetch", async (url: string | URL, init?: RequestInit) => {
        const value = String(url);
        calls.push(value);
        if (value.includes("/api/lookup")) return Response.json(fixture());
        if (init?.mode === "no-cors") return new Response(null, { status: 200 });
        throw new TypeError("Failed to fetch");
      });

      selectProbeSource("browser");
      await submitLookup("https://example.com/");
      await vi.waitFor(() => expect(document.querySelector("#browserDiagnosisBadge")?.textContent).toBe("browser_policy_blocked"));
      // No silent fallback to the Worker.
      expect(calls.some((call) => call.includes("/api/lookup"))).toBe(false);

      (document.querySelector("#browserRetryCloudflare") as HTMLButtonElement).click();
      await vi.waitFor(() => expect(calls.some((call) => call.includes("/api/lookup"))).toBe(true));
      expect((document.querySelector('input[name="probeSource"][value="cloudflare"]') as HTMLInputElement).checked).toBe(true);
      await vi.waitFor(() => expect(document.querySelector("#sumStatus")?.textContent).toContain("200"));
    });

    it("only offers the force no-cors toggle for the Browser Probe", () => {
      const options = document.querySelector("#browserOptions");
      expect(options?.hasAttribute("hidden")).toBe(true);
      selectProbeSource("browser");
      expect(options?.hasAttribute("hidden")).toBe(false);
      selectProbeSource("cloudflare");
      expect(options?.hasAttribute("hidden")).toBe(true);
    });

    it("forces a single opaque no-cors request when the toggle is on", async () => {
      const calls: Array<{ url: string; init?: RequestInit }> = [];
      vi.stubGlobal("fetch", async (url: string | URL, init?: RequestInit) => {
        calls.push({ url: String(url), init });
        return new Response(null, { status: 200 });
      });

      selectProbeSource("browser");
      (document.querySelector("#forceNoCors") as HTMLInputElement).checked = true;
      await submitLookup("https://example.com/");
      await vi.waitFor(() => expect(document.querySelector("#browserDiagnosisBadge")?.textContent).toBe("opaque_response"));

      // Exactly one request to the target, sent no-cors; no CORS-visible attempt.
      const probeCalls = calls.filter((call) => call.url === "https://example.com/");
      expect(probeCalls).toHaveLength(1);
      expect(probeCalls[0]?.init?.mode).toBe("no-cors");
      expect(probeCalls[0]?.init?.credentials).toBe("omit");
      expect(document.querySelector("#browserHttpStatus")?.textContent).toMatch(/opaque/i);
      expect(document.querySelector("#browserSumReadable")?.textContent).toBe("No");
    });

    it("reports a network failure when the forced opaque request fails", async () => {
      vi.stubGlobal("fetch", async () => {
        throw new TypeError("Failed to fetch");
      });

      selectProbeSource("browser");
      (document.querySelector("#forceNoCors") as HTMLInputElement).checked = true;
      await submitLookup("https://example.com/");
      await vi.waitFor(() => expect(document.querySelector("#browserDiagnosisBadge")?.textContent).toBe("network_failure"));
    });

    it("shows the CORS Relaxer chip when the extension marks the page", () => {
      document.documentElement.dataset.corsRelaxer = "1";
      selectProbeSource("browser");
      expect(document.querySelector("#browserOptions")?.hasAttribute("hidden")).toBe(false);
      expect(document.querySelector("#relaxerStatus")?.hasAttribute("hidden")).toBe(false);
    });

    it("offers the CORS Relaxer download to browser-probe users", () => {
      selectProbeSource("browser");
      const link = document.querySelector("#downloadRelaxer") as HTMLAnchorElement;
      expect(link).toBeTruthy();
      expect(link.getAttribute("href")).toBe("cors-relaxer.zip");
      expect(link.hasAttribute("download")).toBe(true);
    });

    it("shows the browser's public IP as the origin of the probe", async () => {
      vi.stubGlobal("fetch", async (url: string | URL) => {
        if (String(url).includes("cdn-cgi/trace")) return new Response("ip=198.51.100.7\n", { status: 200 });
        return new Response("ok", { status: 200, statusText: "OK", headers: { "content-type": "text/html" } });
      });

      selectProbeSource("browser");
      await submitLookup("https://example.com/");
      await vi.waitFor(() => expect(document.querySelector("#browserRouteIp")?.textContent).toBe("198.51.100.7"));
    });

    it("flags a full cross-origin read when the CORS Relaxer is present", async () => {
      document.documentElement.dataset.corsRelaxer = "1";
      vi.stubGlobal("fetch", async () => new Response("ok", { status: 200, statusText: "OK", headers: { "content-type": "text/html" } }));

      selectProbeSource("browser");
      await submitLookup("https://example.com/");
      await vi.waitFor(() => expect(document.querySelector("#browserSumStatus")?.textContent).toContain("200"));
      expect(document.querySelector("#browserDiagnosisEvidence")?.textContent).toContain("cors relaxer");
    });
  });
});
