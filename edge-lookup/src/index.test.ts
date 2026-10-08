import { afterEach, describe, expect, it, vi } from "vitest";
import worker, { normalizeTarget, resetLookupCache } from "./index";

const socketState = vi.hoisted(() => ({ mode: "open" as "open" | "throw" }));

vi.mock("cloudflare:sockets", () => ({
  connect: () => {
    if (socketState.mode === "throw") throw new Error("connection refused");
    return { opened: Promise.resolve(), close: async () => {} };
  },
}));

afterEach(() => {
  vi.unstubAllGlobals();
  resetLookupCache();
  socketState.mode = "open";
});

describe("normalizeTarget", () => {
  it("accepts public IPv4, IPv6, domains, and HTTP(S) URLs", () => {
    expect(normalizeTarget("8.8.8.8").host).toBe("8.8.8.8");
    expect(normalizeTarget("2001:4860:4860::8888").kind).toBe("ip");
    expect(normalizeTarget("Example.COM").url.href).toBe("https://example.com/");
    expect(normalizeTarget("http://example.com/path?q=ok#fragment").url.href).toBe("http://example.com/path?q=ok");
  });

  it.each(["127.0.0.1", "10.2.3.4", "169.254.1.2", "::1", "[::ffff:127.0.0.1]"])(
    "rejects private or reserved address %s",
    (target) => expect(() => normalizeTarget(target)).toThrow(/private or reserved/i),
  );

  it.each(["ftp://example.com", "https://user:secret@example.com", "https://example.com:8443", "https://example.com/?api_key=secret", "localhost", "router.local"])(
    "rejects unsafe target form %s",
    (target) => expect(() => normalizeTarget(target)).toThrow(),
  );
});

describe("lookup API", () => {
  function installProviderMocks() {
    const calls: Array<{ url: string; method: string; redirect?: string }> = [];
    vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      const method = init?.method ?? (input instanceof Request ? input.method : "GET");
      calls.push({ url, method, redirect: init?.redirect });
      if (url.includes("cloudflare-dns.com")) {
        const type = new URL(url).searchParams.get("type");
        if (type === "TXT") return Response.json({ Answer: [{ type: 16, data: '"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"' }] });
        if (type === "A") return Response.json({ Answer: [{ type: 1, data: "8.8.8.8" }] });
        if (type === "AAAA") return Response.json({ Answer: [{ type: 28, data: "2001:4860:4860::8888" }] });
        return Response.json({ Answer: [] });
      }
      if (url.includes("rdap.org/autnum/")) {
        return Response.json({ entities: [{ roles: ["registrant"], vcardArray: ["vcard", [["fn", {}, "text", "Example Network"]]] }] });
      }
      if (url.includes("rdap.org/ip/")) {
        return Response.json({ name: "Example Net", country: "US", startAddress: "8.8.8.0", endAddress: "8.8.8.255" });
      }
      if (method === "HEAD") return new Response(null, { status: 200, headers: { server: "fixture", "content-length": "123" } });
      throw new Error(`Unexpected provider request: ${url}`);
    });
    return calls;
  }

  let clientCounter = 0;

  async function requestLookup(env: Record<string, unknown>, target = "8.8.8.8", clientIp?: string) {
    // Unique client IP per call keeps the per-client rate limiter out of unrelated cases.
    const ip = clientIp ?? `9.9.9.${(clientCounter += 1)}`;
    const request = new Request("https://lookup.test/api/lookup", {
      method: "POST",
      headers: { "Content-Type": "application/json", "CF-Connecting-IP": ip },
      body: JSON.stringify({ target }),
    });
    return worker.fetch(request, { ASSETS: { fetch: async () => new Response("asset") }, ...env } as never);
  }

  it("runs passive enrichment and the live checks for any public target by default", async () => {
    const calls = installProviderMocks();
    const response = await requestLookup({});
    const body = await response.json() as any;
    expect(response.status).toBe(200);
    expect(body.http.status).toBe("complete");
    expect(body.http.statusCode).toBe(200);
    expect(body.network.asn.asn).toBe("AS15169");
    expect(body.network.asn.country).toBe("US");
    expect(body.network.organization).toBe("Example Network");
    expect(calls.filter((call) => call.method === "HEAD")).toHaveLength(1);
    // Regression: an object interpolated into a finding string used to render "[object Object]".
    const networkFinding = body.findings.find((finding: any) => finding.id === "network-path");
    expect(networkFinding.detail).toContain("AS15169");
    expect(JSON.stringify(body.findings)).not.toContain("[object Object]");
  });

  it("follows provider redirects so RDAP lookups resolve", async () => {
    const calls = installProviderMocks();
    await requestLookup({});
    const rdapCalls = calls.filter((call) => call.url.includes("rdap.org"));
    expect(rdapCalls.length).toBeGreaterThan(0);
    expect(rdapCalls.every((call) => call.redirect === "follow")).toBe(true);
  });

  it("filters private DNS answers and refuses to probe", async () => {
    const calls: Array<{ url: string; method: string }> = [];
    vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      const method = init?.method ?? (input instanceof Request ? input.method : "GET");
      calls.push({ url, method });
      if (url.includes("cloudflare-dns.com")) {
        const type = new URL(url).searchParams.get("type");
        if (type === "A") return Response.json({ Answer: [{ type: 1, data: "93.184.216.34" }] });
        if (type === "AAAA") return Response.json({ Answer: [{ type: 28, data: "fd00::1" }] });
        return Response.json({ Answer: [{ type: 16, data: '"15169 | 93.184.216.0/24 | US | arin | 1997-03-14"' }] });
      }
      if (url.includes("rdap.org/domain/")) return Response.json({ nameservers: [], events: [] });
      if (url.includes("rdap.org/autnum/")) return Response.json({});
      if (url.includes("rdap.org/ip/")) return Response.json({ country: "US" });
      if (method === "HEAD") return Response.json({ status: "unexpected" }, { status: 500 });
      throw new Error(`Unexpected provider request: ${url}`);
    });

    const response = await requestLookup({}, "example.com");
    const body = await response.json() as any;
    expect(response.status).toBe(200);
    expect(body.network.dns.A).toEqual(["93.184.216.34"]);
    expect(body.network.dns.AAAA).toEqual([]);
    expect(body.network.privateDnsAnswersFiltered).toBe(true);
    expect(body.http.status).toBe("blocked");
    expect(calls.every((call) => call.method !== "HEAD")).toBe(true);
  });

  it("labels the visitor's observed public IP as the source", async () => {
    installProviderMocks();
    const response = await requestLookup({}, "8.8.8.8", "9.9.9.9");
    const body = await response.json() as any;
    expect(body.source.observedIp).toBe("9.9.9.9");
    expect(body.source.probeOrigin).toMatch(/edge network/i);
  });

  it("TCP-connects the web ports by default", async () => {
    installProviderMocks();
    const response = await requestLookup({});
    const body = await response.json() as any;
    expect(body.tcp.status).toBe("complete");
    expect(body.tcp.checks.map((check: any) => check.port).sort((a: number, b: number) => a - b)).toEqual([80, 443]);
    expect(body.tcp.checks.every((check: any) => check.reachable)).toBe(true);
  });

  it("includes extra ports from config and reports refusal honestly", async () => {
    installProviderMocks();
    socketState.mode = "throw";
    const response = await requestLookup({ EXTRA_PORTS: "8080" });
    const body = await response.json() as any;
    const ports = body.tcp.checks.map((check: any) => check.port);
    expect(ports).toContain(8080);
    expect(body.tcp.checks.filter((check: any) => check.port === 8080)[0].reachable).toBe(false);
    expect(body.tcp.checks.filter((check: any) => check.port === 8080)[0].detail).toMatch(/refused|filtered/i);
  });

  it("refuses to run checks against a private address", async () => {
    installProviderMocks();
    const response = await requestLookup({}, "127.0.0.1");
    const body = await response.json() as any;
    expect(response.status).toBe(400);
    expect(body.error).toMatch(/private or reserved/i);
  });

  it("returns DNS_NO_RECORDS when a name does not resolve", async () => {
    vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      const method = init?.method ?? "GET";
      if (url.includes("cloudflare-dns.com")) return Response.json({ Answer: [] });
      if (url.includes("rdap.org")) return Response.json({});
      if (method === "HEAD") throw new Error("should not be reached");
      throw new Error(`Unexpected: ${url}`);
    });
    const response = await requestLookup({}, "no-such-host.example");
    const body = await response.json() as any;
    expect(body.http.status).toBe("error");
    expect(body.http.code).toBe("DNS_NO_RECORDS");
    expect(body.overview.reachable).toBe(false);
    expect(body.overview.status).toBe("DNS_NO_RECORDS");
    // Regression: an unresolvable name must not be reported as a blocked private address.
    expect(body.tcp.status).toBe("not_run");
    expect(body.tcp.reason).toMatch(/no public address/i);
  });

  it("classifies an HTTP timeout as CONNECT_TIMEOUT", async () => {
    vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      const method = init?.method ?? "GET";
      if (url.includes("cloudflare-dns.com")) {
        const type = new URL(url).searchParams.get("type");
        if (type === "TXT") return Response.json({ Answer: [{ type: 16, data: '"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"' }] });
        return Response.json({ Answer: [{ type: type === "A" ? 1 : 28, data: type === "A" ? "8.8.8.8" : "2001:4860:4860::8888" }] });
      }
      if (url.includes("rdap.org")) return Response.json({});
      if (method === "HEAD") throw new DOMException("The operation was aborted due to timeout", "TimeoutError");
      throw new Error(`Unexpected: ${url}`);
    });
    const response = await requestLookup({});
    const body = await response.json() as any;
    expect(body.http.status).toBe("error");
    expect(body.http.code).toBe("CONNECT_TIMEOUT");
  });

  it("codes a refused TCP port instead of only saying closed", async () => {
    installProviderMocks();
    socketState.mode = "throw";
    const response = await requestLookup({});
    const body = await response.json() as any;
    expect(body.tcp.checks.every((check: any) => check.code === "CONNECTION_REFUSED")).toBe(true);
  });

  it("serves repeat lookups from the in-isolate cache", async () => {
    const calls = installProviderMocks();
    await requestLookup({});
    const afterFirst = calls.filter((call) => call.method !== "HEAD").length;
    expect(afterFirst).toBeGreaterThan(0);

    await requestLookup({});
    const afterSecond = calls.filter((call) => call.method !== "HEAD").length;
    // Enrichment is cached; the live HEAD check deliberately is not.
    expect(afterSecond).toBe(afterFirst);
    expect(calls.filter((call) => call.method === "HEAD")).toHaveLength(2);
  });

  it("diagnoses an edge/WAF block from the blocking status plus edge headers", async () => {
    vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      const method = init?.method ?? "GET";
      if (url.includes("cloudflare-dns.com")) {
        const type = new URL(url).searchParams.get("type");
        if (type === "TXT") return Response.json({ Answer: [{ type: 16, data: '"13335 | 104.20.0.0/16 | US | arin | 2014-03-28"' }] });
        return Response.json({ Answer: [{ type: type === "A" ? 1 : 28, data: type === "A" ? "104.20.23.154" : "2606:4700::1" }] });
      }
      if (url.includes("rdap.org")) return Response.json({});
      if (method === "HEAD") {
        return new Response(null, { status: 403, headers: { server: "cloudflare", "cf-ray": "abc123-LHR", "cf-mitigated": "challenge" } });
      }
      throw new Error(`Unexpected: ${url}`);
    });

    const response = await requestLookup({});
    const body = await response.json() as any;
    expect(body.diagnosis.category).toBe("waf_block");
    expect(body.diagnosis.severity).toBe("warn");
    expect(body.diagnosis.evidence.join(" ")).toMatch(/HTTP 403/);
    expect(body.diagnosis.evidence.join(" ")).toMatch(/Cloudflare/);
    expect(body.http.edge.labels).toContain("Cloudflare");
  });

  it("diagnoses a filtered host when nothing answers and no ports are open", async () => {
    vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      const method = init?.method ?? "GET";
      if (url.includes("cloudflare-dns.com")) {
        const type = new URL(url).searchParams.get("type");
        if (type === "TXT") return Response.json({ Answer: [{ type: 16, data: '"64500 | 203.0.113.0/24 | US | arin | 2010-01-01"' }] });
        return Response.json({ Answer: [{ type: type === "A" ? 1 : 28, data: type === "A" ? "203.0.114.9" : "2606:4700::9" }] });
      }
      if (url.includes("rdap.org")) return Response.json({});
      if (method === "HEAD") throw new DOMException("timed out", "TimeoutError");
      throw new Error(`Unexpected: ${url}`);
    });
    socketState.mode = "throw";

    const response = await requestLookup({});
    const body = await response.json() as any;
    expect(body.diagnosis.category).toBe("filtered_or_offline");
    expect(body.diagnosis.summary).toMatch(/firewall or blocklist/i);
  });

  it("reports a healthy site as reachable", async () => {
    installProviderMocks();
    const response = await requestLookup({});
    const body = await response.json() as any;
    expect(body.diagnosis.category).toBe("reachable");
    expect(body.diagnosis.severity).toBe("ok");
  });

  it("rate-limits a single client after 30 lookups in the window", async () => {
    installProviderMocks();
    const statuses: number[] = [];
    for (let attempt = 0; attempt < 31; attempt += 1) {
      const response = await requestLookup({}, "8.8.8.8", "198.51.100.7");
      statuses.push(response.status);
    }
    expect(statuses.slice(0, 30).every((status) => status === 200)).toBe(true);
    expect(statuses[30]).toBe(429);
  });

  it("allows CORS only for an allowlisted origin and answers preflight", async () => {
    installProviderMocks();
    const origin = "https://enendugodwin.github.io";
    const env = { ALLOWED_ORIGIN: origin };
    const assets = { ASSETS: { fetch: async () => new Response("asset") } };

    const post = (requestOrigin: string, ip: string) =>
      worker.fetch(
        new Request("https://lookup.test/api/lookup", {
          method: "POST",
          headers: { "Content-Type": "application/json", "CF-Connecting-IP": ip, Origin: requestOrigin },
          body: JSON.stringify({ target: "8.8.8.8" }),
        }),
        { ...assets, ...env } as never,
      );

    const allowed = await post(origin, "9.9.9.201");
    expect(allowed.headers.get("Access-Control-Allow-Origin")).toBe(origin);
    expect(allowed.headers.get("Vary")).toBe("Origin");

    const denied = await post("https://evil.example", "9.9.9.202");
    expect(denied.headers.get("Access-Control-Allow-Origin")).toBeNull();

    const preflight = await worker.fetch(
      new Request("https://lookup.test/api/lookup", { method: "OPTIONS", headers: { Origin: origin, "Access-Control-Request-Method": "POST" } }),
      { ...assets, ...env } as never,
    );
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("Access-Control-Allow-Origin")).toBe(origin);
    expect(preflight.headers.get("Access-Control-Allow-Methods")).toContain("POST");
  });

  it("marks TCP inconclusive when HTTP succeeded but every raw connect was refused", async () => {
    installProviderMocks();
    socketState.mode = "throw";
    const response = await requestLookup({});
    const body = await response.json() as any;
    expect(body.http.status).toBe("complete");
    expect(body.tcp.status).toBe("inconclusive");
    expect(body.tcp.reason).toMatch(/unavailable rather than closed/i);
    expect(body.diagnosis.evidence.join(" ")).toMatch(/not measurable/i);
  });

  describe("response body capture", () => {    function stubFetch(handler: (url: string, method: string) => Response) {
      const calls: Array<{ url: string; method: string }> = [];
      vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
        const url = input instanceof Request ? input.url : String(input);
        const method = init?.method ?? (input instanceof Request ? input.method : "GET");
        calls.push({ url, method });
        if (url.includes("cloudflare-dns.com")) {
          const type = new URL(url).searchParams.get("type");
          if (type === "TXT") return Response.json({ Answer: [{ type: 16, data: '"13335 | 104.20.0.0/16 | US | arin | 2014-03-28"' }] });
          return Response.json({ Answer: [{ type: type === "A" ? 1 : 28, data: type === "A" ? "104.20.23.154" : "2606:4700::1" }] });
        }
        if (url.includes("rdap.org")) return Response.json({});
        return handler(url, method);
      });
      return calls;
    }

    async function lookup(captureBody: boolean) {
      const request = new Request("https://lookup.test/api/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json", "CF-Connecting-IP": `9.9.9.${captureBody ? 211 : 212}` },
        body: JSON.stringify({ target: "blocked.example", captureBody }),
      });
      return worker.fetch(request, { ASSETS: { fetch: async () => new Response("asset") } } as never);
    }

    it("uses HEAD and captures nothing by default", async () => {
      const calls = stubFetch(() => new Response(null, { status: 200, headers: { server: "fixture" } }));
      const body = await (await lookup(false)).json() as any;
      expect(calls.filter((call) => call.method === "HEAD")).toHaveLength(1);
      expect(calls.some((call) => call.method === "GET" && call.url.startsWith("https://blocked.example"))).toBe(false);
      expect(body.http.body).toBeNull();
    });

    it("uses GET and surfaces the title and challenge markers when asked", async () => {
      const html = "<html><head><title>  Just a moment...  </title></head><body><div id=\"cf-chl\">Enable JavaScript and cookies to continue</div></body></html>";
      const calls = stubFetch(() => new Response(html, {
        status: 403,
        headers: { "content-type": "text/html; charset=utf-8", server: "cloudflare", "cf-ray": "abc-LHR" },
      }));

      const body = await (await lookup(true)).json() as any;
      expect(calls.filter((call) => call.method === "GET" && call.url.startsWith("https://blocked.example"))).toHaveLength(1);
      expect(body.http.body.contentType).toMatch(/text\/html/);
      expect(body.http.body.textual).toBe(true);
      expect(body.http.body.title).toBe("Just a moment...");
      expect(body.http.body.markers).toContain("Cloudflare challenge");
      expect(body.http.body.bytesRead).toBeGreaterThan(0);
      expect(body.http.body.truncated).toBe(false);
      expect(body.http.source.name).toMatch(/GET/);
      // The page evidence feeds the diagnosis.
      expect(body.diagnosis.category).toBe("waf_block");
      expect(body.diagnosis.evidence.join(" ")).toMatch(/page: Cloudflare challenge/);
    });

    it("marks a body larger than the cap as truncated", async () => {
      const huge = "x".repeat(40_000);
      stubFetch(() => new Response(huge, { status: 200, headers: { "content-type": "text/plain" } }));
      const body = await (await lookup(true)).json() as any;
      expect(body.http.body.bytesRead).toBe(16_384);
      expect(body.http.body.truncated).toBe(true);
    });

    it("does not decode binary bodies as text", async () => {
      stubFetch(() => new Response(new Uint8Array([0x89, 0x50, 0x4e, 0x47]), { status: 200, headers: { "content-type": "image/png" } }));
      const body = await (await lookup(true)).json() as any;
      expect(body.http.body.textual).toBe(false);
      expect(body.http.body.text).toBeNull();
      expect(body.http.body.title).toBeNull();
    });
  });
});
