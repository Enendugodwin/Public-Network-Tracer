import ipaddr from "ipaddr.js";
import { connect } from "cloudflare:sockets";

interface Env {
  ASSETS: Fetcher;
  EXTRA_PORTS?: string;
  ALLOWED_ORIGIN?: string;
  SHODAN_API_KEY?: string;
}

type NormalizedTarget = {
  kind: "ip" | "domain";
  host: string;
  url: URL;
  ip?: string;
};

type SourceCitation = {
  name: string;
  url: string;
  collectedAt: string;
  publishedAt: string | null;
  contentSha256: string | null;
  confidence: number;
};

const MAX_BODY_BYTES = 8_192;
const MAX_UPSTREAM_BYTES = 512_000;
const MAX_REDIRECTS = 4;
const MAX_LOOKUPS_PER_MINUTE = 12;
const REQUEST_TIMEOUT_MS = 5_000;
const RATE_WINDOW_MS = 60_000;
const rateWindows = new Map<string, { start: number; count: number }>();
const PRIVATE_SUFFIXES = [".localhost", ".local", ".internal", ".test", ".invalid"];
const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);
const USER_AGENT = "signal-internet-lookup/0.1 (+https://github.com/)";
const DEFAULT_PROBE_PORTS = [80, 443];
const MAX_PROBE_PORTS = 16;
const TCP_TIMEOUT_MS = 1_500;

class LookupError extends Error {
  constructor(
    message: string,
    readonly status = 400,
  ) {
    super(message);
  }
}

function json(data: unknown, status = 200): Response {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    },
  });
}

/**
 * CORS for the dashboard when it is hosted separately (e.g. GitHub Pages).
 * Locked to an explicit origin allowlist — never a wildcard.
 */
function corsHeaders(request: Request, env: Pick<Env, "ALLOWED_ORIGIN">): Record<string, string> {
  const origin = request.headers.get("Origin");
  if (!origin) return {};
  const allowed = (env.ALLOWED_ORIGIN ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
  if (!allowed.includes(origin)) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "600",
    Vary: "Origin",
  };
}

function withCors(response: Response, cors: Record<string, string>): Response {
  if (!Object.keys(cors).length) return response;
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(cors)) headers.set(name, value);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

type FailureCode =
  | "DNS_NO_RECORDS"
  | "DNS_PRIVATE"
  | "DNS_FAILURE"
  | "PRIVATE_ADDRESS"
  | "REDIRECT_UNSUPPORTED"
  | "REDIRECT_LIMIT"
  | "CONNECT_TIMEOUT"
  | "TLS_ERROR"
  | "CONNECTION_REFUSED"
  | "NETWORK_ERROR"
  | "NO_RESPONSE";

const FAILURE_REASONS: Record<FailureCode, string> = {
  DNS_NO_RECORDS: "The hostname did not resolve to a public address.",
  DNS_PRIVATE: "The hostname resolved to a private or reserved address.",
  DNS_FAILURE: "DNS resolution failed.",
  PRIVATE_ADDRESS: "The target resolves to a private or reserved address.",
  REDIRECT_UNSUPPORTED: "A redirect pointed at an unsupported or unsafe destination.",
  REDIRECT_LIMIT: "The redirect limit was reached.",
  CONNECT_TIMEOUT: "The target did not respond before the timeout.",
  TLS_ERROR: "The TLS handshake failed.",
  CONNECTION_REFUSED: "The target refused the connection.",
  NETWORK_ERROR: "The connection could not be established.",
  NO_RESPONSE: "The target did not return an HTTP response.",
};

function failure(code: FailureCode, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { status: "error", code, reason: FAILURE_REASONS[code], ...extra };
}

function blocked(code: FailureCode, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { status: "blocked", code, reason: FAILURE_REASONS[code], ...extra };
}

function classifyFetchError(error: unknown): FailureCode {  const name = error instanceof Error ? error.name.toLowerCase() : "";
  const message = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
  if (name.includes("timeout") || message.includes("timeout") || message.includes("aborted")) return "CONNECT_TIMEOUT";
  if (message.includes("certificate") || message.includes("tls") || message.includes("ssl")) return "TLS_ERROR";
  if (message.includes("refused")) return "CONNECTION_REFUSED";
  if (message.includes("dns") || message.includes("resolve") || message.includes("enotfound") || message.includes("getaddrinfo")) return "DNS_FAILURE";
  return "NETWORK_ERROR";
}

const EDGE_SIGNATURES: Array<{ label: string; header?: string; server?: string }> = [
  { label: "Cloudflare", header: "cf-ray" },
  { label: "Cloudflare", header: "cf-mitigated" },
  { label: "Cloudflare", server: "cloudflare" },
  { label: "Sucuri", header: "x-sucuri-id" },
  { label: "Akamai", header: "x-akamai-transformed" },
  { label: "Imperva", header: "x-iinfo" },
  { label: "AWS WAF", header: "x-amzn-waf-action" },
  { label: "AWS", server: "awselb" },
  { label: "Azure Front Door", header: "x-azure-ref" },
  { label: "Fastly", header: "x-fastly-request-id" },
  { label: "Vercel", header: "x-vercel-id" },
  { label: "F5 BIG-IP", server: "bigip" },
];

function detectEdge(headers: Headers): { labels: string[] } {
  const server = (headers.get("server") ?? "").toLowerCase();
  const labels = EDGE_SIGNATURES
    .filter((signature) => (signature.header ? headers.has(signature.header) : false) || (signature.server ? server.includes(signature.server) : false))
    .map((signature) => signature.label);
  return { labels: [...new Set(labels)] };
}

const CACHE_TTL_MS = 120_000;
const CACHE_MAX_ENTRIES = 500;
const microCache = new Map<string, { expiresAt: number; value: Promise<unknown> }>();

/** Test hook: drop the in-isolate cache so cases do not leak into each other. */
export function resetLookupCache(): void {
  microCache.clear();
}

/**
 * Short-lived, per-isolate cache. Not storage: it is lost with the isolate and
 * only spares repeat lookups of the same target from re-hitting public APIs.
 */
function cached<T>(key: string, load: () => Promise<T>): Promise<T> {
  const now = Date.now();
  const hit = microCache.get(key);
  if (hit && hit.expiresAt > now) return hit.value as Promise<T>;

  const promise = load();
  microCache.set(key, { expiresAt: now + CACHE_TTL_MS, value: promise as Promise<unknown> });
  promise.catch(() => {
    if (microCache.get(key)?.value === (promise as Promise<unknown>)) microCache.delete(key);
  });

  if (microCache.size > CACHE_MAX_ENTRIES) {
    for (const [entryKey, entry] of microCache) {
      if (entry.expiresAt <= now) microCache.delete(entryKey);
    }
  }
  return promise;
}

function blockedAddress(value: string): boolean {
  try {
    const address = ipaddr.process(value);
    return address.range() !== "unicast";
  } catch {
    return true;
  }
}

function validateDomain(host: string): string {
  const normalized = host.toLowerCase().replace(/\.$/, "");
  if (
    normalized.length > 253 ||
    normalized === "localhost" ||
    PRIVATE_SUFFIXES.some((suffix) => normalized.endsWith(suffix)) ||
    !normalized.includes(".") ||
    normalized.split(".").some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
  ) {
    throw new LookupError("Enter a public IP address, domain, or HTTP(S) URL.");
  }
  return normalized;
}

export function normalizeTarget(input: string): NormalizedTarget {
  const raw = input.trim();
  if (!raw || raw.length > 2_048 || /[\u0000-\u001f\u007f]/.test(raw)) {
    throw new LookupError("Enter a target up to 2,048 characters long.");
  }

  let url: URL;
  const bareIp = ipaddr.isValid(raw);
  try {
    if (bareIp) {
      const ip = ipaddr.process(raw).toString();
      if (blockedAddress(ip)) throw new LookupError("Private or reserved IP addresses are not supported.");
      url = new URL(`https://${ip.includes(":") ? `[${ip}]` : ip}/`);
    } else {
      const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
      url = new URL(candidate);
    }
  } catch (error) {
    if (error instanceof LookupError) throw error;
    throw new LookupError("Enter a valid IP address, domain, or HTTP(S) URL.");
  }

  if (!new Set(["http:", "https:"]).has(url.protocol)) {
    throw new LookupError("Only HTTP and HTTPS targets are supported.");
  }
  if (url.username || url.password) throw new LookupError("URLs with embedded credentials are not accepted.");
  if (["token", "access_token", "api_key", "key", "password", "secret", "session"].some((key) => url.searchParams.has(key))) {
    throw new LookupError("URLs with credential-like query parameters are not accepted.");
  }
  if (url.port && !["80", "443"].includes(url.port)) {
    throw new LookupError("Only standard HTTP and HTTPS ports are supported.");
  }
  if ((url.protocol === "https:" && url.port === "80") || (url.protocol === "http:" && url.port === "443")) {
    throw new LookupError("The URL scheme and port do not match.");
  }
  url.hash = "";

  let ip: string | undefined;
  let host: string;
  try {
    ip = ipaddr.process(url.hostname.replace(/^\[|\]$/g, "")).toString();
    if (blockedAddress(ip)) throw new LookupError("Private or reserved IP addresses are not supported.");
    host = ip;
  } catch (error) {
    if (error instanceof LookupError) throw error;
    if (url.hostname.startsWith("[")) throw new LookupError("Enter a valid public IP address.");
    host = validateDomain(url.hostname);
  }

  return { kind: ip ? "ip" : "domain", host, url, ip };
}

function rateLimited(request: Request): boolean {
  const now = Date.now();
  const key = request.headers.get("CF-Connecting-IP") ?? "unknown-client";
  let window = rateWindows.get(key);
  if (!window || now - window.start >= RATE_WINDOW_MS) {
    window = { start: now, count: 0 };
    rateWindows.set(key, window);
  }
  window.count += 1;

  if (rateWindows.size > 2_000) {
    for (const [entry, value] of rateWindows) {
      if (now - value.start >= RATE_WINDOW_MS) rateWindows.delete(entry);
    }
  }
  return window.count > MAX_LOOKUPS_PER_MINUTE;
}

async function readBounded(stream: ReadableStream<Uint8Array> | null, maxBytes: number): Promise<Uint8Array> {
  if (!stream) return new Uint8Array();
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        throw new LookupError("The request or source response is too large.", 413);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

async function parseRequest(request: Request): Promise<{ target: NormalizedTarget }> {
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
    throw new LookupError("Send a JSON request.", 415);
  }
  const length = Number(request.headers.get("content-length") ?? 0);
  if (length > MAX_BODY_BYTES) throw new LookupError("The request is too large.", 413);
  const bytes = await readBounded(request.body, MAX_BODY_BYTES);
  let data: unknown;
  try {
    data = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new LookupError("The request body must be valid JSON.");
  }
  if (!data || typeof data !== "object" || typeof (data as { target?: unknown }).target !== "string") {
    throw new LookupError("Provide a target field containing an IP, domain, or URL.");
  }
  return { target: normalizeTarget((data as { target: string }).target) };
}

async function fetchJson(url: string, accept = "application/json"): Promise<unknown> {
  const response = await fetch(url, {
    headers: { Accept: accept, "User-Agent": USER_AGENT },
    redirect: "follow",
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error(`Public data source unavailable (${response.status})`);
  }
  const headerSize = Number(response.headers.get("content-length") ?? 0);
  if (headerSize > MAX_UPSTREAM_BYTES) {
    await response.body?.cancel();
    throw new Error("Public data source response too large");
  }
  const bytes = await readBounded(response.body, MAX_UPSTREAM_BYTES);
  return JSON.parse(new TextDecoder().decode(bytes));
}

function citation(name: string, url: string, confidence = 95): SourceCitation {
  return { name, url, collectedAt: new Date().toISOString(), publishedAt: null, contentSha256: null, confidence };
}

type DnsAnswer = { name?: string; type?: number; data?: string };

function dnsAnswers(domain: string, type: "A" | "AAAA"): Promise<{ records: string[]; blockedAnswer: boolean; source: SourceCitation }> {
  return cached(`dns:${type}:${domain}`, async () => {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`;
    const result = await fetchJson(url, "application/dns-json") as { Answer?: DnsAnswer[] };
    const answers = (result.Answer ?? [])
      .filter((answer) => answer.type === (type === "A" ? 1 : 28) && typeof answer.data === "string")
      .map((answer) => answer.data!)
      .filter((value) => ipaddr.isValid(value));
    return {
      records: answers.filter((value) => !blockedAddress(value)),
      blockedAnswer: answers.some(blockedAddress),
      source: citation("Cloudflare DNS over HTTPS", url),
    };
  });
}

function reverseIpForCymru(ip: string): string {
  const address = ipaddr.process(ip);
  if (address.kind() === "ipv4") return address.toString().split(".").reverse().join(".");
  const hex = (address as ipaddr.IPv6).toByteArray().map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return hex.split("").reverse().join(".");
}

function lookupAsn(ip: string): Promise<{ info: { asn: string; prefix: string; country: string; registry: string }; source: SourceCitation } | null> {
  return cached(`asn:${ip}`, async () => {
    const query = `${reverseIpForCymru(ip)}.origin.asn.cymru.com`;
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(query)}&type=TXT`;
    const result = await fetchJson(url, "application/dns-json") as { Answer?: DnsAnswer[] };
    const line = (result.Answer ?? []).find((answer) => answer.type === 16)?.data?.replace(/^"|"$/g, "");
    if (!line) return null;
    const [asn, prefix, country, registry] = line.split("|").map((part) => part.trim());
    const asnNumber = (asn ?? "").replace(/^AS/i, "");
    if (!/^\d+$/.test(asnNumber)) return null;
    return {
      info: { asn: `AS${asnNumber}`, prefix: prefix ?? "", country: country ?? "", registry: registry ?? "" },
      source: citation("Team Cymru ASN lookup via DNS", url),
    };
  });
}

function rdapName(data: any): string | null {
  const entity = data?.entities?.find((item: any) => (item.roles ?? []).some((role: string) => ["registrant", "registrar", "administrative", "technical"].includes(role)));
  const vcard = entity?.vcardArray?.[1];
  const org = vcard?.find((item: any[]) => item[0] === "org")?.[3];
  const name = vcard?.find((item: any[]) => item[0] === "fn")?.[3];
  return (Array.isArray(org) ? org.join(" ") : org) || name || data?.name || data?.handle || null;
}

function rdapForIp(ip: string): Promise<{ data: any; source: SourceCitation } | null> {
  return cached(`rdap:ip:${ip}`, async () => {
    const url = `https://rdap.org/ip/${encodeURIComponent(ip)}`;
    try {
      const data = await fetchJson(url) as any;
      return { data, source: citation("RDAP", url) };
    } catch {
      return null;
    }
  });
}

function rdapForAsn(asn: string): Promise<{ name: string | null; source: SourceCitation } | null> {
  return cached(`rdap:asn:${asn}`, async () => {
    const url = `https://rdap.org/autnum/${encodeURIComponent(asn.replace(/^AS/i, ""))}`;
    try {
      const data = await fetchJson(url) as any;
      return { name: rdapName(data), source: citation("RDAP", url) };
    } catch {
      return null;
    }
  });
}

function rdapForDomain(domain: string): Promise<{ registrar: string | null; nameservers: string[]; events: Record<string, string>; source: SourceCitation } | null> {
  return cached(`rdap:domain:${domain}`, async () => {
    const url = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
    try {
      const data = await fetchJson(url) as any;
      const registrarEntity = data?.entities?.find((item: any) => (item.roles ?? []).includes("registrar"));
      return {
        registrar: rdapName({ entities: registrarEntity ? [registrarEntity] : [] }),
        nameservers: (data?.nameservers ?? []).map((item: any) => item.ldhName).filter((name: unknown): name is string => typeof name === "string").slice(0, 12),
        events: Object.fromEntries((data?.events ?? [])
          .filter((item: any) => typeof item?.eventAction === "string" && typeof item?.eventDate === "string")
          .map((item: any) => [item.eventAction, item.eventDate])
          .slice(0, 8)),
        source: citation("RDAP", url),
      };
    } catch {
      return null;
    }
  });
}

function shodanForIp(ip: string, apiKey?: string): Promise<{
  ports: number[];
  services: string[];
  certificates: Array<{ sha256: string; subject: string | null; issuer: string | null; expiresAt: string | null }>;
  organization: string | null;
  os: string | null;
  source: SourceCitation;
} | null> {
  if (!apiKey) return Promise.resolve(null);
  return cached(`shodan:${ip}`, async () => {
    const url = `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(apiKey)}`;
    try {
      const data = await fetchJson(url) as any;
      const ports: number[] = Array.isArray(data?.ports)
        ? data.ports.filter((port: unknown): port is number => typeof port === "number" && Number.isInteger(port) && port > 0 && port < 65536)
        : [];
      const records: any[] = Array.isArray(data?.data) ? data.data.slice(0, 128) : [];
      const services = [...new Set(records.map((record) => {
        const port = Number.isInteger(record?.port) ? `:${record.port}` : "";
        const protocol = typeof record?.transport === "string" ? `/${record.transport}` : "";
        const product = typeof record?.product === "string" ? record.product.slice(0, 80) : "";
        const version = typeof record?.version === "string" ? record.version.slice(0, 40) : "";
        return [port + protocol, product, version].filter(Boolean).join(" ");
      }).filter(Boolean))].slice(0, 40);
      const certificates = records.flatMap((record) => {
        const cert = record?.ssl?.cert;
        const fingerprint = typeof cert?.fingerprint?.sha256 === "string" ? cert.fingerprint.sha256.replace(/:/g, "").toLowerCase() : "";
        if (!/^[0-9a-f]{64}$/.test(fingerprint)) return [];
        const commonName = (value: unknown) => {
          if (typeof value === "string") return value.slice(0, 160);
          if (Array.isArray(value)) return value.filter((item) => typeof item === "string").join(", ").slice(0, 160) || null;
          return null;
        };
        return [{
          sha256: fingerprint,
          subject: commonName(cert?.subject?.CN),
          issuer: commonName(cert?.issuer?.CN),
          expiresAt: typeof cert?.expires === "string" ? cert.expires.slice(0, 40) : null,
        }];
      }).slice(0, 12);
      return {
        ports: [...new Set(ports)].slice(0, 64),
        services,
        certificates,
        organization: typeof data?.org === "string" ? data.org.slice(0, 160) : null,
        os: typeof data?.os === "string" ? data.os.slice(0, 100) : null,
        source: citation("Shodan Host API", `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}`, 90),
      };
    } catch {
      return null;
    }
  });
}

function allowedByCidr(ip: string, cidrs: string | undefined): boolean {
  const address = ipaddr.process(ip);
  return (cidrs ?? "").split(",").map((entry) => entry.trim()).filter(Boolean).some((range) => {
    try {
      return address.match(ipaddr.parseCIDR(range));
    } catch {
      return false;
    }
  });
}

function safeRedirectUrl(location: string, current: URL): URL | null {
  try {
    const next = new URL(location, current);
    if (!new Set(["http:", "https:"]).has(next.protocol) || next.username || next.password) return null;
    if (next.port && !["80", "443"].includes(next.port)) return null;
    next.hash = "";
    const host = next.hostname.replace(/^\[|\]$/g, "");
    if (ipaddr.isValid(host)) {
      if (blockedAddress(host)) return null;
    } else {
      validateDomain(host);
    }
    return next;
  } catch {
    return null;
  }
}

async function probeHttp(initial: NormalizedTarget): Promise<Record<string, unknown>> {
  let current = new URL(initial.url);
  const redirects: string[] = [];
  let startedAt: number | null = null;
  for (let step = 0; step <= MAX_REDIRECTS; step += 1) {
    const ip = ipaddr.isValid(current.hostname.replace(/^\[|\]$/g, ""))
      ? ipaddr.process(current.hostname.replace(/^\[|\]$/g, "")).toString()
      : undefined;
    if (ip && blockedAddress(ip)) return blocked("PRIVATE_ADDRESS", { redirects });
    if (!ip) {
      try {
        const [a, aaaa] = await Promise.all([dnsAnswers(current.hostname, "A"), dnsAnswers(current.hostname, "AAAA")]);
        if (a.blockedAnswer || aaaa.blockedAnswer) return blocked("DNS_PRIVATE", { redirects });
        if (![...a.records, ...aaaa.records].length) return failure("DNS_NO_RECORDS", { redirects });
      } catch {
        return failure("DNS_FAILURE", { redirects });
      }
    }

    try {
      startedAt ??= Date.now();
      const response = await fetch(current, {
        method: "HEAD",
        redirect: "manual",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (REDIRECT_CODES.has(response.status)) {
        const location = response.headers.get("location");
        await response.body?.cancel();
        if (!location) break;
        if (step === MAX_REDIRECTS) return failure("REDIRECT_LIMIT", { redirects });
        const next = safeRedirectUrl(location, current);
        if (!next) return failure("REDIRECT_UNSUPPORTED", { redirects });
        redirects.push(next.origin);
        current = next;
        continue;
      }
      await response.body?.cancel();
      return {
        status: "complete",
        statusCode: response.status,
        statusText: response.statusText,
        responseTimeMs: Date.now() - startedAt,
        contentLength: parseContentLength(response.headers.get("content-length")),
        server: response.headers.get("server")?.slice(0, 120) ?? null,
        edge: detectEdge(response.headers),
        headers: Object.fromEntries(["content-type", "cache-control", "last-modified", "strict-transport-security", "x-content-type-options", "x-frame-options", "cf-mitigated", "x-amzn-waf-action", "x-sucuri-id", "retry-after", "via", "x-cache"]
          .map((name) => [name, response.headers.get(name)?.slice(0, 240) ?? null])
          .filter((entry): entry is [string, string] => entry[1] !== null)),
        tls: current.protocol === "https:" ? { enabled: true, version: null } : { enabled: false, version: null },
        redirected: redirects.length > 0,
        redirects,
        checkedAt: new Date().toISOString(),
        source: citation("Live HTTP HEAD check", current.origin, 100),
      };
    } catch (error) {
      return failure(classifyFetchError(error), { redirects, responseTimeMs: startedAt === null ? null : Date.now() - startedAt });
    }
  }
  return failure("NO_RESPONSE", { redirects });
}

function parseContentLength(value: string | null): number | null {
  if (!value || !/^\d+$/.test(value)) return null;
  const length = Number(value);
  return Number.isSafeInteger(length) ? length : null;
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function clientPublicIp(request: Request): string | null {
  const value = request.headers.get("CF-Connecting-IP")?.trim();
  if (!value || !ipaddr.isValid(value)) return null;
  const address = ipaddr.process(value).toString();
  return blockedAddress(address) ? null : address;
}

function probePorts(env: Pick<Env, "EXTRA_PORTS">): number[] {
  const extra = (env.EXTRA_PORTS ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map(Number)
    .filter((port) => Number.isInteger(port) && port > 0 && port < 65_536);
  return [...new Set([...DEFAULT_PROBE_PORTS, ...extra])].slice(0, MAX_PROBE_PORTS);
}

type TcpCheck = { port: number; reachable: boolean; responseTimeMs: number | null; code: FailureCode | null; detail: string };

async function probeTcpPort(host: string, port: number): Promise<TcpCheck> {
  const started = Date.now();
  let socket: ReturnType<typeof connect> | undefined;
  try {
    socket = connect({ hostname: host, port });
    const outcome = await Promise.race([
      socket.opened.then(() => "open" as const),
      sleep(TCP_TIMEOUT_MS).then(() => "timeout" as const),
    ]);
    if (outcome === "timeout") {
      return { port, reachable: false, responseTimeMs: null, code: "CONNECT_TIMEOUT", detail: "No TCP handshake before the timeout." };
    }
    return { port, reachable: true, responseTimeMs: Date.now() - started, code: null, detail: "TCP handshake completed." };
  } catch (error) {
    const code = classifyFetchError(error);
    return {
      port,
      reachable: false,
      responseTimeMs: null,
      code: code === "TLS_ERROR" || code === "CONNECT_TIMEOUT" ? code : "CONNECTION_REFUSED",
      detail: "The port refused or dropped the connection.",
    };
  } finally {
    // Never await close on a socket that never opened: a filtered port can make
    // close() wait for the OS connect timeout and stall the whole lookup.
    socket?.close().catch(() => {});
  }
}

async function probeTcp(target: NormalizedTarget, env: Env, ip: string | undefined): Promise<Record<string, unknown>> {
  const host = ip ?? target.host;
  if (blockedAddress(host)) return blocked("PRIVATE_ADDRESS", { checks: [] });
  const ports = probePorts(env);
  const checks = await Promise.all(ports.map((port) => probeTcpPort(host, port)));
  return { status: "complete", host, ports, checks, checkedAt: new Date().toISOString() };
}

type DnsResolution = {
  ip: string | undefined;
  dns: Record<string, string[]>;
  privateDnsAnswersFiltered: boolean;
  sources: SourceCitation[];
};

async function resolveTarget(target: NormalizedTarget): Promise<DnsResolution> {
  if (target.kind !== "domain") {
    return { ip: target.ip, dns: {}, privateDnsAnswersFiltered: false, sources: [] };
  }
  const types = ["A", "AAAA"] as const;
  const dns: Record<string, string[]> = {};
  const sources: SourceCitation[] = [];
  let privateDnsAnswersFiltered = false;

  const results = await Promise.allSettled(types.map((type) => dnsAnswers(target.host, type)));
  results.forEach((result, index) => {
    if (result.status === "fulfilled") {
      dns[types[index]] = result.value.records;
      privateDnsAnswersFiltered ||= result.value.blockedAnswer;
      sources.push(result.value.source);
    }
  });
  return { ip: dns.A?.[0] ?? dns.AAAA?.[0], dns, privateDnsAnswersFiltered, sources };
}

type Enrichment = {
  sources: SourceCitation[];
  asnInfo: { asn: string; prefix: string; country: string; registry: string } | null;
  asnOrganization: string | null;
  ipRdap: { data: any; source: SourceCitation } | null;
  shodan: Awaited<ReturnType<typeof shodanForIp>>;
  domainRdap: Awaited<ReturnType<typeof rdapForDomain>>;
};

async function enrichTarget(target: NormalizedTarget, ip: string | undefined, env: Env): Promise<Enrichment> {
  const asnLookup = ip ? lookupAsn(ip).catch(() => null) : Promise.resolve(null);
  const [ipRdap, asnResult, asnRdap, shodan, domainRdap] = await Promise.all([
    ip ? rdapForIp(ip) : Promise.resolve(null),
    asnLookup,
    asnLookup.then((result) => (result ? rdapForAsn(result.info.asn).catch(() => null) : null)),
    ip ? shodanForIp(ip, env.SHODAN_API_KEY) : Promise.resolve(null),
    target.kind === "domain" ? rdapForDomain(target.host) : Promise.resolve(null),
  ]);

  const sources: SourceCitation[] = [];
  if (ipRdap) sources.push(ipRdap.source);
  if (asnResult) sources.push(asnResult.source);
  if (asnRdap) sources.push(asnRdap.source);
  if (shodan) sources.push(shodan.source);
  if (domainRdap) sources.push(domainRdap.source);

  return {
    sources,
    asnInfo: asnResult?.info ?? null,
    asnOrganization: asnRdap?.name ?? null,
    ipRdap,
    shodan,
    domainRdap,
  };
}

type Diagnosis = { category: string; severity: "ok" | "warn" | "bad"; title: string; summary: string; evidence: string[] };

const BLOCKING_STATUS = new Set([403, 406, 429, 451, 503]);

function summarizeTcp(tcp: any): string | null {
  const checks: any[] = tcp?.checks ?? [];
  if (!checks.length) return null;
  const open = checks.filter((check) => check.reachable).map((check) => `:${check.port}`);
  return open.length ? `open ports: ${open.join(", ")}` : "no web ports open";
}

function diagnose(http: any, tcp: any): Diagnosis {
  const evidence: string[] = [];
  const tcpSummary = summarizeTcp(tcp);
  if (tcpSummary) evidence.push(tcpSummary);
  const edgeLabels: string[] = http?.edge?.labels ?? [];
  const edgeEvidence = edgeLabels.map((label) => `edge: ${label}`);

  if (http?.status === "complete") {
    const code: number = http.statusCode;
    const base = [`HTTP ${code}`, ...evidence];

    if (BLOCKING_STATUS.has(code) && edgeLabels.length) {
      return {
        category: "waf_block",
        severity: "warn",
        title: "Blocked at the edge / WAF",
        summary: "The site is reachable, but an edge or WAF layer refused the request. This is a deliberate block or bot rule, not a network fault.",
        evidence: [...base, ...edgeEvidence],
      };
    }
    if (BLOCKING_STATUS.has(code)) {
      return {
        category: "blocked_response",
        severity: "warn",
        title: "Request rejected by the server",
        summary: `The origin answered ${code}. Reachability is fine; the server declined the request (rate limit, bot rule, or access policy).`,
        evidence: base,
      };
    }
    if (code === 401) {
      return { category: "auth_required", severity: "warn", title: "Authentication required", summary: "The site is reachable but requires credentials (401).", evidence: base };
    }
    if (code >= 500) {
      return {
        category: "origin_error",
        severity: "bad",
        title: "Origin server error",
        summary: `The site is reachable, but the origin returned ${code}. The destination is up; its application is failing.`,
        evidence: base,
      };
    }
    if (code >= 400) {
      return { category: "client_rejected", severity: "warn", title: "Request rejected", summary: `The origin answered ${code}.`, evidence: base };
    }
    return {
      category: "reachable",
      severity: "ok",
      title: "Reachable",
      summary: `The site answered ${code} from the checker's network.`,
      evidence: [...base, ...edgeEvidence],
    };
  }

  switch (http?.code) {
    case "DNS_NO_RECORDS":
      return {
        category: "dns",
        severity: "bad",
        title: "Name does not resolve",
        summary: "DNS returned no public address for this name. Check the spelling, the domain's DNS records, or whether it is internal-only.",
        evidence,
      };
    case "DNS_PRIVATE":
    case "PRIVATE_ADDRESS":
      return {
        category: "policy",
        severity: "warn",
        title: "Private or reserved address",
        summary: "The name resolves to a private or reserved address, so it is not reachable from the public internet.",
        evidence,
      };
    case "DNS_FAILURE":
      return { category: "dns", severity: "bad", title: "DNS lookup failed", summary: "The resolver could not complete the lookup for this name.", evidence };
    case "CONNECT_TIMEOUT": {
      const anyOpen = (tcp?.checks ?? []).some((check: any) => check.reachable);
      return anyOpen
        ? {
            category: "http_layer_timeout",
            severity: "bad",
            title: "Ports open, HTTP timed out",
            summary: "TCP connected, but the HTTP request got no response in time. That points at the application, a proxy, or a load balancer rather than the network path.",
            evidence,
          }
        : {
            category: "filtered_or_offline",
            severity: "bad",
            title: "No response: filtered or offline",
            summary: "Nothing answered on the web ports. The host may be offline, or a firewall or blocklist is silently dropping the traffic. A timeout (not a refusal) is the signature of a drop.",
            evidence,
          };
    }
    case "CONNECTION_REFUSED":
      return {
        category: "refused",
        severity: "bad",
        title: "Destination not available",
        summary: "The network path works, but nothing is listening on the port. The service is down or the port is closed.",
        evidence,
      };
    case "TLS_ERROR":
      return {
        category: "tls",
        severity: "bad",
        title: "TLS handshake failed",
        summary: "TCP connected, but TLS failed: expired or mismatched certificate, wrong SNI, or an intercepting proxy.",
        evidence,
      };
    case "REDIRECT_LIMIT":
    case "REDIRECT_UNSUPPORTED":
      return { category: "redirect", severity: "bad", title: "Redirect problem", summary: "The site redirected in a loop, or to an unsupported or unsafe destination.", evidence };
    case "NO_RESPONSE":
    case "NETWORK_ERROR":
    default:
      return { category: "network", severity: "bad", title: "Unreachable", summary: "The connection could not be established from the checker's network.", evidence };
  }
}

async function doLookup(target: NormalizedTarget, env: Env, sourceIp: string | null): Promise<Record<string, unknown>> {
  // Overlap the independent work: HTTP does not need DNS, and TCP/enrichment
  // start as soon as the address is known rather than after the other stages.
  const resolution = resolveTarget(target);
  const httpPromise = probeHttp(target);
  const tcpPromise = resolution.then((r) => probeTcp(target, env, r.ip));
  const enrichmentPromise = resolution.then((r) => enrichTarget(target, r.ip, env));

  const [resolved, http, tcp, enrichment] = await Promise.all([resolution, httpPromise, tcpPromise, enrichmentPromise]);

  const sources: SourceCitation[] = [...resolved.sources, ...enrichment.sources];
  if (http.status === "complete" && http.source) sources.push(http.source as SourceCitation);

  const { ip, dns, privateDnsAnswersFiltered } = resolved;
  const { asnInfo, asnOrganization, ipRdap, shodan, domainRdap } = enrichment;
  const organization = asnOrganization ?? shodan?.organization ?? rdapName(ipRdap?.data) ?? null;
  const country = asnInfo?.country || ipRdap?.data?.country || null;

  return {
    target: { kind: target.kind, host: target.host, url: target.url.origin + target.url.pathname },
    source: {
      observedIp: sourceIp,
      unavailableReason: sourceIp ? null : "Cloudflare sets CF-Connecting-IP at the edge. It is not present in local development (wrangler dev), so your public IP cannot be observed here.",
      label: "Your public IP, as observed by the checker",
      probeOrigin: "Live HTTP and TCP checks run from the checker's edge network, not from your IP.",
    },
    checkedAt: new Date().toISOString(),
    overview: {
      status: http.status === "complete" ? `${http.statusCode} ${http.statusText ?? ""}`.trim() : (http.code as string) ?? "—",
      reachable: http.status === "complete",
      ip: ip ?? null,
      asn: asnInfo?.asn ?? null,
      organization,
      country,
      responseTimeMs: (http.responseTimeMs as number | null) ?? null,
    },
    http,
    tcp,
    diagnosis: diagnose(http, tcp),
    network: {
      ip: ip ?? null,
      asn: asnInfo,
      organization,
      country,
      networkName: ipRdap?.data?.name ?? null,
      range: ipRdap?.data?.startAddress && ipRdap?.data?.endAddress ? `${ipRdap.data.startAddress} – ${ipRdap.data.endAddress}` : null,
      domain: domainRdap ? { registrar: domainRdap.registrar, nameservers: domainRdap.nameservers, events: domainRdap.events } : null,
      dns,
      privateDnsAnswersFiltered,
      observedPorts: shodan?.ports ?? null,
      services: shodan?.services ?? null,
      certificates: shodan?.certificates ?? null,
      portSourceAvailable: Boolean(env.SHODAN_API_KEY),
    },
    sources,
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") return json({ status: "ok", storage: "none" });
    if (url.pathname !== "/api/lookup") {
      const response = await env.ASSETS.fetch(request);
      const headers = new Headers(response.headers);
      headers.set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' https://www.cloudflare.com; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'");
      headers.set("Referrer-Policy", "no-referrer");
      headers.set("X-Content-Type-Options", "nosniff");
      return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
    }
    const cors = corsHeaders(request, env);
    const respond = (data: unknown, status = 200) => withCors(json(data, status), cors);

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (request.method !== "POST") return respond({ error: "Method not allowed." }, 405);
    if (rateLimited(request)) return respond({ error: "Lookup limit reached. Try again in a minute." }, 429);

    try {
      const { target } = await parseRequest(request);
      const result = await doLookup(target, env, clientPublicIp(request));
      return respond(result);
    } catch (error) {
      if (error instanceof LookupError) return respond({ error: error.message }, error.status);
      return respond({ error: "The lookup could not be completed." }, 502);
    }
  },
};
