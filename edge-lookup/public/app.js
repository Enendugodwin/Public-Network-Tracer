const form = document.querySelector("#lookupForm");
const input = document.querySelector("#targetInput");
const button = document.querySelector("#checkButton");
const status = document.querySelector("#formStatus");
const results = document.querySelector("#results");
const emptyState = document.querySelector("#emptyState");

/**
 * Where the API lives for this page load.
 *
 * Local development: the dev server answers /api/lookup itself, so always use
 * same-origin — otherwise the configured base (meant for the separately hosted
 * Pages copy) would send the browser cross-origin to a Worker that does not
 * allowlist localhost, and every lookup would look like a network failure.
 */
function apiBase() {
  const configured = String(window.TRACER_API_BASE ?? "").replace(/\/+$/, "");
  const host = location.hostname;
  const localDev = host === "localhost" || host === "127.0.0.1" || host === "::1" || host.endsWith(".local");
  return localDev ? "" : configured;
}
const HISTORY_KEY = "pit.history.v1";
const SHODAN_KEY_STORAGE = "pit.shodanKey.v1";
const SHODAN_KEY_PATTERN = /^[A-Za-z0-9]{16,64}$/;

/** Held in memory unless the user explicitly asks to remember it. */
let shodanKey = "";
const HISTORY_MAX = 8;
const PUBLIC_IP_ENDPOINT = "https://www.cloudflare.com/cdn-cgi/trace";

let lastResult = null;

/* ---------- small helpers ---------- */

function setText(selector, value, fallback = "—") {
  const node = document.querySelector(selector);
  if (node) node.textContent = value == null || value === "" ? fallback : String(value);
}

function clear(node) {
  if (node) node.replaceChildren();
}

function addTokens(container, values, emptyMessage = "") {
  if (!container) return;
  clear(container);
  const list = Array.isArray(values) ? values.filter((value) => value !== null && value !== undefined && value !== "") : [];
  if (!list.length) {
    if (!emptyMessage) return;
    const empty = document.createElement("span");
    empty.className = "muted";
    empty.textContent = emptyMessage;
    container.append(empty);
    return;
  }
  for (const value of list) {
    const token = document.createElement("span");
    token.className = "token";
    token.textContent = String(value);
    container.append(token);
  }
}

function formatBytes(value) {
  if (!Number.isFinite(value)) return "—";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function formatTime(value) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(parsed);
}

function detailRow(label, value, mono = false) {
  const row = document.createElement("div");
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  if (mono) dd.className = "mono";
  dd.textContent = value == null || value === "" ? "—" : String(value);
  row.append(dt, dd);
  return row;
}

/* ---------- public IP fallback (local dev only) ---------- */

async function detectBrowserPublicIp() {
  try {
    const response = await fetch(PUBLIC_IP_ENDPOINT, { cache: "no-store" });
    if (!response.ok) return null;
    const match = (await response.text()).match(/^ip=(.+)$/m);
    return match ? match[1].trim() : null;
  } catch {
    return null;
  }
}

/* ---------- optional Shodan key (bring your own) ---------- */

function readStoredShodanKey() {
  try {
    return localStorage.getItem(SHODAN_KEY_STORAGE) ?? "";
  } catch {
    return "";
  }
}

function storeShodanKey(value) {
  try {
    if (value) localStorage.setItem(SHODAN_KEY_STORAGE, value);
    else localStorage.removeItem(SHODAN_KEY_STORAGE);
  } catch {
    /* storage unavailable — the key still works for this page load */
  }
}

function refreshShodanUi(message = "") {
  const active = SHODAN_KEY_PATTERN.test(shodanKey);
  const badge = document.querySelector("#optionsBadge");
  if (badge) badge.hidden = !active;
  const input = document.querySelector("#shodanKey");
  if (input) input.value = shodanKey;
  const status = document.querySelector("#shodanKeyStatus");
  if (status) status.textContent = message;
}

function saveShodanKey() {
  const input = document.querySelector("#shodanKey");
  const value = (input?.value ?? "").trim();
  if (!value) {
    shodanKey = "";
    storeShodanKey("");
    refreshShodanUi("Key cleared.");
    return;
  }
  if (!SHODAN_KEY_PATTERN.test(value)) {
    refreshShodanUi("That does not look like a Shodan key (expected 16–64 letters or digits).");
    return;
  }
  shodanKey = value;
  const remember = document.querySelector("#rememberShodanKey")?.checked === true;
  storeShodanKey(remember ? value : "");
  refreshShodanUi(remember ? "Saved in this browser." : "Set for this page only — not remembered.");
}

function initShodanKey() {
  const stored = readStoredShodanKey();
  if (stored && SHODAN_KEY_PATTERN.test(stored)) {
    shodanKey = stored;
    document.querySelector("#rememberShodanKey").checked = true;
  }
  refreshShodanUi();
}

/* ---------- history (browser only) ---------- */

function readHistory() {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.slice(0, HISTORY_MAX) : [];
  } catch {
    return [];
  }
}

function writeHistory(entries) {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(entries.slice(0, HISTORY_MAX)));
  } catch {
    /* storage unavailable (private mode) — history is optional */
  }
}

function renderHistory() {
  const block = document.querySelector("#historyBlock");
  const list = document.querySelector("#historyList");
  const entries = readHistory();
  block.hidden = entries.length === 0;
  clear(list);
  for (const entry of entries) {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "history-chip";
    const name = document.createElement("span");
    name.className = "mono";
    name.textContent = entry.target;
    const meta = document.createElement("span");
    meta.className = "history-meta";
    meta.textContent = [entry.grade ? `grade ${entry.grade}` : null, formatTime(entry.at)].filter(Boolean).join(" · ");
    chip.append(name, meta);
    chip.addEventListener("click", () => {
      input.value = entry.target;
      runLookup(entry.target);
    });
    list.append(chip);
  }
}

function rememberLookup(target, result) {
  const entries = readHistory().filter((entry) => entry.target !== target);
  entries.unshift({ target, at: new Date().toISOString(), grade: result?.posture?.grade ?? null, score: result?.posture?.score ?? null });
  writeHistory(entries);
  renderHistory();
}

/* ---------- renderers ---------- */

function renderRoute(source, destination) {
  const sourceNode = document.querySelector("#routeSource");
  setText("#routeDestination", destination);
  if (source?.observedIp) {
    sourceNode.textContent = source.observedIp;
    sourceNode.title = source.probeOrigin ?? "";
    return;
  }
  sourceNode.textContent = "resolving…";
  sourceNode.title = source?.unavailableReason ?? "";
  detectBrowserPublicIp().then((ip) => {
    sourceNode.textContent = ip ?? "unavailable";
    if (ip) sourceNode.title = "Detected by your browser (local development fallback).";
  });
}

function renderDiagnosis(diagnosis) {
  const block = document.querySelector("#diagnosis");
  if (!diagnosis) {
    block.hidden = true;
    return;
  }
  block.hidden = false;
  block.className = `diagnosis ${diagnosis.severity ?? ""}`.trim();
  setText("#diagnosisBadge", diagnosis.category, "result");
  setText("#diagnosisTitle", diagnosis.title);
  setText("#diagnosisSummary", diagnosis.summary);
  addTokens(document.querySelector("#diagnosisEvidence"), diagnosis.evidence);
}

function renderSummary(data) {
  const http = data.http ?? {};
  const overview = data.overview ?? {};
  const complete = http.status === "complete";
  setText("#sumStatus", complete ? `${http.statusCode} ${http.statusText ?? ""}`.trim() : (http.code ?? "Not run"));
  document.querySelector("#sumStatus").className = `summary-status ${overview.reachable ? "ok" : "bad"}`;
  setText("#sumNote", complete ? "reachable" : "not reachable", "");
  setText("#sumIp", overview.ip);
  setText("#sumAsn", overview.asn);
  setText("#sumOrg", overview.organization ?? "organization unavailable");
  setText("#sumTime", Number.isFinite(overview.responseTimeMs) ? `${overview.responseTimeMs} ms` : "—");
  setText("#sumTls", http.tls?.enabled === true ? "HTTPS" : http.tls ? "HTTP" : "—");
  setText("#sumPosture", data.posture ? `${data.posture.score}/100 (${data.posture.grade})` : "—");
  const dns = data.network?.dns ?? {};
  setText("#sumDns", `${(dns.A ?? []).length} A · ${(dns.AAAA ?? []).length} AAAA`);
}

function renderPosture(posture) {
  if (!posture) return;
  setText("#postureScore", posture.score);
  setText("#postureGrade", posture.grade);
  const bars = document.querySelector("#postureBars");
  clear(bars);
  for (const category of posture.categories ?? []) {
    const row = document.createElement("div");
    row.className = "posture-bar";
    const head = document.createElement("div");
    head.className = "posture-bar-head";
    const label = document.createElement("span");
    label.textContent = category.name;
    const score = document.createElement("span");
    score.className = "mono";
    score.textContent = `${category.score}/${category.max}`;
    head.append(label, score);
    const track = document.createElement("div");
    track.className = "posture-track";
    const fill = document.createElement("div");
    fill.className = "posture-fill";
    fill.style.width = `${Math.round((category.score / (category.max || 1)) * 100)}%`;
    track.append(fill);
    const note = document.createElement("span");
    note.className = "posture-note";
    note.textContent = category.note ?? "";
    row.append(head, track, note);
    bars.append(row);
  }
}

function renderFindings(findings) {
  const list = document.querySelector("#findingsList");
  clear(list);
  const items = findings ?? [];
  setText("#findingsCount", items.length ? `${items.length} item${items.length === 1 ? "" : "s"}` : "none");
  if (!items.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "No findings from the data observed.";
    list.append(empty);
    return;
  }
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  for (const finding of [...items].sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9))) {
    const card = document.createElement("article");
    card.className = `finding finding-${finding.severity}`;
    const head = document.createElement("div");
    head.className = "finding-head";
    const severity = document.createElement("span");
    severity.className = `severity severity-${finding.severity}`;
    severity.textContent = finding.severity.toUpperCase();
    const title = document.createElement("strong");
    title.textContent = finding.title;
    head.append(severity, title);
    const detail = document.createElement("p");
    detail.className = "finding-detail";
    detail.textContent = finding.detail;
    card.append(head, detail);

    const why = document.createElement("p");
    why.className = "finding-why";
    why.textContent = `Why it matters: ${finding.why}`;
    const rec = document.createElement("p");
    rec.className = "finding-rec";
    rec.textContent = `Recommendation: ${finding.recommendation}`;
    const ev = document.createElement("div");
    ev.className = "token-list finding-evidence";
    addTokens(ev, [...(finding.evidence ?? []), `source: ${finding.source}`]);
    card.append(why, rec, ev);
    list.append(card);
  }
}

function renderRedirects(http) {
  const chain = document.querySelector("#redirectChain");
  clear(chain);
  const hops = http.redirects ?? [];
  if (!hops.length) {
    const none = document.createElement("span");
    none.className = "muted";
    none.textContent = http.status === "complete" ? "No redirects" : "Not available";
    chain.append(none);
    return;
  }
  hops.forEach((hop, index) => {
    const row = document.createElement("div");
    row.className = "chain-hop";
    const code = document.createElement("span");
    code.className = "chain-code mono";
    code.textContent = String(hop.status);
    const url = document.createElement("span");
    url.className = "chain-url mono";
    url.textContent = hop.from;
    row.append(code, url);
    chain.append(row);
    const arrow = document.createElement("div");
    arrow.className = "chain-arrow";
    arrow.textContent = "↓";
    chain.append(arrow);
    if (index === hops.length - 1) {
      const finalRow = document.createElement("div");
      finalRow.className = "chain-hop";
      const finalCode = document.createElement("span");
      finalCode.className = "chain-code mono";
      finalCode.textContent = String(http.statusCode ?? "");
      const finalUrl = document.createElement("span");
      finalUrl.className = "chain-url mono";
      finalUrl.textContent = hop.to;
      finalRow.append(finalCode, finalUrl);
      chain.append(finalRow);
    }
  });
}

function renderBody(body) {
  const section = document.querySelector("#bodySection");
  section.hidden = !body;
  if (!body) return;
  setText("#bodyType", body.contentType, "unknown");
  const size = body.skipped ? "skipped (non-text content type)" : `${formatBytes(body.bytesRead)}${body.truncated ? " (truncated)" : ""}`;
  setText("#bodySize", size);
  setText("#bodyTitle", body.title, "—");
  addTokens(document.querySelector("#bodyMarkers"), body.markers);
  const pre = document.querySelector("#bodyText");
  const showText = body.textual && !body.skipped && typeof body.text === "string" && body.text.length > 0;
  pre.hidden = !showText;
  // textContent, never innerHTML: the remote page is data, not markup.
  pre.textContent = showText ? body.text : "";
}

function renderHttp(http) {
  const complete = http.status === "complete";
  const state = document.querySelector("#httpState");
  state.textContent = complete ? "Live" : (http.code ?? "Unavailable");
  state.className = `panel-state ${complete ? "live" : "off"}`;

  const notice = document.querySelector("#httpNotice");
  notice.hidden = complete;
  notice.textContent = complete ? "" : (http.reason ?? "The live HTTP check did not complete.");

  setText("#httpMethod", http.method, "—");
  setText("#httpStatus", complete ? `${http.statusCode} ${http.statusText ?? ""}`.trim() : (http.code ?? "Not run"));
  setText("#httpFinalUrl", http.finalUrl, "—");
  setText("#httpTime", Number.isFinite(http.responseTimeMs) ? `${http.responseTimeMs} ms` : "—");
  setText("#httpType", http.headerAnalysis?.application?.["content-type"], "—");
  setText("#httpLength", http.contentLength == null ? "—" : formatBytes(http.contentLength));
  setText("#httpEncoding", http.headerAnalysis?.application?.["content-encoding"], "none");
  setText("#httpServer", http.server, "not disclosed");

  renderRedirects(http);

  const security = http.headerAnalysis?.security;
  setText("#secHeaderScore", security ? `${security.score}/${security.max}` : "", "");
  addTokens(document.querySelector("#securityHeaders"), (security?.present ?? []).map((entry) => `${entry.label}: ${entry.value}`), "None present");
  const missing = document.querySelector("#missingHeaders");
  clear(missing);
  for (const entry of security?.missing ?? []) {
    const line = document.createElement("p");
    line.className = "missing-header";
    line.textContent = `Missing: ${entry.label} — ${entry.why}`;
    missing.append(line);
  }
  addTokens(document.querySelector("#cachingHeaders"), Object.entries(http.headerAnalysis?.caching ?? {}).map(([k, v]) => `${k}: ${v}`), "None observed");
  addTokens(document.querySelector("#appHeaders"), Object.entries(http.headerAnalysis?.application ?? {}).map(([k, v]) => `${k}: ${v}`), "None observed");
  renderBody(http.body);
}

function renderDns(network) {
  const list = document.querySelector("#dnsList");
  clear(list);
  const dns = network?.dns ?? {};
  const types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA"];
  let any = false;
  for (const type of types) {
    const values = dns[type] ?? [];
    if (!values.length) continue;
    any = true;
    list.append(detailRow(type, values.slice(0, 6).join("   "), type !== "TXT" && type !== "SOA"));
  }
  if (!any) list.append(detailRow("Records", "none returned"));
  const dnssec = dns.dnssec ?? [];
  const state = document.querySelector("#dnssecState");
  state.textContent = dnssec.length ? "DNSSEC AD" : "DNSSEC ?";
  state.className = `panel-state ${dnssec.length ? "live" : ""}`;
  setText("#dnsNote", dnssec.length ? "Resolver set the authenticated-data flag." : "No authenticated-data flag observed; this is not proof the zone is unsigned.", "");
}

function renderTls(data) {
  const tls = data.tls ?? {};
  const http = data.http ?? {};
  setText("#tlsEnabled", tls.enabled === true ? "Yes" : tls.enabled === false ? "No (plain HTTP)" : "Unknown");
  setText("#tlsVersion", "not exposed by the platform");
  setText("#tlsNote", tls.note ?? "", "");
  document.querySelector("#tlsEnabled").className = tls.enabled ? "ok-text" : "bad-text";
  void http;
  const certs = data.network?.certificates ?? [];
  const container = document.querySelector("#certificateRecords");
  clear(container);
  if (!certs.length) {
    const empty = document.createElement("span");
    empty.className = "muted";
    empty.textContent = "No passive certificate data (requires a Shodan key)";
    container.append(empty);
    return;
  }
  for (const cert of certs) {
    const token = document.createElement("span");
    token.className = "token";
    token.textContent = `${cert.subject ?? "certificate"} · ${cert.sha256.slice(0, 16)}…`;
    token.title = `Issuer: ${cert.issuer ?? "unknown"}; expires: ${cert.expiresAt ?? "unknown"}; SHA-256: ${cert.sha256}`;
    container.append(token);
  }
}

function renderNetwork(data, tcp) {
  const network = data.network ?? {};
  setText("#networkIp", network.ip);
  setText("#networkIpVersion", network.ipVersion);
  setText("#networkAsn", network.asn?.asn);
  setText("#networkOrg", network.organization);
  setText("#networkPrefix", network.prefix ?? network.asn?.prefix);
  setText("#networkCountry", network.country);
  setText("#networkName", network.networkName);
  setText("#networkRange", network.range);
  setText("#networkPtr", Array.isArray(network.reverseDns) ? network.reverseDns.join(", ") : network.reverseDns);
  setText("#networkHosting", network.hostingType);
  setText("#networkAbuse", network.abuseContact, "not published in RDAP");

  setText("#relTarget", data.target?.host);
  setText("#relIp", network.ip);
  setText("#relAsn", network.asn?.asn ?? (data.overview?.asn ?? "—"));
  setText("#relOrg", network.organization);

  const active = document.querySelector("#activePorts");
  clear(active);
  if (tcp?.status === "inconclusive") {
    const note = document.createElement("span");
    note.className = "muted";
    note.textContent = "not measurable from this vantage point";
    active.append(note);
  } else if (tcp?.status === "complete") {
    for (const check of tcp.checks ?? []) {
      const token = document.createElement("span");
      token.className = `token ${check.reachable ? "token-open" : "token-closed"}`;
      const timing = check.reachable && Number.isFinite(check.responseTimeMs) ? ` · ${check.responseTimeMs} ms` : "";
      const code = check.reachable ? "" : ` · ${check.code ?? "CLOSED"}`;
      token.textContent = `:${check.port} ${check.reachable ? "open" : "closed"}${timing}${code}`;
      token.title = check.code ? `${check.code} — ${check.detail}` : check.detail;
      active.append(token);
    }
  } else {
    const note = document.createElement("span");
    note.className = "muted";
    note.textContent = "no active checks run";
    active.append(note);
  }
  setText("#activePortNote", tcp?.reason ?? "TCP connect from the checker's edge network.", "");

  addTokens(document.querySelector("#passivePorts"), (network.observedPorts ?? []).map((port) => `:${port}`), "No passive dataset (requires a Shodan key)");
  const shodanSource = network.shodanSource;
  setText(
    "#passivePortNote",
    shodanSource === "client"
      ? "Historical third-party observations via your Shodan key, not a live scan."
      : shodanSource === "server"
        ? "Historical third-party observations via the server's Shodan key, not a live scan."
        : "Add a Shodan API key under Options to include passive port observations.",
    "",
  );
  addTokens(document.querySelector("#serviceRecords"), network.services);
}

function renderRegistration(registration) {
  setText("#registrar", registration?.registrar, "not published");
  setText("#registeredAt", formatTime(registration?.events?.registration));
  setText("#expiresAt", formatTime(registration?.events?.expiration));
  setText("#changedAt", formatTime(registration?.events?.["last changed"]));
  addTokens(document.querySelector("#nameServers"), registration?.nameservers, "No registration data");
}

function renderSources(sources) {
  const list = document.querySelector("#sourceList");
  clear(list);
  if (!sources?.length) {
    const item = document.createElement("li");
    item.className = "source-item";
    item.textContent = "No public source returned data for this target.";
    list.append(item);
    return;
  }
  for (const source of sources) {
    const item = document.createElement("li");
    item.className = "source-item";
    const link = document.createElement("a");
    link.href = source.url;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = source.name;
    const meta = document.createElement("div");
    meta.className = "source-meta";
    const kind = source.kind ? `${source.kind}` : "source";
    meta.textContent = `${kind} · ${source.freshness ?? ""} · checked ${formatTime(source.collectedAt)} · confidence ${source.confidence}%`.replace(/\s+·\s+·/g, " ·");
    item.append(link, meta);
    list.append(item);
  }
}

function render(data) {
  results.hidden = false;
  emptyState.hidden = true;
  setText(".result-target", data.target?.host);
  setText("#checkedAt", `Analysed ${formatTime(data.checkedAt)}`);
  renderRoute(data.lookupSource ?? data.source ?? {}, data.target?.host);
  renderDiagnosis(data.diagnosis);
  renderSummary(data);
  renderPosture(data.posture);
  renderFindings(data.findings);
  renderHttp(data.http ?? {});
  renderDns(data.network);
  renderTls(data);
  renderNetwork(data, data.tcp);
  renderRegistration(data.registration ?? data.network?.domain);
  renderSources(data.sources);
}

/* ---------- export ---------- */

function reportLines(data) {
  const http = data.http ?? {};
  const network = data.network ?? {};
  const lines = [];
  lines.push(`Public Internet Intelligence report`);
  lines.push(`Target: ${data.target?.host ?? "—"}`);
  lines.push(`Checked: ${data.checkedAt ?? "—"}`);
  lines.push(`HTTP: ${http.status === "complete" ? `${http.statusCode} ${http.statusText ?? ""}`.trim() : (http.code ?? "not run")}`);
  if (http.finalUrl) lines.push(`Final URL: ${http.finalUrl}`);
  if (Number.isFinite(http.responseTimeMs)) lines.push(`Response time: ${http.responseTimeMs} ms`);
  if (data.overview?.postureScore != null) lines.push(`Posture: ${data.overview.postureScore}/100 (${data.overview.grade})`);
  lines.push("");
  lines.push(`Network`);
  lines.push(`  IP: ${network.ip ?? "—"} (${network.ipVersion ?? "—"})`);
  lines.push(`  ASN: ${network.asn?.asn ?? "—"}`);
  lines.push(`  Organization: ${network.organization ?? "—"}`);
  lines.push(`  Prefix: ${network.prefix ?? "—"}`);
  lines.push(`  Country: ${network.country ?? "—"}`);
  lines.push(`  Hosting: ${network.hostingType ?? "—"}`);
  lines.push(`  Reverse DNS: ${Array.isArray(network.reverseDns) ? network.reverseDns.join(", ") : "—"}`);
  lines.push("");
  lines.push(`DNS`);
  for (const type of ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA"]) {
    const values = network.dns?.[type] ?? [];
    if (values.length) lines.push(`  ${type}: ${values.join(", ")}`);
  }
  lines.push("");
  lines.push(`Findings (${(data.findings ?? []).length})`);
  for (const finding of data.findings ?? []) {
    lines.push(`  [${finding.severity.toUpperCase()}] ${finding.title}`);
    lines.push(`      ${finding.detail}`);
    lines.push(`      Evidence: ${(finding.evidence ?? []).join(" | ")}`);
    lines.push(`      Source: ${finding.source}`);
  }
  return lines;
}

function toCsv(data) {
  const rows = [["section", "field", "value"]];
  const push = (section, field, value) => rows.push([section, field, value == null ? "" : String(value)]);
  push("target", "host", data.target?.host);
  push("target", "checkedAt", data.checkedAt);
  push("overview", "status", data.overview?.status);
  push("overview", "reachable", data.overview?.reachable);
  push("overview", "postureScore", data.overview?.postureScore);
  push("overview", "grade", data.overview?.grade);
  push("http", "statusCode", data.http?.statusCode);
  push("http", "finalUrl", data.http?.finalUrl);
  push("http", "responseTimeMs", data.http?.responseTimeMs);
  push("network", "ip", data.network?.ip);
  push("network", "asn", data.network?.asn?.asn);
  push("network", "organization", data.network?.organization);
  push("network", "prefix", data.network?.prefix);
  push("network", "country", data.network?.country);
  push("network", "hostingType", data.network?.hostingType);
  push("dns", "A", (data.network?.dns?.A ?? []).join(" "));
  push("dns", "AAAA", (data.network?.dns?.AAAA ?? []).join(" "));
  for (const finding of data.findings ?? []) push("finding", finding.title, `${finding.severity}: ${finding.detail}`);
  return rows.map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(",")).join("\n");
}

function download(filename, text, mime) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

function slug(value) {
  return String(value ?? "report").replace(/[^a-z0-9.-]+/gi, "_").slice(0, 60);
}

/* ---------- lookup ---------- */

async function runLookup(target) {
  const value = String(target ?? input.value ?? "").trim();
  if (!value) return;
  input.value = value;
  status.textContent = "";
  status.classList.remove("success");
  status.classList.remove("error");
  button.disabled = true;
  button.querySelector("span").textContent = "Analysing…";
  status.textContent = "Resolving DNS · checking HTTP · retrieving ASN, registration and TLS…";

  try {
    let response;
    try {
      const headers = { "Content-Type": "application/json" };
      if (SHODAN_KEY_PATTERN.test(shodanKey)) headers["X-Shodan-Key"] = shodanKey;
      response = await fetch(`${apiBase()}/api/lookup`, {
        method: "POST",
        headers,
        body: JSON.stringify({ target: value, captureBody: document.querySelector("#captureBody")?.checked === true }),
      });
    } catch {
      throw new Error("Could not reach the lookup API. Check TRACER_API_BASE and the Worker's ALLOWED_ORIGIN.");
    }
    const data = await response.json().catch(() => null);
    if (!data) {
      throw new Error(`No lookup API at ${apiBase() || location.origin}. Deploy the Worker and set TRACER_API_BASE in config.js to its URL.`);
    }
    if (!response.ok) throw new Error(data.error || "Lookup failed. Try again.");

    lastResult = data;
    render(data);
    rememberLookup(data.target?.host ?? value, data);
    status.classList.add("success");
    status.textContent = "Analysis complete.";
    document.querySelector("#results-heading").focus?.({ preventScroll: true });
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : "Lookup failed. Try again.";
  } finally {
    button.disabled = false;
    button.querySelector("span").textContent = "Analyse target";
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  runLookup(input.value);
});

document.querySelectorAll(".example-chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    input.value = chip.dataset.target ?? "";
    input.focus();
  });
});

document.querySelector("#clearHistory")?.addEventListener("click", () => {
  writeHistory([]);
  renderHistory();
});

document.querySelector("#copyReport")?.addEventListener("click", async () => {
  if (!lastResult) return;
  const ok = await copyText(reportLines(lastResult).join("\n"));
  status.textContent = ok ? "Report copied to clipboard." : "Clipboard unavailable.";
});

document.querySelector("#shareLink")?.addEventListener("click", async () => {
  const target = lastResult?.target?.host ?? input.value;
  if (!target) return;
  const url = `${location.origin}${location.pathname}?target=${encodeURIComponent(target)}`;
  const ok = await copyText(url);
  status.textContent = ok ? "Shareable link copied." : url;
});

document.querySelector("#exportJson")?.addEventListener("click", () => {
  if (lastResult) download(`pit-${slug(lastResult.target?.host)}.json`, JSON.stringify(lastResult, null, 2), "application/json");
});
document.querySelector("#exportCsv")?.addEventListener("click", () => {
  if (lastResult) download(`pit-${slug(lastResult.target?.host)}.csv`, toCsv(lastResult), "text/csv");
});
document.querySelector("#exportTxt")?.addEventListener("click", () => {
  if (lastResult) download(`pit-${slug(lastResult.target?.host)}.txt`, reportLines(lastResult).join("\n"), "text/plain");
});

/* ---------- boot ---------- */

document.querySelector("#saveShodanKey")?.addEventListener("click", saveShodanKey);
document.querySelector("#clearShodanKey")?.addEventListener("click", () => {
  shodanKey = "";
  storeShodanKey("");
  refreshShodanUi("Key cleared.");
});
document.querySelector("#toggleKeyVisibility")?.addEventListener("click", (event) => {
  const field = document.querySelector("#shodanKey");
  const showing = field.type === "text";
  field.type = showing ? "password" : "text";
  event.currentTarget.textContent = showing ? "Show" : "Hide";
});

initShodanKey();
renderHistory();
const initial = new URLSearchParams(location.search).get("target");
if (initial) {
  input.value = initial;
  runLookup(initial);
}
