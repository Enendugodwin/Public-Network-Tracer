const form = document.querySelector("#lookupForm");
const input = document.querySelector("#targetInput");
const button = document.querySelector("#checkButton");
const status = document.querySelector("#formStatus");
const results = document.querySelector("#results");
const emptyState = document.querySelector("#emptyState");

function setText(selector, value, fallback = "—") {
  const node = document.querySelector(selector);
  if (node) node.textContent = value == null || value === "" ? fallback : String(value);
}

function formatBytes(value) {
  if (!Number.isFinite(value)) return "—";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function formatTime(value) {
  if (!value) return "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function addTokens(container, values, emptyMessage = "No public records returned") {
  container.replaceChildren();
  if (!values?.length) {
    const empty = document.createElement("span");
    empty.className = "muted";
    empty.textContent = emptyMessage;
    container.append(empty);
    return;
  }
  for (const value of values) {
    const token = document.createElement("span");
    token.className = "token";
    token.textContent = String(value);
    container.append(token);
  }
}

function renderSources(sources) {
  const list = document.querySelector("#sourceList");
  list.replaceChildren();
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
    meta.textContent = `Checked ${formatTime(source.collectedAt)} · confidence ${source.confidence}%`;
    item.append(link, meta);
    list.append(item);
  }
}

function renderCertificates(certificates) {
  const container = document.querySelector("#certificateRecords");
  container.replaceChildren();
  if (!certificates?.length) {
    const empty = document.createElement("span");
    empty.className = "muted";
    empty.textContent = "No certificate observations available";
    container.append(empty);
    return;
  }
  for (const certificate of certificates) {
    const token = document.createElement("span");
    token.className = "token";
    token.textContent = `${certificate.subject ?? "Certificate"} · ${certificate.sha256.slice(0, 16)}…`;
    token.title = `Issuer: ${certificate.issuer ?? "unknown"}; expires: ${certificate.expiresAt ?? "unknown"}; SHA-256: ${certificate.sha256}`;
    container.append(token);
  }
}

const PUBLIC_IP_ENDPOINT = "https://www.cloudflare.com/cdn-cgi/trace";

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

function renderRoute(source, destination) {
  const sourceNode = document.querySelector("#routeSource");
  document.querySelector("#routeDestination").textContent = destination || "—";

  if (source.observedIp) {
    sourceNode.textContent = source.observedIp;
    sourceNode.title = source.probeOrigin ?? "";
    return;
  }

  sourceNode.textContent = "resolving…";
  sourceNode.title = source.unavailableReason ?? "";
  detectBrowserPublicIp().then((ip) => {
    sourceNode.textContent = ip ?? "unavailable";
    if (ip) sourceNode.title = "Detected by your browser (local development fallback).";
  });
}

function renderTcp(tcp) {
  const container = document.querySelector("#tcpChecks");
  const note = document.querySelector("#tcpNote");
  container.replaceChildren();
  if (!tcp || tcp.status !== "complete") {
    const empty = document.createElement("span");
    empty.className = "muted";
    empty.textContent = tcp?.status === "blocked" ? "Blocked" : "No TCP checks run";
    container.append(empty);
    note.textContent = tcp?.reason ?? "TCP connect checks run from the checker's edge network, not from your IP.";
    return;
  }
  for (const check of tcp.checks ?? []) {
    const token = document.createElement("span");
    token.className = `token ${check.reachable ? "token-open" : "token-closed"}`;
    const timing = check.reachable && Number.isFinite(check.responseTimeMs) ? ` · ${check.responseTimeMs} ms` : "";
    const code = check.reachable ? "" : ` · ${check.code ?? "CLOSED"}`;
    token.textContent = `:${check.port} ${check.reachable ? "open" : "closed"}${timing}${code}`;
    token.title = check.code ? `${check.code} — ${check.detail}` : check.detail;
    container.append(token);
  }
  note.textContent = "TCP connect checks run from the checker's edge network, not from your IP. There is no ICMP ping.";
}

function renderDiagnosis(diagnosis) {
  const block = document.querySelector("#diagnosis");
  if (!diagnosis) {
    block.hidden = true;
    return;
  }
  block.hidden = false;
  block.className = `diagnosis ${diagnosis.severity ?? ""}`.trim();
  document.querySelector("#diagnosisBadge").textContent = diagnosis.category ?? "result";
  document.querySelector("#diagnosisTitle").textContent = diagnosis.title ?? "";
  document.querySelector("#diagnosisSummary").textContent = diagnosis.summary ?? "";
  addTokens(document.querySelector("#diagnosisEvidence"), diagnosis.evidence ?? [], "");
}

function render(data) {
  results.hidden = false;
  emptyState.hidden = true;
  setText(".result-target", data.target?.host);
  setText("#checkedAt", `LOOKED UP ${formatTime(data.checkedAt)}`);
  renderRoute(data.source ?? {}, data.target?.host);
  renderDiagnosis(data.diagnosis);
  setText("#metricStatus", data.overview?.status);
  setText("#metricIp", data.overview?.ip);
  setText("#metricAsn", data.overview?.asn);
  setText("#metricOrg", data.overview?.organization, "Organization unavailable");
  setText("#metricTime", Number.isFinite(data.overview?.responseTimeMs) ? `${data.overview.responseTimeMs} ms` : "—");

  const http = data.http ?? {};
  const httpState = document.querySelector("#httpState");
  httpState.textContent = http.status === "complete" ? "Live" : http.status === "blocked" ? "Blocked" : http.status === "not_run" ? "Not run" : (http.code ?? "Unreachable");
  httpState.className = `panel-state ${http.status === "complete" ? "live" : http.status === "blocked" ? "" : "off"}`;
  const notice = document.querySelector("#httpNotice");
  notice.hidden = http.status === "complete";
  notice.textContent = http.status === "complete" ? "" : (http.reason ?? "The live HTTP check could not be completed.");
  setText("#metricHttpNote", http.status === "complete" ? "Live response" : http.status === "blocked" ? "Blocked" : "Unreachable");
  setText("#httpStatus", http.status === "complete" ? `${http.statusCode} ${http.statusText ?? ""}`.trim() : (http.code ?? (http.status === "blocked" ? "BLOCKED" : "NOT_RUN")));
  setText("#httpTime", Number.isFinite(http.responseTimeMs) ? `${http.responseTimeMs} ms` : "—");
  setText("#httpLength", http.contentLength == null ? "—" : formatBytes(http.contentLength));
  setText("#httpServer", http.server);
  setText("#httpTls", http.tls?.enabled ? "HTTPS · version not exposed" : http.tls ? "HTTP · no TLS" : "—");
  setText("#httpRedirect", http.status === "complete" ? (http.redirected ? `${http.redirects?.length ?? 0} hop(s)` : "No") : "—");
  addTokens(document.querySelector("#httpHeaders"), Object.entries(http.headers ?? {}).map(([name, value]) => `${name}: ${value}`), "No selected response headers");

  const network = data.network ?? {};
  setText("#networkIp", network.ip);
  setText("#networkAsn", network.asn?.asn);
  setText("#networkOrg", network.organization);
  setText("#networkCountry", network.country);
  setText("#networkRange", network.range);
  setText("#networkName", network.networkName);
  const dnsValues = Object.entries(network.dns ?? {}).flatMap(([type, records]) => records.map((record) => `${type}  ${record}`));
  addTokens(document.querySelector("#dnsRecords"), dnsValues);
  setText("#dnsNote", network.privateDnsAnswersFiltered ? "Private or reserved DNS answers were filtered from the result." : "", "");
  addTokens(document.querySelector("#portRecords"), network.observedPorts?.map((port) => `:${port}`), "No historical port data available");
  setText("#portNote", network.portSourceAvailable ? "Ports are historical public observations from Shodan, not a live port scan." : "Configure a Shodan API key to show its public historical port observations.", "");
  addTokens(document.querySelector("#serviceRecords"), network.services, "No service details available");
  renderCertificates(network.certificates);

  const domainDetails = document.querySelector("#domainDetails");
  domainDetails.hidden = !network.domain;
  if (network.domain) {
    setText("#registrar", network.domain.registrar);
    setText("#registeredAt", formatTime(network.domain.events?.registration));
    setText("#expiresAt", formatTime(network.domain.events?.expiration));
    setText("#nameServers", network.domain.nameservers?.join(", "));
  }
  renderSources(data.sources);
  renderTcp(data.tcp);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  status.textContent = "";
  status.classList.remove("success");
  button.disabled = true;
  button.querySelector("span").textContent = "Checking…";
  status.classList.remove("error");
  try {
    const response = await fetch("/api/lookup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: input.value }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Lookup failed. Try again.");
    render(data);
    status.classList.add("success");
    status.textContent = "Lookup complete.";
    document.querySelector("#results-heading").focus?.({ preventScroll: true });
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : "Lookup failed. Try again.";
  } finally {
    button.disabled = false;
    button.querySelector("span").textContent = "Check target";
  }
});

document.querySelectorAll(".example-chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    input.value = chip.dataset.target ?? "";
    input.focus();
  });
});
