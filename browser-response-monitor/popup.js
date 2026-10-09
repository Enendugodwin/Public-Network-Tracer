const results = document.getElementById("results");
const summary = document.getElementById("summary");
const filter = document.getElementById("filter");
const capture = document.getElementById("capture");
const popout = document.getElementById("popout");

// Same page, two modes: the toolbar popup (transient) and a persistent
// popup window opened with chrome.windows.create (popup.html?window=1).
const inWindow = new URLSearchParams(location.search).get("window") === "1";

let requests = [];

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

function statusClass(status) {
  if (status >= 200 && status < 300) return "s2";
  if (status >= 300 && status < 400) return "s3";
  if (status >= 400 && status < 500) return "s4";
  if (status >= 500) return "s5";
  return "";
}

async function refresh() {
  const data = await chrome.runtime.sendMessage({
    type: "GET_REQUESTS"
  });

  requests = data.requests || [];
  capture.checked = data.captureEnabled;
  render();
}

function render() {
  const query = filter.value.trim().toLowerCase();

  const filtered = requests.filter(request =>
    [
      request.url,
      request.method,
      request.status,
      request.type,
      request.error
    ].some(value =>
      String(value ?? "").toLowerCase().includes(query)
    )
  );

  summary.textContent =
    `${capture.checked ? "Capture on" : "Capture paused"} · ` +
    `${requests.length} recorded · ${filtered.length} displayed`;

  if (!filtered.length) {
    results.innerHTML =
      '<div class="empty">No requests found. Browse a website and reopen this panel.</div>';
    return;
  }

  results.innerHTML = filtered.map(request => {
    const status = request.error ? "ERR" : (request.status ?? "—");
    const time = new Date(request.time).toLocaleTimeString();
    const duration = request.durationMs == null
      ? "—"
      : `${request.durationMs} ms`;

    return `
      <article class="request">
        <div class="row">
          <span class="status ${statusClass(request.status)}">
            ${escapeHtml(status)}
          </span>
          <span class="method">${escapeHtml(request.method)}</span>
          <span>${escapeHtml(request.type)}</span>
        </div>

        <div class="url">${escapeHtml(request.url)}</div>

        <div class="meta">
          <span>${escapeHtml(time)}</span>
          <span>${escapeHtml(duration)}</span>
          <span>${request.fromCache ? "Cache" : "Network"}</span>
          ${request.ip ? `<span>IP: ${escapeHtml(request.ip)}</span>` : ""}
          ${request.error ? `<span>${escapeHtml(request.error)}</span>` : ""}
        </div>
      </article>
    `;
  }).join("");
}

filter.addEventListener("input", render);

capture.addEventListener("change", async () => {
  await chrome.runtime.sendMessage({
    type: "SET_CAPTURE",
    enabled: capture.checked
  });
  await refresh();
});

document.getElementById("clear").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ type: "CLEAR" });
  await refresh();
});

document.getElementById("export").addEventListener("click", () => {
  const query = filter.value.trim().toLowerCase();

  const filtered = requests.filter(request =>
    [
      request.url,
      request.method,
      request.status,
      request.type,
      request.error
    ].some(value =>
      String(value ?? "").toLowerCase().includes(query)
    )
  );

  const columns = [
    "time", "method", "status", "url", "type",
    "durationMs", "ip", "fromCache", "error"
  ];

  const cell = value =>
    `"${String(value ?? "").replace(/"/g, '""')}"`;

  const csv = [
    columns.join(","),
    ...filtered.map(request =>
      columns.map(column => cell(request[column])).join(",")
    )
  ].join("\r\n");

  const blob = new Blob([csv], {
    type: "text/csv;charset=utf-8"
  });

  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "browser-responses.csv";
  link.click();
  URL.revokeObjectURL(url);
});

// Pop out into a persistent window so traffic can be watched while you browse.
// The toolbar popup closes as soon as it loses focus; this window does not.
if (inWindow) {
  popout.hidden = true;
  document.body.classList.add("window-mode");
} else {
  popout.addEventListener("click", () => {
    chrome.windows.create({
      url: chrome.runtime.getURL("popup.html?window=1"),
      type: "popup",
      width: 720,
      height: 780
    });
  });
}

// Live-update the open monitor as new responses land. The toolbar popup
// re-reads on open, so this only matters for the persistent window.
let liveTimer = null;
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (!changes.requests && !changes.captureEnabled) return;
  clearTimeout(liveTimer);
  liveTimer = setTimeout(refresh, 150);
});

refresh();
