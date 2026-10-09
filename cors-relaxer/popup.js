const enabledEl = document.getElementById("enabled");
const summary = document.getElementById("summary");
const siteInput = document.getElementById("siteInput");
const destInput = document.getElementById("destInput");
const statusEl = document.getElementById("status");
const sitesEl = document.getElementById("sites");
const destinationsEl = document.getElementById("destinations");
const matchesEl = document.getElementById("matches");

function send(type, extra = {}) {
  return chrome.runtime.sendMessage({ type, ...extra });
}

function statusClass(status) {
  if (status >= 200 && status < 300) return "s2";
  if (status >= 300 && status < 400) return "s3";
  if (status >= 400 && status < 500) return "s4";
  if (status >= 500) return "s5";
  return "";
}

function setStatus(message, ok = false) {
  statusEl.textContent = message;
  statusEl.className = `status${ok ? " ok" : ""}`;
}

function renderList(container, list, prefix, emptyMessage) {
  container.replaceChildren();
  if (!list.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = emptyMessage;
    container.append(empty);
    return;
  }
  for (const entry of list) {
    const row = document.createElement("div");
    row.className = "domain";

    const label = document.createElement("label");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = entry.enabled;
    checkbox.addEventListener("change", async () => {
      await send(`TOGGLE_${prefix}`, { domain: entry.domain, enabled: checkbox.checked });
      refresh();
    });
    const name = document.createElement("span");
    name.className = "mono";
    name.textContent = entry.domain;
    label.append(checkbox, name);

    const remove = document.createElement("button");
    remove.className = "link";
    remove.textContent = "Remove";
    remove.addEventListener("click", async () => {
      await send(`REMOVE_${prefix}`, { domain: entry.domain });
      refresh();
    });

    row.append(label, remove);
    container.append(row);
  }
}

function renderMatches(matches) {
  matchesEl.replaceChildren();
  if (!matches.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "No matching requests seen yet.";
    matchesEl.append(empty);
    return;
  }
  for (const match of matches) {
    const card = document.createElement("article");
    card.className = "match";

    const row = document.createElement("div");
    row.className = "row";
    const badge = document.createElement("span");
    badge.className = `status-badge ${statusClass(match.status)}`;
    badge.textContent = match.error ? "ERR" : (match.status ?? "—");
    const method = document.createElement("span");
    method.className = "method";
    method.textContent = match.method || "";
    const type = document.createElement("span");
    type.textContent = match.type || "";
    row.append(badge, method, type);

    const url = document.createElement("div");
    url.className = "url";
    url.textContent = match.url || "";

    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = [new Date(match.time).toLocaleTimeString(), match.error].filter(Boolean).join(" · ");

    card.append(row, url, meta);
    matchesEl.append(card);
  }
}

async function refresh() {
  const state = await send("GET_STATE");
  enabledEl.checked = state.enabled;
  const activeSites = state.sites.filter((entry) => entry.enabled).length;
  const activeDests = state.destinations.filter((entry) => entry.enabled).length;
  summary.textContent = `${state.enabled ? "Relaxing" : "Paused"} · ${activeSites} site${activeSites === 1 ? "" : "s"} · ${activeDests ? `${activeDests} dest` : "any"} · ${state.matches.length} seen`;
  renderList(sitesEl, state.sites, "SITE", "No site yet — nothing is relaxed until you add your site.");
  renderList(destinationsEl, state.destinations, "DEST", "Any other site (no destination limit).");
  renderMatches(state.matches);
}

async function addDomain(type, input, label) {
  const value = input.value.trim();
  if (!value) return;
  const result = await send(type, { domain: value });
  if (result.ok) {
    input.value = "";
    setStatus(`Added ${result.domain} to ${label}.`, true);
    refresh();
  } else {
    setStatus(result.error || "Could not add that domain.");
  }
}

enabledEl.addEventListener("change", async () => {
  await send("SET_ENABLED", { enabled: enabledEl.checked });
  refresh();
});

document.getElementById("addSite").addEventListener("click", () => addDomain("ADD_SITE", siteInput, "my site"));
document.getElementById("addDest").addEventListener("click", () => addDomain("ADD_DEST", destInput, "destinations"));
siteInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") document.getElementById("addSite").click();
});
destInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") document.getElementById("addDest").click();
});

document.getElementById("addCurrent").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let host = "";
  try {
    host = tab?.url ? new URL(tab.url).hostname : "";
  } catch {
    host = "";
  }
  if (!host) {
    setStatus("Could not read the current tab's address.");
    return;
  }
  const result = await send("ADD_SITE", { domain: host });
  if (result.ok) {
    setStatus(`Added ${result.domain} as my site.`, true);
    refresh();
  } else {
    setStatus(result.error || "Could not add the current site.");
  }
});

document.getElementById("clearMatches").addEventListener("click", async () => {
  await send("CLEAR_MATCHES");
  refresh();
});

refresh();
