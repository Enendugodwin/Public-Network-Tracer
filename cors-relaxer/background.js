// CORS Relaxer — scoped to YOUR site.
//
// CORS is relaxed ONLY for requests that originate from one of your configured
// sites ("initiator"), so other websites are unaffected. Requests from your site
// to other sites get their response CORS headers rewritten. Deny-by-default: with
// no "my site" configured, no rules exist and nothing changes.
//
// This changes only what *this browser* enforces; it cannot change a server's
// policy, grant access to data the server withholds, or satisfy credentials.
// Use only on sites you own or are authorized to assess.

const MAX_MATCHES = 100;
const MARKER_ID = "cors-relaxer-marker";

// Cached flattening of the config for the sync webRequest monitor.
let siteSet = new Set();
let destSet = new Set();

function hostnameOf(value) {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function domainMatches(host, set) {
  for (const domain of set) {
    if (host === domain || host.endsWith(`.${domain}`)) return true;
  }
  return false;
}

/** Requests from one of your sites? (empty initiator means a top-level load.) */
function fromMySite(initiator) {
  if (!initiator || !siteSet.size) return false;
  return domainMatches(hostnameOf(initiator), siteSet);
}

/** Is the destination allowed? No configured destinations means "any". */
function destinationAllowed(host) {
  if (!destSet.size) return true;
  return domainMatches(host, destSet);
}

function refreshCaches(sites, destinations) {
  siteSet = new Set((sites || []).filter((e) => e && e.enabled && e.domain).map((e) => e.domain));
  destSet = new Set((destinations || []).filter((e) => e && e.enabled && e.domain).map((e) => e.domain));
}

async function getState() {
  const data = await chrome.storage.local.get(["enabled", "sites", "destinations", "matches"]);
  const sites = Array.isArray(data.sites) ? data.sites : [];
  const destinations = Array.isArray(data.destinations) ? data.destinations : [];
  refreshCaches(sites, destinations);
  return {
    enabled: data.enabled !== false,
    sites,
    destinations,
    matches: Array.isArray(data.matches) ? data.matches : [],
  };
}

/** Accept a hostname or a URL and return a normalised lowercase host, or null. */
function normalizeDomain(input) {
  try {
    const value = String(input ?? "").trim();
    if (!value) return null;
    const withScheme = /^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : `https://${value}`;
    const host = new URL(withScheme).hostname.toLowerCase().replace(/^\.+|\.+$/g, "");
    if (!host || host.length > 253 || !host.includes(".") || !/^[a-z0-9.-]+$/.test(host)) return null;
    return host;
  } catch {
    return null;
  }
}

const RELAXED_HEADERS = [
  { header: "access-control-allow-origin", operation: "set", value: "*" },
  { header: "access-control-allow-methods", operation: "set", value: "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS" },
  { header: "access-control-allow-headers", operation: "set", value: "*" },
  { header: "access-control-expose-headers", operation: "set", value: "*" },
  { header: "access-control-max-age", operation: "set", value: "86400" },
  { header: "cross-origin-resource-policy", operation: "set", value: "cross-origin" },
];

/**
 * Keep a content script registered for the configured sites only, so a page
 * there can detect the relaxer. Nothing runs anywhere else.
 */
async function syncPageMarker(sites) {
  const matches = [];
  for (const entry of sites) {
    if (entry.enabled && entry.domain) {
      matches.push(`*://${entry.domain}/*`, `*://*.${entry.domain}/*`);
    }
  }
  try {
    await chrome.scripting.unregisterContentScripts({ ids: [MARKER_ID] });
  } catch {
    /* nothing registered yet */
  }
  if (!matches.length) return;
  try {
    await chrome.scripting.registerContentScripts([
      {
        id: MARKER_ID,
        matches: [...new Set(matches)],
        js: ["page-marker.js"],
        runAt: "document_start",
        allFrames: false,
      },
    ]);
  } catch (error) {
    console.warn("CORS Relaxer: could not register the page marker", error);
  }
}

/** Rebuild the dynamic rule set from the current config. */
async function applyRules() {
  const { enabled, sites, destinations } = await getState();
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing.map((rule) => rule.id);

  const initiators = sites.filter((entry) => entry.enabled && entry.domain).map((entry) => entry.domain);
  const dests = destinations.filter((entry) => entry.enabled && entry.domain).map((entry) => entry.domain);

  const addRules = [];
  // A rule only exists when the request is initiated by one of YOUR sites.
  if (enabled && initiators.length) {
    const condition = { initiatorDomains: initiators };
    if (dests.length) condition.requestDomains = dests;
    addRules.push({
      id: 1,
      priority: 1,
      action: { type: "modifyHeaders", responseHeaders: RELAXED_HEADERS },
      condition,
    });
  }

  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
  await chrome.action.setBadgeBackgroundColor({ color: "#1e40af" });
  await chrome.action.setBadgeText({ text: addRules.length ? "on" : "" });
  await syncPageMarker(sites);
  return addRules.length;
}

async function recordMatch(record) {
  const { matches } = await getState();
  matches.unshift(record);
  await chrome.storage.local.set({ matches: matches.slice(0, MAX_MATCHES) });
}

function shouldMonitor(details) {
  if (!fromMySite(details.initiator)) return false;
  return destinationAllowed(hostnameOf(details.url));
}

chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (!shouldMonitor(details)) return;
    recordMatch({
      time: new Date().toISOString(),
      url: details.url,
      method: details.method,
      type: details.type,
      status: details.statusCode,
      error: "",
    });
  },
  { urls: ["http://*/*", "https://*/*"] },
);

chrome.webRequest.onErrorOccurred.addListener(
  (details) => {
    if (!shouldMonitor(details)) return;
    recordMatch({
      time: new Date().toISOString(),
      url: details.url,
      method: details.method,
      type: details.type,
      status: null,
      error: details.error || "Request failed",
    });
  },
  { urls: ["http://*/*", "https://*/*"] },
);

async function initialize() {
  const data = await chrome.storage.local.get(["enabled", "sites", "destinations", "matches"]);
  const defaults = {};
  if (typeof data.enabled !== "boolean") defaults.enabled = true;
  if (!Array.isArray(data.sites)) defaults.sites = [];
  if (!Array.isArray(data.destinations)) defaults.destinations = [];
  if (!Array.isArray(data.matches)) defaults.matches = [];
  if (Object.keys(defaults).length) await chrome.storage.local.set(defaults);
  await applyRules();
}

chrome.runtime.onInstalled.addListener(initialize);
chrome.runtime.onStartup.addListener(initialize);

async function addDomain(listKey, raw, state) {
  const domain = normalizeDomain(raw);
  if (!domain) return { ok: false, error: "Enter a hostname or URL, e.g. tracer.example.org." };
  const list = state[listKey].filter((entry) => entry.domain !== domain);
  list.push({ domain, enabled: true });
  await chrome.storage.local.set({ [listKey]: list });
  await applyRules();
  return { ok: true, domain };
}

async function removeDomain(listKey, domain, state) {
  const list = state[listKey].filter((entry) => entry.domain !== domain);
  await chrome.storage.local.set({ [listKey]: list });
  await applyRules();
  return { ok: true };
}

async function toggleDomain(listKey, domain, enabled, state) {
  const list = state[listKey].map((entry) => (entry.domain === domain ? { ...entry, enabled: Boolean(enabled) } : entry));
  await chrome.storage.local.set({ [listKey]: list });
  await applyRules();
  return { ok: true };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    const state = await getState();
    const listKey = message.type.endsWith("_SITE") ? "sites" : "destinations";
    switch (message.type) {
      case "GET_STATE":
        sendResponse({ enabled: state.enabled, sites: state.sites, destinations: state.destinations, matches: state.matches });
        break;
      case "SET_ENABLED":
        await chrome.storage.local.set({ enabled: Boolean(message.enabled) });
        await applyRules();
        sendResponse({ ok: true });
        break;
      case "ADD_SITE":
      case "ADD_DEST":
        sendResponse(await addDomain(listKey, message.domain, state));
        break;
      case "REMOVE_SITE":
      case "REMOVE_DEST":
        sendResponse(await removeDomain(listKey, message.domain, state));
        break;
      case "TOGGLE_SITE":
      case "TOGGLE_DEST":
        sendResponse(await toggleDomain(listKey, message.domain, message.enabled, state));
        break;
      case "CLEAR_MATCHES":
        await chrome.storage.local.set({ matches: [] });
        sendResponse({ ok: true });
        break;
      default:
        sendResponse({ ok: false, error: "Unknown message." });
    }
  })();
  return true;
});
