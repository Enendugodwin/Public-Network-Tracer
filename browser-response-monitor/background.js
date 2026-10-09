const MAX_RECORDS = 500;
const pending = new Map();

async function isEnabled() {
  const data = await chrome.storage.local.get("captureEnabled");
  return data.captureEnabled !== false;
}

async function saveRecord(record) {
  const data = await chrome.storage.local.get("requests");
  const records = Array.isArray(data.requests) ? data.requests : [];

  records.unshift(record);
  await chrome.storage.local.set({
    requests: records.slice(0, MAX_RECORDS)
  });
}

chrome.runtime.onInstalled.addListener(async () => {
  const data = await chrome.storage.local.get([
    "captureEnabled",
    "requests"
  ]);

  const defaults = {};

  if (typeof data.captureEnabled !== "boolean") {
    defaults.captureEnabled = true;
  }

  if (!Array.isArray(data.requests)) {
    defaults.requests = [];
  }

  if (Object.keys(defaults).length) {
    await chrome.storage.local.set(defaults);
  }
});

chrome.webRequest.onBeforeRequest.addListener(
  async details => {
    if (!(await isEnabled())) return;

    pending.set(details.requestId, {
      startedAt: details.timeStamp
    });
  },
  { urls: ["http://*/*", "https://*/*"] }
);

chrome.webRequest.onCompleted.addListener(
  async details => {
    if (!(await isEnabled())) return;

    const start = pending.get(details.requestId);
    pending.delete(details.requestId);

    await saveRecord({
      id: `${details.requestId}-${details.timeStamp}`,
      time: new Date(details.timeStamp).toISOString(),
      url: details.url,
      method: details.method,
      type: details.type,
      status: details.statusCode,
      statusLine: details.statusLine,
      durationMs: start
        ? Math.round(details.timeStamp - start.startedAt)
        : null,
      ip: details.ip || "",
      fromCache: Boolean(details.fromCache),
      error: ""
    });
  },
  { urls: ["http://*/*", "https://*/*"] }
);

chrome.webRequest.onErrorOccurred.addListener(
  async details => {
    if (!(await isEnabled())) return;

    const start = pending.get(details.requestId);
    pending.delete(details.requestId);

    await saveRecord({
      id: `${details.requestId}-${details.timeStamp}`,
      time: new Date(details.timeStamp).toISOString(),
      url: details.url,
      method: details.method,
      type: details.type,
      status: null,
      statusLine: "",
      durationMs: start
        ? Math.round(details.timeStamp - start.startedAt)
        : null,
      ip: "",
      fromCache: false,
      error: details.error || "Request failed"
    });
  },
  { urls: ["http://*/*", "https://*/*"] }
);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_REQUESTS") {
    chrome.storage.local.get(
      ["requests", "captureEnabled"],
      data => {
        sendResponse({
          requests: data.requests || [],
          captureEnabled: data.captureEnabled !== false
        });
      }
    );
    return true;
  }

  if (message.type === "SET_CAPTURE") {
    chrome.storage.local.set(
      { captureEnabled: Boolean(message.enabled) },
      () => sendResponse({ ok: true })
    );
    return true;
  }

  if (message.type === "CLEAR") {
    chrome.storage.local.set({ requests: [] }, () => {
      sendResponse({ ok: true });
    });
    return true;
  }
});
