// Points the dashboard at the Worker API.
//
// Served by the Worker, this is empty and the dashboard calls the same origin.
// When the dashboard is hosted separately (as on GitHub Pages), this holds the
// deployed Worker origin. The Worker must also list the dashboard's origin in
// ALLOWED_ORIGIN, otherwise the browser blocks the cross-origin call.
//
// Setting the repository variable TRACER_API_BASE overrides this file during
// the `pages` workflow; this default keeps the hosted dashboard working as-is.
window.TRACER_API_BASE = "https://public-network-tracer.enendugodwin.workers.dev";
