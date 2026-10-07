// Points the dashboard at the Worker API.
//
// Served by the Worker, this is empty and the dashboard calls the same origin.
// When the dashboard is hosted separately (e.g. GitHub Pages), set this to the
// deployed Worker origin, for example:
//
//   window.TRACER_API_BASE = "https://public-network-tracer.<subdomain>.workers.dev";
//
// The Worker must also list the dashboard's origin in ALLOWED_ORIGIN.
window.TRACER_API_BASE = "";
