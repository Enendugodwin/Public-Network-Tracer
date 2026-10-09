// Runs on your configured sites only. Marks the document so the page (e.g.
// Public Network Tracer) can tell the CORS Relaxer is present and that
// cross-origin responses will be readable. Harmless: it sets one data attribute.
(function () {
  function mark() {
    if (document.documentElement) {
      document.documentElement.dataset.corsRelaxer = "1";
      return true;
    }
    return false;
  }

  if (!mark()) {
    const observer = new MutationObserver(() => {
      if (mark()) observer.disconnect();
    });
    observer.observe(document, { childList: true, subtree: true });
  }
})();
