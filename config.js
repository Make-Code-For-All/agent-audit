/* Public settings for the scanner page. Nothing secret goes in this file. */
window.AGENT_AUDIT_CONFIG = {
  // Address of your deployed Worker, for example "https://agent-audit-api.YOUR-NAME.workers.dev".
  // Leave empty to run the page with the quick scan only.
  apiUrl: "https://agent-audit-api.mcfa.workers.dev/",
  // Public site key from Cloudflare Turnstile. Leave empty only if the Worker has no TURNSTILE_SECRET.
  turnstileSiteKey: "0x4AAAAAAFncL0288QYLD3RJ"
};
