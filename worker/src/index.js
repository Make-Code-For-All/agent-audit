/* Agent Audit API: a small Cloudflare Worker that sits between the public scanner page and GitHub.
 *
 * It exists so visitors never need a GitHub token. The token lives here as a secret.
 *
 *   POST /scan            page asks for a deep scan of a public repository
 *   GET  /result/:id      page polls for the result
 *   POST /callback?job=   the GitHub Actions job posts its finished report (HMAC signed)
 *
 * Storage is a single KV namespace (SCANS). Results are kept for 24 hours and then deleted.
 */

const REPO_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9_.-]{1,100}$/;
const ID_RE = /^r[0-9a-f]{20}$/;
const SHA_RE = /^[0-9a-f]{40}$/;
const DAY = 86400;

// Tune these to control cost and abuse. KV's free plan allows about 1,000 writes per day,
// and each new scan uses about 5 of them.
const LIMITS = {
  perIpPerHour: 6,        // requests per visitor per hour
  globalPerHour: 60,      // new scan jobs started per hour, across everyone
  maxRepoKb: 500000,      // refuse repositories larger than about 500 MB
  maxBodyBytes: 2000,     // size of a /scan request
  maxCallbackBytes: 5000000
};

// Sent on every response. The API only ever returns JSON, so nothing here should be rendered or framed.
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'Referrer-Policy': 'no-referrer',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Cache-Control': 'no-store'
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cors = { ...corsHeaders(request, env), ...SECURITY_HEADERS };
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    let res;
    try {
      if (url.pathname === '/scan' && request.method === 'POST') res = await handleScan(request, env);
      else if (url.pathname.startsWith('/result/') && request.method === 'GET') res = await handleResult(url, env);
      else if (url.pathname === '/callback' && request.method === 'POST') res = await handleCallback(request, url, env);
      else res = json({ error: 'Not found' }, 404);
    } catch (err) {
      console.error('unhandled error', err && err.stack ? err.stack : err);
      res = json({ error: 'Something went wrong. Please try again in a moment.' }, 500);
    }
    for (const [k, v] of Object.entries(cors)) res.headers.set(k, v);
    return res;
  }
};

/* ------------------------------ helpers ------------------------------ */

function allowedOrigins(env) {
  return String(env.ALLOWED_ORIGIN || '').split(',').map((s) => s.trim()).filter(Boolean);
}

function corsHeaders(request, env) {
  const origin = request.headers.get('Origin');
  const h = {
    'Vary': 'Origin',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400'
  };
  if (origin && allowedOrigins(env).includes(origin)) h['Access-Control-Allow-Origin'] = origin;
  return h;
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  });
}

function parseRepo(input) {
  let s = String(input || '').trim().replace(/^https?:\/\//i, '').replace(/^www\./i, '').replace(/^github\.com\//i, '');
  s = s.split(/[?#]/)[0];
  const parts = s.split('/').filter(Boolean);
  if (parts.length < 2) return null;
  const name = parts[0] + '/' + parts[1].replace(/\.git$/i, '');
  if (!REPO_RE.test(name) || name.split('/')[1] === '.' || name.split('/')[1] === '..') return null;
  return name;
}

function randomId() {
  const b = new Uint8Array(10);
  crypto.getRandomValues(b);
  return 'r' + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

const hexToBytes = (hex) => Uint8Array.from(hex.match(/../g), (x) => parseInt(x, 16));

async function bump(env, key, limit, ttl = 3700) {
  const current = parseInt((await env.SCANS.get(key)) || '0', 10);
  if (current >= limit) return false;
  await env.SCANS.put(key, String(current + 1), { expirationTtl: ttl });
  return true;
}

function gh(env, path, init = {}) {
  return fetch('https://api.github.com' + path, {
    ...init,
    headers: {
      'Accept': 'application/vnd.github+json',
      'Authorization': 'Bearer ' + env.GITHUB_TOKEN,
      'User-Agent': 'agent-audit-api',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(init.headers || {})
    }
  });
}

async function verifyTurnstile(env, token, ip) {
  if (!env.TURNSTILE_SECRET) return true; // not configured: skipped (not recommended for a public site)
  if (typeof token !== 'string' || token.length < 10 || token.length > 2048) return false;
  const form = new FormData();
  form.append('secret', env.TURNSTILE_SECRET);
  form.append('response', token);
  if (ip) form.append('remoteip', ip);
  const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
  const data = await r.json().catch(() => ({}));
  return data.success === true;
}

async function verifySignature(secret, bodyBytes, header) {
  const m = /^sha256=([0-9a-f]{64})$/.exec(header || '');
  if (!m || !secret) return false;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  return crypto.subtle.verify('HMAC', key, hexToBytes(m[1]), bodyBytes); // constant-time comparison
}

/* ------------------------------ POST /scan ------------------------------ */

async function handleScan(request, env) {
  // Browsers always send Origin on cross-site POSTs. Requiring a known one blocks other websites
  // (and casual scripts); the Turnstile check below is what stops determined bots.
  const origin = request.headers.get('Origin');
  if (!origin || !allowedOrigins(env).includes(origin)) return json({ error: 'This site is not allowed to use the scanner.' }, 403);
  // JSON only: a cross-site form cannot send this content type without a CORS preflight.
  if (!/^application\/json\b/i.test(request.headers.get('Content-Type') || '')) return json({ error: 'Unsupported content type.' }, 415);

  const text = await request.text();
  if (text.length > LIMITS.maxBodyBytes) return json({ error: 'Request too large.' }, 413);
  let body;
  try { body = JSON.parse(text); } catch { return json({ error: 'Invalid request.' }, 400); }
  if (!body || typeof body !== 'object') return json({ error: 'Invalid request.' }, 400);

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await verifyTurnstile(env, body.turnstile, ip))) return json({ error: 'The security check failed. Reload the page and try again.' }, 403);

  const requested = parseRepo(body.repo);
  if (!requested) return json({ error: 'Enter a repository as owner/name or a github.com link.' }, 400);
  if (body.commit !== undefined && body.commit !== null && body.commit !== '' && !SHA_RE.test(String(body.commit))) return json({ error: 'Invalid commit.' }, 400);

  const hour = Math.floor(Date.now() / 3600000);
  if (!(await bump(env, `rl:ip:${ip}:${hour}`, LIMITS.perIpPerHour))) {
    return json({ error: 'Too many scans from your connection. Please try again in an hour.' }, 429);
  }

  // Confirm the repository is public and not enormous.
  const metaRes = await gh(env, '/repos/' + requested);
  if (metaRes.status === 404) return json({ error: 'Repository not found, or it is private. Only public repositories can be scanned.' }, 404);
  if (!metaRes.ok) { console.error('github repo lookup', metaRes.status); return json({ error: 'GitHub is not responding right now. Please try again shortly.' }, 502); }
  const meta = await metaRes.json();
  if (meta.private) return json({ error: 'Repository not found, or it is private. Only public repositories can be scanned.' }, 404);
  if (typeof meta.size === 'number' && meta.size > LIMITS.maxRepoKb) return json({ error: 'This repository is too large for the deep scan.' }, 413);
  const full = meta.full_name;

  // Pin the exact commit so the quick scan and the deep scan look at the same code.
  let sha;
  if (body.commit) {
    const c = await gh(env, `/repos/${full}/commits/${body.commit}`);
    if (c.status === 404 || c.status === 422) return json({ error: 'That commit was not found in this repository.' }, 400);
    if (!c.ok) { console.error('github commit lookup', c.status); return json({ error: 'GitHub is not responding right now. Please try again shortly.' }, 502); }
    sha = (await c.json()).sha;
  } else {
    const c = await gh(env, `/repos/${full}/commits?per_page=1&sha=${encodeURIComponent(meta.default_branch)}`);
    if (!c.ok) return json({ error: 'Could not read the latest commit of this repository.' }, 502);
    const list = await c.json();
    sha = list && list[0] && list[0].sha;
  }
  if (!SHA_RE.test(String(sha))) return json({ error: 'Could not determine which commit to scan.' }, 502);

  // Reuse an existing or in-progress scan of the same commit.
  const cacheKey = `cache:${full.toLowerCase()}@${sha}`;
  const cachedId = await env.SCANS.get(cacheKey);
  if (cachedId && ID_RE.test(cachedId)) {
    const rawJob = await env.SCANS.get('job:' + cachedId);
    if (rawJob) {
      const job = JSON.parse(rawJob);
      if (job.status !== 'failed') return json({ jobId: cachedId, status: job.status, repo: full, commit: sha, cached: true });
    }
  }

  if (!(await bump(env, `rl:global:${hour}`, LIMITS.globalPerHour))) {
    return json({ error: 'The scanner is busy right now. Please try again in a little while.' }, 429);
  }

  const id = randomId();
  await env.SCANS.put('job:' + id, JSON.stringify({ status: 'pending', repo: full, sha, createdAt: Date.now() }), { expirationTtl: DAY });
  await env.SCANS.put(cacheKey, id, { expirationTtl: DAY });

  const dispatch = await gh(env, `/repos/${env.SCANNER_REPO}/actions/workflows/${env.WORKFLOW_FILE || 'scan.yml'}/dispatches`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ref: env.SCANNER_BRANCH || 'main', inputs: { target: full, commit: sha, run_key: id } })
  });
  if (dispatch.status !== 204) {
    console.error('dispatch failed', dispatch.status, await dispatch.text().catch(() => ''));
    await env.SCANS.delete('job:' + id);
    await env.SCANS.delete(cacheKey);
    return json({ error: 'Could not start the deep scan right now. Please try again later.' }, 502);
  }
  return json({ jobId: id, status: 'pending', repo: full, commit: sha });
}

/* ------------------------------ GET /result/:id ------------------------------ */

async function handleResult(url, env) {
  const id = url.pathname.slice('/result/'.length);
  if (!ID_RE.test(id)) return json({ error: 'Unknown scan.' }, 404);
  const raw = await env.SCANS.get('job:' + id);
  if (!raw) return json({ error: 'This scan does not exist or has expired.' }, 404);
  const job = JSON.parse(raw);
  const out = { status: job.status, repo: job.repo, commit: job.sha };
  if (job.status === 'done') out.report = job.report;
  if (job.status === 'failed') out.message = job.message || 'The scan did not complete.';
  return json(out);
}

/* ------------------------------ POST /callback ------------------------------ */

async function handleCallback(request, url, env) {
  const id = url.searchParams.get('job') || '';
  if (!ID_RE.test(id)) return json({ error: 'Bad request.' }, 400);
  const declared = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (declared > LIMITS.maxCallbackBytes) return json({ error: 'Too large.' }, 413);
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength > LIMITS.maxCallbackBytes) return json({ error: 'Too large.' }, 413);

  if (!(await verifySignature(env.CALLBACK_SECRET, bytes, request.headers.get('X-Signature')))) {
    return json({ error: 'Invalid signature.' }, 401);
  }

  const raw = await env.SCANS.get('job:' + id);
  if (!raw) return json({ error: 'Unknown job.' }, 404);
  const job = JSON.parse(raw);
  if (job.status !== 'pending') return json({ error: 'Job already finished.' }, 409); // blocks replays

  let body;
  try { body = JSON.parse(new TextDecoder().decode(bytes)); } catch { return json({ error: 'Invalid body.' }, 400); }

  if (body && body.status === 'failed') {
    const message = String(body.message || 'The scan did not complete.').slice(0, 200);
    await env.SCANS.put('job:' + id, JSON.stringify({ ...job, status: 'failed', message, finishedAt: Date.now() }), { expirationTtl: DAY });
    return json({ ok: true });
  }

  const report = body && body.report;
  const valid = body && body.status === 'done' && report && typeof report === 'object' && report.schema === 1 &&
    report.tools && typeof report.tools === 'object' &&
    String(report.target || '').toLowerCase() === job.repo.toLowerCase() && report.commit === job.sha;
  if (!valid) return json({ error: 'Report does not match this job.' }, 400);

  await env.SCANS.put('job:' + id, JSON.stringify({ ...job, status: 'done', report, finishedAt: Date.now() }), { expirationTtl: DAY });
  return json({ ok: true });
}
