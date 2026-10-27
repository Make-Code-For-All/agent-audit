'use strict';
/* Agent Audit: scanner logic and page behaviour. Needs rules.js loaded first. */

// Clickjacking guard: static hosting cannot send frame-ancestors headers, so refuse to run inside a frame.
if (typeof window !== 'undefined' && window.top !== window.self){
  document.documentElement.textContent = 'This page cannot be shown inside another website. Open it directly.';
  throw new Error('Blocked: page is framed');
}

/* ============================================================
   Small helpers
   ============================================================ */
const $ = (id) => document.getElementById(id);
function h(tag, props, ...kids){
  const el = document.createElement(tag);
  if (props) for (const [k,v] of Object.entries(props)){
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat(Infinity)){ if (kid === null || kid === undefined || kid === false) continue; el.append(kid); }
  return el;
}
const basename = (p) => p.slice(p.lastIndexOf('/') + 1);
function extOf(p){
  const b = basename(p).toLowerCase();
  if (b === 'dockerfile' || b.startsWith('dockerfile.')) return 'dockerfile';
  if (b === 'makefile') return 'makefile';
  const i = b.lastIndexOf('.');
  return i < 0 ? '' : b.slice(i + 1);
}
const groupOf = (ext) => { for (const k in GROUPS) if (GROUPS[k].has(ext)) return k; return null; };
const encPath = (p) => p.split('/').map(encodeURIComponent).join('/');
const fmtDate = (s) => s ? new Date(s).toISOString().slice(0,10) : 'unknown';
const daysSince = (s) => (Date.now() - new Date(s).getTime()) / 864e5;
const fmtNum = (n) => Number(n).toLocaleString('en-US');

// Make invisible or control characters visible so they cannot reorder or hide text in the report.
function sanitize(s){
  return s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u2069\uFEFF]|[\u{E0000}-\u{E007F}]/gu,
    (c) => '\u27E6U+' + c.codePointAt(0).toString(16).toUpperCase().padStart(4,'0') + '\u27E7');
}
function snippet(line, idx){
  const start = Math.max(0, (idx || 0) - 70);
  let t = line.slice(start, start + 260).trim();
  if (start > 0) t = '\u2026' + t;
  if (line.length > start + 260) t += '\u2026';
  return sanitize(t);
}
function parseRepo(input){
  let s = input.trim().replace(/^https?:\/\//i,'').replace(/^www\./i,'').replace(/^github\.com\//i,'');
  s = s.split(/[?#]/)[0];
  const parts = s.split('/').filter(Boolean);
  if (parts.length < 2) return null;
  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/i,'');
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(owner)) return null;
  if (!/^[A-Za-z0-9_.-]{1,100}$/.test(repo) || repo === '.' || repo === '..') return null;
  return { owner, repo };
}
function levenshtein(a, b){
  if (Math.abs(a.length - b.length) > 1) return 2;
  const dp = Array.from({length:a.length+1}, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++)
    dp[i][j] = Math.min(dp[i-1][j] + 1, dp[i][j-1] + 1, dp[i-1][j-1] + (a[i-1] === b[j-1] ? 0 : 1));
  return dp[a.length][b.length];
}
class ScanError extends Error {}

/* ============================================================
   Network
   ============================================================ */
const net = { rate:null, controller:null };
function timeoutSignal(ms){
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  net.controller.signal.addEventListener('abort', () => { clearTimeout(t); c.abort(); }, { once:true });
  return c.signal;
}
async function gh(url, token, notFound){
  const headers = { 'Accept':'application/vnd.github+json' };
  if (token) headers['Authorization'] = 'Bearer ' + token;
  let res;
  try { res = await fetch(url, { headers, signal: timeoutSignal(25000), cache:'no-store' }); }
  catch (e){
    if (net.controller.signal.aborted) throw new ScanError('Scan cancelled.');
    throw new ScanError('Could not reach GitHub. Check your connection and try again.');
  }
  const rem = res.headers.get('x-ratelimit-remaining');
  if (rem !== null) net.rate = { remaining:+rem, limit:+res.headers.get('x-ratelimit-limit'), reset:+res.headers.get('x-ratelimit-reset') };
  if (res.status === 204) return null;
  if (!res.ok){
    if (res.status === 404) throw new ScanError(notFound || 'Repository not found. It may be private or misspelled. This version supports public repositories only.');
    if (res.status === 401) throw new ScanError('GitHub rejected the token. Remove it or paste a valid one.');
    if ((res.status === 403 || res.status === 429) && rem === '0'){
      const when = net.rate ? new Date(net.rate.reset * 1000).toLocaleTimeString() : 'later';
      throw new ScanError('GitHub rate limit reached. Try again after ' + when + ', or add a token under Optional settings.');
    }
    throw new ScanError('GitHub returned an error (' + res.status + ').');
  }
  return res.json();
}
async function fetchRaw(owner, repo, sha, path){
  const url = 'https://raw.githubusercontent.com/' + owner + '/' + repo + '/' + sha + '/' + encPath(path);
  const res = await fetch(url, { signal: timeoutSignal(25000), cache:'no-store' });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return res.text();
}
async function pool(items, n, fn){
  let i = 0;
  await Promise.all(Array.from({length:n}, async () => {
    while (i < items.length){ if (net.controller.signal.aborted) return; const idx = i++; await fn(items[idx], idx); }
  }));
}

/* ============================================================
   Analysis
   ============================================================ */
function add(findings, f){ findings.push(Object.assign({ file:null, line:null, snippet:'' }, f)); }

function scanText(path, text, findings){
  const ext = extOf(path);
  const group = groupOf(ext);
  const applicable = [];
  for (const r of RULES){
    if (r.path && !r.path.test(path)) continue;
    if (r.skip && r.skip.test(path)) continue;
    let sev = r.sev;
    if (r.exts){ if (!r.exts.includes(ext)) continue; }
    else if (r.path){ /* path-only rule */ }
    else {
      const allowed = r.in || ['CODE','CONF'];
      if (allowed.includes(group)) { /* ok */ }
      else if (group === 'DOC' && r.docSev) sev = r.docSev;
      else continue;
    }
    applicable.push({ r, sev });
  }
  const counts = new Map();
  let longFlagged = false;
  const lines = text.split(/\r\n|\r|\n/);
  for (let i = 0; i < lines.length; i++){
    let line = lines[i];
    if (line.length < 4) continue;
    if (!longFlagged && group === 'CODE' && line.length > LIMITS.longLine && !/\.min\.|\.map$|\.bundle\./i.test(path)){
      longFlagged = true;
      add(findings, { rule:'OBF-LONGLINE', sev:'low', title:'Extremely long line in source file',
        why:'Minified or obfuscated code is hard to review. Look for the unminified source.',
        file:path, line:i+1, snippet:sanitize(line.slice(0,160)) + '\u2026 (' + fmtNum(line.length) + ' characters)' });
    }
    if (line.length > LIMITS.lineCap) line = line.slice(0, LIMITS.lineCap);
    for (const { r, sev } of applicable){
      const n = counts.get(r.id) || 0;
      if (n >= LIMITS.perFileRule) continue;
      const m = r.re.exec(line);
      if (!m) continue;
      if (r.filter && !r.filter(m, line, i + 1)) continue;
      counts.set(r.id, n + 1);
      add(findings, { rule:r.id, sev, title:r.title, why:r.why, file:path, line:i+1, snippet:snippet(line, m.index) });
    }
  }
  for (const fr of FILE_RULES){
    if (!fr.exts.includes(ext) || !fr.test(text, path)) continue;
    let at = 0;
    if (fr.find) for (let i = 0; i < lines.length; i++){ if (fr.find.test(lines[i])){ at = i; break; } }
    add(findings, { rule:fr.id, sev:fr.sev, title:fr.title, why:fr.why, file:path, line:at + 1, snippet:snippet(lines[at] || '', 0) });
  }
}

function versionFrom(spec){
  let m = /(\d+)\.(\d+)\.(\d+)(?:-[\w.]+)?/.exec(spec);
  if (m) return m[0];
  m = /(\d+)\.(\d+)/.exec(spec);
  if (m) return m[0] + '.0';
  m = /^[~^>=<\s]*(\d+)\s*(?:\.[x*])?\s*$/.exec(spec);
  return m ? m[1] + '.0.0' : null;
}

function analyzePackageJson(path, text, findings, deps){
  let j; try { j = JSON.parse(text); } catch { return; }
  if (!j || typeof j !== 'object') return;
  const scripts = (j.scripts && typeof j.scripts === 'object') ? j.scripts : {};
  for (const hook of ['preinstall','install','postinstall','prepare']){
    const cmd = scripts[hook];
    if (typeof cmd !== 'string') continue;
    const risky = /curl|wget|https?:\/\/|\bnode\s+-e|\beval\b|base64|powershell|\bnc\b|\|\s*(?:ba)?sh/i.test(cmd);
    add(findings, { rule:'PKG-INSTALL-HOOK', sev: risky ? 'high' : 'medium', title:'npm install-time script',
      why:'This command runs automatically when the package is installed. Read it before you run npm install.',
      file:path, snippet:sanitize(hook + ': ' + cmd.slice(0, 300)) });
  }
  for (const sect of ['dependencies','devDependencies','optionalDependencies']){
    const o = j[sect]; if (!o || typeof o !== 'object') continue;
    for (const [name, spec] of Object.entries(o)){
      if (typeof spec !== 'string') continue;
      if (/^(?:git\+|git:|github:|https?:|file:|ssh:)|^[\w.-]+\/[\w.-]+(?:#.+)?$/.test(spec)){
        add(findings, { rule:'PKG-URL-DEP', sev:'medium', title:'Dependency installed from a URL or git, not the registry',
          why:'These skip the registry, so there is no malware screening and the target can change without a version bump.',
          file:path, snippet:sanitize(name + ': ' + spec.slice(0, 200)) });
        continue;
      }
      deps.push({ eco:'npm', name, spec, file:path, dev: sect === 'devDependencies' });
    }
  }
}

function analyzeRequirements(path, text, findings, deps){
  const unpinned = [];
  for (let raw of text.split(/\r\n|\r|\n/)){
    let line = raw.replace(/\s+#.*$/, '').replace(/;.*$/, '').trim();
    if (!line || line.startsWith('#') || /^-[rc]\s/.test(line) || line.startsWith('--')) continue;
    if (/^(?:-e\s+)?(?:git\+|https?:|ssh:|file:)/.test(line)){
      add(findings, { rule:'PKG-URL-DEP', sev:'medium', title:'Dependency installed from a URL or git, not the registry',
        why:'These skip the registry, so there is no malware screening and the target can change without a version bump.',
        file:path, snippet:sanitize(line.slice(0, 200)) });
      continue;
    }
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(==|~=|>=|<=|>|<|!=)?\s*([\w.!+*-]+)?/.exec(line);
    if (!m) continue;
    const [, name, op, ver] = m;
    if (op === '==' && ver) deps.push({ eco:'PyPI', name, spec:'==' + ver, file:path, dev:false });
    else if (op && ver && op !== '!=') deps.push({ eco:'PyPI', name, spec:op + ver, file:path, dev:false });
    else { unpinned.push(name); deps.push({ eco:'PyPI', name, spec:'(any)', file:path, dev:false, noVersion:true }); }
  }
  if (unpinned.length)
    add(findings, { rule:'REQ-UNPINNED', sev:'low', title:'Dependencies without a version',
      why:'Unpinned packages install whatever is newest, including a malicious release published later. Pin exact versions.',
      file:path, snippet:sanitize(unpinned.slice(0, 12).join(', ') + (unpinned.length > 12 ? ' and ' + (unpinned.length - 12) + ' more' : '')) });
}

function analyzeMcp(path, text, findings){
  let j; try { j = JSON.parse(text); } catch { return; }
  const servers = j && (j.mcpServers || j.mcp_servers);
  if (!servers || typeof servers !== 'object') return;
  for (const [name, s] of Object.entries(servers)){
    if (!s || typeof s !== 'object') continue;
    if (typeof s.url === 'string'){
      add(findings, { rule:'MCP-SERVER', sev:'info', title:'MCP server declared',
        why:'Each MCP server adds tools the agent can call. Make sure you trust whoever runs it.',
        file:path, snippet:sanitize(name + ' (remote): ' + s.url.slice(0, 200)) });
      continue;
    }
    const args = Array.isArray(s.args) ? s.args.map(String) : [];
    const cmd = [String(s.command || ''), ...args].join(' ');
    const runner = basename(String(s.command || '')).toLowerCase();
    let sev = 'info', rule = 'MCP-SERVER', title = 'MCP server declared', why = 'Each MCP server adds tools the agent can call. Make sure you trust whoever runs it.';
    if (/curl|wget|\|\s*(?:ba)?sh|powershell|\beval\b|base64/i.test(cmd)){
      sev = 'high'; rule = 'MCP-SUSPICIOUS-CMD'; title = 'MCP server launched with a suspicious command';
      why = 'The launch command downloads or decodes something at start-up.';
    } else if (['npx','uvx','bunx','pipx'].includes(runner)){
      const pkg = args.find((a) => !a.startsWith('-')) || '';
      const bare = pkg.startsWith('@') ? pkg.slice(1) : pkg;
      if (pkg && !(/@\d/.test(bare) || /==\d/.test(pkg))){
        sev = 'medium'; rule = 'MCP-UNPINNED'; title = 'MCP server fetched from a registry without a pinned version';
        why = 'It downloads and runs the newest release every time it starts, so a compromised release reaches you automatically.';
      }
    }
    add(findings, { rule, sev, title, why, file:path, snippet:sanitize(name + ': ' + cmd.slice(0, 240)) });
  }
}

function typosquat(deps, findings){
  const seen = new Set();
  for (const d of deps){
    const list = POPULAR[d.eco]; if (!list) continue;
    const key = d.eco + ':' + d.name; if (seen.has(key)) continue; seen.add(key);
    const n = d.name.toLowerCase();
    if (n.length < 4 || list.includes(n)) continue;
    const norm = (s) => s.replace(/[_.]/g, '-');
    if (d.eco === 'PyPI' && list.some((p) => norm(p) === norm(n))) continue;
    const near = list.find((p) => p !== n && levenshtein(norm(n), norm(p)) === 1);
    if (near) add(findings, { rule:'DEP-TYPOSQUAT', sev:'medium', title:'Dependency name is one character away from a popular package',
      why:'Attackers publish packages with near-identical names hoping for a mistyped install. Confirm this is the package you intended.',
      file:d.file, snippet:sanitize(d.name + ' looks like ' + near) });
  }
}

async function osvLookup(deps, findings, notes){
  const uniq = new Map();
  for (const d of deps){
    if (d.noVersion) continue;
    const version = versionFrom(d.spec); if (!version) continue;
    d.version = version;
    d.approx = !/^==?\d/.test(d.spec) && !/^\d/.test(d.spec);
    uniq.set(d.eco + '|' + d.name + '|' + version, { package:{ name:d.name, ecosystem:d.eco }, version });
  }
  const keys = [...uniq.keys()].slice(0, 500);
  if (!keys.length) return;
  if (uniq.size > 500) notes.push('Only the first 500 dependency versions were checked against OSV.');
  let data;
  try {
    const res = await fetch('https://api.osv.dev/v1/querybatch', {
      method:'POST', headers:{ 'Content-Type':'application/json' },
      body: JSON.stringify({ queries: keys.map((k) => uniq.get(k)) }), signal: timeoutSignal(30000)
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    data = await res.json();
  } catch (e){
    if (net.controller.signal.aborted) throw new ScanError('Scan cancelled.');
    notes.push('The OSV.dev vulnerability lookup failed, so dependencies were not checked for known vulnerabilities.');
    return;
  }
  const hits = new Map();
  keys.forEach((k, i) => { const v = data.results && data.results[i] && data.results[i].vulns; if (v && v.length) hits.set(k, v.map((x) => x.id)); });
  for (const d of deps){
    if (!d.version) continue;
    const ids = hits.get(d.eco + '|' + d.name + '|' + d.version);
    if (!ids) continue;
    d.vulns = ids;
    const mal = ids.filter((id) => id.startsWith('MAL-'));
    const label = d.name + '@' + d.version + (d.approx ? ' (estimated from range ' + d.spec + ')' : '');
    if (mal.length) add(findings, { rule:'OSV-MALICIOUS', sev:'critical', title:'Dependency is on the known-malicious package list',
      why:'OSV lists this package version as malware. Do not install it.', file:d.file, snippet:sanitize(label + ' \u2192 ' + mal.join(', ')) });
    const vul = ids.filter((id) => !id.startsWith('MAL-'));
    if (vul.length) add(findings, { rule:'OSV-VULN', sev: d.dev ? 'low' : 'medium', title:'Dependency has known vulnerabilities',
      why:'Published advisories exist for this version. Many are minor, so open the OSV links to judge impact.',
      file:d.file, snippet:sanitize(label + ' \u2192 ' + vul.slice(0, 6).join(', ') + (vul.length > 6 ? ' and ' + (vul.length - 6) + ' more' : '')) });
  }
}

function repoSignals(repo, owner, contributors, findings){
  const age = daysSince(repo.created_at);
  if (age < 30) add(findings, { rule:'REPO-NEW', sev:'medium', title:'Repository is very new',
    why:'New repositories have no track record. Waiting, or checking who made it, lowers the risk.', snippet:'Created ' + Math.floor(age) + ' days ago (' + fmtDate(repo.created_at) + ').' });
  else if (age < 90) add(findings, { rule:'REPO-NEW', sev:'low', title:'Repository is fairly new',
    why:'New repositories have little history to judge.', snippet:'Created ' + Math.floor(age) + ' days ago (' + fmtDate(repo.created_at) + ').' });
  if (repo.stargazers_count >= 500 && age < 14) add(findings, { rule:'REPO-STARS', sev:'medium', title:'Many stars on a brand-new repository',
    why:'Sudden popularity can be real, but fake stars are also used to make malicious projects look trusted.', snippet:fmtNum(repo.stargazers_count) + ' stars in ' + Math.floor(age) + ' days.' });
  if (repo.fork) add(findings, { rule:'REPO-FORK', sev:'low', title:'This is a fork',
    why:'Forks can carry changes the original author never approved. Compare with the original.',
    snippet:'Forked from ' + sanitize(repo.parent && repo.parent.full_name ? repo.parent.full_name : 'another repository') + '.' });
  if (owner && owner.created_at && daysSince(owner.created_at) < 60) add(findings, { rule:'OWNER-NEW', sev:'medium', title:'Owner account is new',
    why:'Throwaway accounts are common in supply-chain attacks.', snippet:'Account created ' + fmtDate(owner.created_at) + '.' });
  if (!repo.license) add(findings, { rule:'REPO-NOLICENSE', sev:'low', title:'No license declared',
    why:'Without a license there is no stated permission to use the code, and it often signals a casual or unreviewed project.', snippet:'' });
  if (repo.archived) add(findings, { rule:'REPO-ARCHIVED', sev:'info', title:'Repository is archived',
    why:'Archived projects no longer receive security fixes.', snippet:'' });
  if (daysSince(repo.pushed_at) > 730) add(findings, { rule:'REPO-STALE', sev:'low', title:'No pushes in over two years',
    why:'Unmaintained code does not get security fixes.', snippet:'Last push ' + fmtDate(repo.pushed_at) + '.' });
  if (Array.isArray(contributors) && contributors.length === 1) add(findings, { rule:'REPO-SOLO', sev:'info', title:'Single contributor',
    why:'Nobody else has reviewed or changed this code, so a mistake or a bad update would go unnoticed.', snippet:'' });
}

/* ============================================================
   Scan pipeline
   ============================================================ */
function log(msg, cls){ const li = h('li', { class: cls || '', text: msg }); $('log').append(li); return li; }

async function runScan(){
  const parsed = parseRepo($('repo').value);
  const out = $('out'); out.hidden = true; out.replaceChildren();
  $('log').replaceChildren(); $('progress').textContent = ''; $('status').hidden = false;
  if (!parsed){ log('Enter a repository as owner/name or a github.com link.', 'err'); return; }
  const { owner, repo } = parsed;
  const token = $('token').value.trim();
  const refInput = $('ref').value.trim();
  if (refInput && !/^[\w./@+-]{1,200}$/.test(refInput)){ log('That branch, tag or commit contains characters that are not allowed.', 'err'); return; }

  const wantDeep = deepEnabled() && $('deep').checked;
  if (wantDeep && SITE.turnstileSiteKey && !tsToken){ log('Please wait a moment for the security check to finish, then press Scan again.', 'err'); return; }

  net.controller = new AbortController();
  $('go').disabled = true; $('cancel').hidden = false;
  const findings = [], deps = [], notes = [];
  try {
    log('Fetching repository details');
    const base = 'https://api.github.com/repos/' + owner + '/' + repo;
    const meta = await gh(base, token);
    const [ownerInfo, contributors] = await Promise.all([
      gh('https://api.github.com/users/' + owner, token).catch(() => null),
      gh(base + '/contributors?per_page=30', token).catch(() => null)
    ]);
    const ref = refInput || meta.default_branch;
    log('Resolving ' + ref + ' to a fixed commit');
    const commits = await gh(base + '/commits?sha=' + encodeURIComponent(ref) + '&per_page=10', token);
    if (!commits || !commits.length) throw new ScanError('The repository has no commits on ' + ref + '.');
    const sha = commits[0].sha;
    log('Listing files at commit ' + sha.slice(0, 7));
    const tree = await gh(base + '/git/trees/' + sha + '?recursive=1', token);
    if (tree.truncated) notes.push('The repository is very large and GitHub truncated the file list, so some files were never seen.');

    const blobs = tree.tree.filter((e) => e.type === 'blob');
    const cov = { total:blobs.length, scanned:0, lines:0, bytes:0, skipped:[], failed:[], unsupported:0 };
    const cands = [];
    const binHits = { exe:[], other:[], secret:[], maps:[] };
    for (const e of blobs){
      const path = e.path, b = basename(path), ext = extOf(path);
      if (/(?:^|\/)node_modules\//.test(path)){ cov.skipped.push(path + ' (node_modules)'); continue; }
      if (SECRET_NAMES.test(b)) binHits.secret.push(path);
      if (/\.(?:js|css|mjs)\.map$/i.test(b)){ binHits.maps.push(path); continue; }
      if (BIN_EXECUTABLE.has(ext)){ binHits.exe.push(path); continue; }
      if (BIN_OTHER.has(ext)){ binHits.other.push(path); continue; }
      if (LOCKFILES.test(b)){ cov.unsupported++; continue; }
      if (!SCAN_EXTS.has(ext)){ cov.unsupported++; continue; }
      if (e.size > LIMITS.fileBytes){ cov.skipped.push(path + ' (over ' + (LIMITS.fileBytes/1024) + ' KB)'); continue; }
      let prio = 3;
      if (/^(?:package\.json|setup\.py|pyproject\.toml|dockerfile|makefile)$/i.test(b) || /^requirements.*\.txt$/i.test(b) || /^\.github\/workflows\//.test(path) || /mcp/i.test(b)) prio = 0;
      else if (['sh','bash','zsh','ksh','ps1','psm1','bat','cmd'].includes(ext)) prio = 1;
      else if (GROUPS.CODE.has(ext)) prio = 2;
      cands.push({ path, size:e.size, prio });
    }
    cands.sort((a, b) => a.prio - b.prio || a.size - b.size);
    const picked = []; let bytes = 0;
    for (const c of cands){
      if (picked.length >= LIMITS.files || bytes + c.size > LIMITS.totalBytes){ cov.skipped.push(c.path + ' (scan limit reached)'); continue; }
      picked.push(c); bytes += c.size;
    }
    if (binHits.exe.length) add(findings, { rule:'BIN-EXEC', sev:'medium', title:'Compiled executables committed to the repository',
      why:'Binaries cannot be reviewed as source. Prefer repositories that build from source, or verify these files separately.', snippet:'', files:binHits.exe });
    if (binHits.other.length) add(findings, { rule:'BIN-OTHER', sev:'low', title:'Archives or bytecode committed to the repository',
      why:'These can contain code that is not visible in the scan.', snippet:'', files:binHits.other });
    if (binHits.maps.length) add(findings, { rule:'SOURCEMAP-COMMITTED', sev:'low', title:'Source maps committed to the repository',
      why:'Source maps publish the original source of the built app, and have exposed hidden keys and internal logic in the past. Remove them from production builds.', snippet:'', files:binHits.maps });
    if (binHits.secret.length) add(findings, { rule:'SECRET-FILE', sev:'medium', title:'Sensitive-looking files committed',
      why:'Key files and .env files in a repository are either leaked secrets or a sign of careless handling.', snippet:'', files:binHits.secret });

    log('Scanning ' + picked.length + ' files (the code is read as text and never executed)');
    const prog = $('progress');
    let done = 0;
    await pool(picked, LIMITS.concurrency, async (c) => {
      try {
        const text = await fetchRaw(owner, repo, sha, c.path);
        if (text.indexOf('\u0000') !== -1){ cov.skipped.push(c.path + ' (binary content)'); }
        else {
          cov.scanned++; cov.bytes += c.size; cov.lines += text.split('\n').length;
          scanText(c.path, text, findings);
          const b = basename(c.path), ext = extOf(c.path);
          if (b === 'package.json') analyzePackageJson(c.path, text, findings, deps);
          else if (/^requirements.*\.txt$/i.test(b)) analyzeRequirements(c.path, text, findings, deps);
          if (ext === 'json' && /"mcp(?:Servers|_servers)"/.test(text)) analyzeMcp(c.path, text, findings);
        }
      } catch (e){
        if (net.controller.signal.aborted) return;
        cov.failed.push(c.path);
      }
      done++; prog.textContent = done + ' of ' + picked.length + ' files read';
    });
    if (net.controller.signal.aborted) throw new ScanError('Scan cancelled.');
    if (cov.failed.length) notes.push(cov.failed.length + ' files could not be downloaded and were not scanned.');

    if (deps.length){
      log('Checking ' + deps.length + ' dependencies against OSV.dev');
      typosquat(deps, findings);
      await osvLookup(deps, findings, notes);
    }
    repoSignals(meta, ownerInfo, contributors, findings);
    log('Done');
    $('status').hidden = true;
    render({ owner, repo, ref, sha, meta, ownerInfo, contributors, commits, findings, deps, cov, notes, rate:net.rate });
    if (wantDeep) await runDeep({ owner, repo, sha });
  } catch (e){
    log(e instanceof ScanError ? e.message : 'Something went wrong while scanning: ' + (e && e.message ? e.message : 'unknown error'), 'err');
  } finally {
    $('go').disabled = false; $('cancel').hidden = true;
  }
}

/* ============================================================
   Rendering (all untrusted text goes through textContent)
   ============================================================ */
function verdictFor(counts, cov, notes){
  const partial = cov.skipped.length > 0 || cov.failed.length > 0 || notes.length > 0;
  const tail = partial ? ' Some files or checks were skipped, see Coverage below.' : '';
  if (counts.critical) return { cls:'critical', title:'Do not run this', text:'Critical indicators were found, such as malware signatures or reverse-shell code. Review the findings before doing anything with this repository.' + tail };
  if (counts.high) return { cls:'high', title:'High-risk patterns found', text:'Do not run this outside a sandbox until you have read the high-severity findings and confirmed they are legitimate.' + tail };
  if (counts.medium) return { cls:'medium', title:'Several items need a closer look', text:'Nothing alarming on its own, but review the medium findings and run it only in an isolated environment with throwaway credentials.' + tail };
  return { cls:'clear', title:'Nothing found by this quick scan', text:'No known risky patterns were detected. That is not proof of safety: this scan cannot see code fetched later, delayed payloads or heavy obfuscation. Keep using a sandbox and approval prompts.' + tail };
}

let activeFilter = null;
function applyFilter(){
  document.querySelectorAll('.group').forEach((g) => { g.hidden = !!activeFilter && g.dataset.sev !== activeFilter; });
  document.querySelectorAll('.tile').forEach((t) => t.setAttribute('aria-pressed', String(t.dataset.sev === activeFilter)));
}

function ghFileLink(owner, repo, sha, f){
  const url = 'https://github.com/' + owner + '/' + repo + '/blob/' + sha + '/' + encPath(f.file) + (f.line ? '#L' + f.line : '');
  return h('a', { class:'loc', href:url, target:'_blank', rel:'noopener noreferrer', text: sanitize(f.file) + (f.line ? ':' + f.line : '') });
}

function render(r){
  const { owner, repo, sha, findings, deps, cov, notes, meta } = r;
  const counts = Object.fromEntries(SEV.map((s) => [s, 0]));
  findings.forEach((f) => counts[f.sev]++);
  const v = verdictFor(counts, cov, notes);
  activeFilter = null;

  const out = $('out'); out.replaceChildren();
  out.append(h('div', { class:'verdict ' + v.cls, role:'status' }, h('h2', { text:v.title }), h('p', { text:v.text })));

  out.append(h('div', { class:'tiles' }, SEV.map((s) =>
    h('button', { type:'button', class:'tile ' + s, 'data-sev':s, 'aria-pressed':'false',
      onclick:() => { activeFilter = activeFilter === s ? null : s; applyFilter(); } },
      h('b', { text:String(counts[s]) }), h('span', { text:SEV_LABEL[s] })))));

  // Findings grouped by rule
  out.append(h('h2', { text:'Findings' }));
  if (!findings.length) out.append(h('p', { class:'empty', text:'No findings.' }));
  const groups = new Map();
  for (const f of findings){
    if (!groups.has(f.rule)) groups.set(f.rule, { rule:f.rule, title:f.title, why:f.why, sev:f.sev, items:[] });
    const g = groups.get(f.rule);
    if (SEV.indexOf(f.sev) < SEV.indexOf(g.sev)) g.sev = f.sev;
    g.items.push(f);
  }
  const ordered = [...groups.values()].sort((a, b) => SEV.indexOf(a.sev) - SEV.indexOf(b.sev) || b.items.length - a.items.length);
  for (const g of ordered){
    const shown = g.items.slice(0, LIMITS.shownPerGroup);
    const list = h('ul', null, shown.map((f) => {
      if (f.files){
        return h('li', null, h('div', { class:'loc pre-wrap', text: f.files.slice(0, 15).map(sanitize).join('\n') + (f.files.length > 15 ? '\n\u2026 and ' + (f.files.length - 15) + ' more' : '') }));
      }
      return h('li', null,
        f.file ? ghFileLink(owner, repo, sha, f) : null,
        f.snippet ? h('pre', { class:'snip', text:f.snippet }) : null);
    }));
    const total = g.items.reduce((n, f) => n + (f.files ? f.files.length : 1), 0);
    const body = h('div', { class:'gbody' }, h('p', { class:'why', text:g.why }), list,
      g.items.length > shown.length ? h('p', { class:'more', text:(g.items.length - shown.length) + ' more in the JSON report.' }) : null);
    const det = h('details', { class:'group', 'data-sev':g.sev },
      h('summary', null, h('span', { class:'badge ' + g.sev, text:SEV_LABEL[g.sev] }), h('span', { class:'t', text:g.title }),
        h('span', { class:'count', text: total + (total === 1 ? ' match' : ' matches') }), h('span', { class:'rid', text:g.rule })), body);
    if (SEV.indexOf(g.sev) <= 1) det.open = true;
    out.append(det);
  }

  // Deep scan slot (filled by runDeep)
  out.append(h('h2', { text:'Deep scan' }), h('div', { id:'deep-slot' }));
  setDeepSlot([h('p', { class:'empty', text: deepEnabled() ? 'Not run. Tick “Also run the deep scan” and scan again to add Semgrep, secret detection and dependency audits.' : 'The deep scan is not enabled on this site.' })]);

  // Repository facts
  const dd = (k, val) => [h('dt', { text:k }), h('dd', { text:String(val) })];
  out.append(h('h2', { text:'Repository' }));
  out.append(h('div', { class:'panel flush' }, h('dl', { class:'facts' },
    dd('Name', owner + '/' + repo),
    dd('Scanned commit', sha + ' on ' + r.ref),
    dd('Created', fmtDate(meta.created_at)),
    dd('Last push', fmtDate(meta.pushed_at)),
    dd('Stars and forks', fmtNum(meta.stargazers_count) + ' stars, ' + fmtNum(meta.forks_count) + ' forks'),
    dd('License', meta.license && meta.license.spdx_id ? meta.license.spdx_id : 'None declared'),
    dd('Contributors', Array.isArray(r.contributors) ? (r.contributors.length >= 30 ? '30 or more' : r.contributors.length) : 'Unknown'),
    dd('Owner account', r.ownerInfo ? (r.ownerInfo.type + ', created ' + fmtDate(r.ownerInfo.created_at)) : 'Unknown'),
    dd('Recent commits', r.commits.slice(0, 5).map((c) => fmtDate(c.commit.author && c.commit.author.date) + ' ' + sanitize(((c.commit.author && c.commit.author.name) || 'unknown').slice(0, 40)) + ': ' + sanitize((c.commit.message || '').split('\n')[0].slice(0, 80))).join('\n')))));

  // Dependencies
  if (deps.length){
    out.append(h('h2', { text:'Dependencies' }));
    const rows = deps.slice(0, 300).map((d) => h('tr', null,
      h('td', { class:'mono', text:sanitize(d.name) }), h('td', { text:d.eco }),
      h('td', { class:'mono', text:sanitize(d.spec.slice(0, 40)) }), h('td', { text:d.dev ? 'dev' : 'runtime' }),
      h('td', null, d.vulns ? d.vulns.slice(0, 4).map((id, i) => [i ? ' ' : '', /^[A-Za-z0-9._:-]+$/.test(id) ? h('a', { href:'https://osv.dev/vulnerability/' + encodeURIComponent(id), target:'_blank', rel:'noopener noreferrer', text:id }) : h('span', { text:'?' })]) : (d.noVersion ? 'not checked (no version)' : (d.version ? 'none known' : 'not checked')))));
    out.append(h('div', { class:'panel scroll flush' }, h('table', null,
      h('thead', null, h('tr', null, ['Package','Ecosystem','Version','Scope','Known advisories'].map((t) => h('th', { text:t })))), h('tbody', null, rows))));
    if (deps.length > 300) out.append(h('p', { class:'more', text:'Showing the first 300 of ' + deps.length + ' dependencies.' }));
  }

  // Coverage
  out.append(h('h2', { text:'Coverage' }));
  const covList = h('ul', { class:'notes' },
    h('li', { text: cov.scanned + ' of ' + fmtNum(cov.total) + ' files were read (' + fmtNum(cov.lines) + ' lines). ' + fmtNum(cov.unsupported) + ' files were skipped because their type is not scanned (images, lockfiles and similar).' }),
    cov.skipped.length ? h('li', { text: cov.skipped.length + ' scannable files were skipped. Examples: ' + cov.skipped.slice(0, 4).map(sanitize).join('; ') + '.' }) : null,
    notes.map((n) => h('li', { text:n })),
    h('li', { text:'Only package.json and requirements files are parsed for dependencies in this version. Lockfiles, pyproject.toml, Cargo and Go modules are not.' }),
    r.rate ? h('li', { text:'GitHub API requests left this hour: ' + r.rate.remaining + ' of ' + r.rate.limit + '.' }) : null);
  out.append(covList);

  // Export
  r.counts = counts; r.deep = null; current = r;
  out.append(h('p', null, h('button', { type:'button', class:'ghost', text:'Download JSON report', onclick:downloadReport })));

  out.hidden = false;
  out.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block:'start' });
}

/* ============================================================
   Report export
   ============================================================ */
let current = null;
function downloadReport(){
  const r = current; if (!r) return;
  const { owner, repo, sha, findings, deps, cov, notes, counts } = r;
  const report = { tool:'agent-audit v0.2', scannedAt:new Date().toISOString(), repository:owner + '/' + repo, commit:sha, ref:r.ref,
    summary:counts, coverage:{ filesInRepo:cov.total, filesScanned:cov.scanned, skipped:cov.skipped, failed:cov.failed, notes },
    findings:findings.map((f) => ({ rule:f.rule, severity:f.sev, title:f.title, file:f.file, line:f.line, snippet:f.snippet, files:f.files })),
    dependencies:deps.map((d) => ({ name:d.name, ecosystem:d.eco, spec:d.spec, version:d.version || null, scope:d.dev ? 'dev' : 'runtime', file:d.file, advisories:d.vulns || [] })),
    deepScan:r.deep };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type:'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'agent-audit-' + owner + '-' + repo + '.json';
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

/* ============================================================
   Deep scan: asks the scan service (a Cloudflare Worker) to start
   the GitHub job, waits for the result, then shows the report
   ============================================================ */
const DEEP = { pollMs:5000, maxMs:25*60*1000 };
const TOOL_TITLES = {
  semgrep:'Semgrep code analysis',
  secrets:'Secret detection',
  pip_audit:'Python dependency audit',
  npm_audit:'npm dependency audit',
  osv_malicious:'Known malicious packages (OSV)',
  registry:'Dependencies missing from the registry'
};
const SITE = (() => {
  const c = (typeof window !== 'undefined' && window.AGENT_AUDIT_CONFIG) || {};
  let api = '';
  try { const u = new URL(String(c.apiUrl || '')); if (u.protocol === 'https:') api = u.origin; } catch (e) { /* not configured */ }
  return { api, turnstileSiteKey: /^[0-9A-Za-z_-]{10,80}$/.test(String(c.turnstileSiteKey || '')) ? String(c.turnstileSiteKey) : '' };
})();
const deepEnabled = () => !!SITE.api;
const sleep = (ms) => new Promise((resolve, reject) => {
  const t = setTimeout(resolve, ms);
  net.controller.signal.addEventListener('abort', () => { clearTimeout(t); reject(new ScanError('Scan cancelled.')); }, { once:true });
});
function setDeepSlot(nodes){ const el = $('deep-slot'); if (el) el.replaceChildren(...nodes); }
function deepStatus(msg){ setDeepSlot([h('div', { class:'deep-line' }, h('span', { text:msg }))]); }

/* Cloudflare Turnstile: a free check that the visitor is not a bot. */
let tsToken = null, tsWidget = null;
function setupTurnstile(){
  if (!SITE.turnstileSiteKey || !deepEnabled()) return;
  const s = document.createElement('script');
  s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
  s.async = true;
  s.onload = () => {
    if (!window.turnstile) return;
    tsWidget = window.turnstile.render('#ts-box', {
      sitekey: SITE.turnstileSiteKey,
      callback: (t) => { tsToken = t; },
      'expired-callback': () => { tsToken = null; },
      'error-callback': () => { tsToken = null; }
    });
  };
  document.head.append(s);
}
function resetTurnstile(){ tsToken = null; try { if (window.turnstile && tsWidget !== null) window.turnstile.reset(tsWidget); } catch (e) { /* ignore */ } }

async function api(path, init){
  let res;
  try { res = await fetch(SITE.api + path, Object.assign({ signal: timeoutSignal(30000), cache:'no-store' }, init || {})); }
  catch (e){
    if (net.controller.signal.aborted) throw new ScanError('Scan cancelled.');
    throw new ScanError('Could not reach the scan service. Try again in a moment.');
  }
  let data = null; try { data = await res.json(); } catch (e) { /* not JSON */ }
  if (!res.ok){
    const msg = data && typeof data.error === 'string' ? data.error.slice(0, 240) : 'The scan service returned an error (' + res.status + ').';
    throw new ScanError(msg);
  }
  return data || {};
}

async function runDeep({ owner, repo, sha }){
  try {
    deepStatus('Starting the deep scan');
    const token = tsToken;
    resetTurnstile();
    const start = await api('/scan', { method:'POST', headers:{ 'Content-Type':'application/json' },
      body: JSON.stringify({ repo: owner + '/' + repo, commit: sha, turnstile: token || undefined }) });
    if (typeof start.jobId !== 'string' || !/^r[0-9a-f]{20}$/.test(start.jobId)) throw new ScanError('The scan service sent an unexpected answer.');
    const began = Date.now();
    let result = start.status === 'done' ? await api('/result/' + start.jobId) : null;
    while (!result || result.status === 'pending'){
      if (Date.now() - began > DEEP.maxMs) throw new ScanError('The deep scan is taking longer than ' + Math.round(DEEP.maxMs / 60000) + ' minutes. Please try again later.');
      const secs = Math.round((Date.now() - began) / 1000);
      deepStatus((start.cached ? 'Joining a scan already in progress' : 'Scanning on GitHub') + ' (' + secs + 's). You can keep reading the quick results meanwhile.');
      await sleep(DEEP.pollMs);
      result = await api('/result/' + start.jobId);
    }
    if (result.status === 'failed') throw new ScanError(String(result.message || 'The deep scan did not complete.').slice(0, 240));
    const report = result.report;
    if (!report || report.schema !== 1 || typeof report.tools !== 'object') throw new ScanError('The report has an unexpected format.');
    if (current) current.deep = report;
    renderDeep(report, owner, repo, sha, null);
  } catch (e){
    const msg = e instanceof ScanError ? e.message : 'The deep scan failed: ' + (e && e.message ? e.message : 'unknown error');
    setDeepSlot([h('p', { class:'empty err-text', text:msg })]);
  }
}

function renderDeep(report, owner, repo, sha, runUrl){
  const slot = [];
  const sevOf = (s) => SEV.includes(s) ? s : 'info';
  const counts = Object.fromEntries(SEV.map((s) => [s, 0]));
  const tools = Object.keys(TOOL_TITLES).filter((k) => report.tools[k] && typeof report.tools[k] === 'object');
  for (const k of tools) for (const f of (Array.isArray(report.tools[k].findings) ? report.tools[k].findings : [])) counts[sevOf(f.severity)]++;
  const commit = typeof report.commit === 'string' && /^[0-9a-f]{40}$/.test(report.commit) ? report.commit : sha;
  const summary = SEV.filter((s) => counts[s]).map((s) => counts[s] + ' ' + SEV_LABEL[s].toLowerCase()).join(', ') || 'no findings';
  slot.push(h('div', { class:'deep-line' },
    h('span', { text:'Deep scan finished at commit ' + commit.slice(0, 7) + ': ' + summary + '.' }),
    /^https:\/\/github\.com\//.test(runUrl || '') ? h('a', { href:runUrl, target:'_blank', rel:'noopener noreferrer', text:'View the run' }) : null));

  for (const k of tools){
    const t = report.tools[k];
    const items = Array.isArray(t.findings) ? t.findings : [];
    let top = 'info';
    for (const f of items) if (SEV.indexOf(sevOf(f.severity)) < SEV.indexOf(top)) top = sevOf(f.severity);
    const shown = items.slice(0, 30);
    const body = h('div', { class:'gbody' });
    if (t.note) body.append(h('p', { class:'why', text:sanitize(String(t.note).slice(0, 300)) }));
    if (t.ok === false) body.append(h('p', { class:'why err-soft', text:'This tool did not complete: ' + sanitize(String(t.error || 'unknown error').slice(0, 300)) }));
    else if (!items.length) body.append(h('p', { class:'why', text:'Nothing found.' }));
    if (shown.length) body.append(h('ul', null, shown.map((f) => {
      const file = typeof f.file === 'string' && f.file ? f.file : null;
      const line = Number.isInteger(f.line) && f.line > 0 ? f.line : null;
      return h('li', null,
        file ? ghFileLink(owner, repo, commit, { file, line }) : null,
        h('pre', { class:'snip', text:sanitize(((f.rule ? String(f.rule).slice(-90) + ': ' : '') + String(f.message || '')).slice(0, 400)) }));
    })));
    if (items.length > shown.length) body.append(h('p', { class:'more', text:(items.length - shown.length) + ' more in the JSON report.' }));
    const ok = t.ok !== false;
    const det = h('details', { class:'group' },
      h('summary', null,
        h('span', { class:'badge ' + (ok ? (items.length ? top : 'info') : 'high'), text: ok ? (items.length ? SEV_LABEL[top] : 'Clear') : 'Error' }),
        h('span', { class:'t', text:TOOL_TITLES[k] }),
        h('span', { class:'count', text: ok ? items.length + (items.length === 1 ? ' finding' : ' findings') : 'incomplete' })),
      body);
    if (items.length && SEV.indexOf(top) <= 1) det.open = true;
    slot.push(det);
  }
  if (Array.isArray(report.notes)) for (const n of report.notes.slice(0, 10)) slot.push(h('p', { class:'more', text:sanitize(String(n).slice(0, 300)) }));
  setDeepSlot(slot);
}

/* ============================================================
   Wiring
   ============================================================ */
$('scan-form').addEventListener('submit', (e) => { e.preventDefault(); if (!$('go').disabled) runScan(); });
$('cancel').addEventListener('click', () => { if (net.controller) net.controller.abort(); });
try {
  const q = new URLSearchParams(location.search).get('repo');
  if (q && q.length < 200) $('repo').value = q;
} catch (e) { /* ignore */ }
if (!deepEnabled()) $('deep').checked = false;
$('deep-row').hidden = !deepEnabled();
setupTurnstile();
