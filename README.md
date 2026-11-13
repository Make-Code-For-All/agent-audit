# Agent Audit

**Scan a GitHub repository before your AI agent runs it.**

Agent Audit is a free web page that reads a public GitHub repository and reports risky code, suspicious dependencies and repository red flags. It reads every file and executes none of them. You don't need to sign in or supply a GitHub token.

**Live site:** https://make-code-for-all.github.io/agent-audit/

**Source:** https://github.com/Make-Code-For-All/agent-audit

---

## Using the web page

1. Open https://make-code-for-all.github.io/agent-audit/
2. Paste a public repository link, for example `https://github.com/owner/name`.
   To scan a single branch, paste the branch link instead: `https://github.com/owner/name/tree/branch`.
3. Optionally tick **Include deep scan** (Semgrep, secret detection and dependency audits; adds a few minutes).
4. Click **Scan repository** and read the report. Findings are grouped by severity (Critical, High, Medium, Low, Info) and can be filtered by category (Code, Dependencies, Repository). Each finding links to the file and line on GitHub. You can download the full report.

> **A clean result is not proof of safety.** The scan cannot see code that is downloaded after install, payloads that activate later, or heavily obfuscated logic. Keep using a sandbox and approval prompts.

## What it checks

| Area | Examples |
| --- | --- |
| **Risky code** | `curl \| sh` and PowerShell download-and-execute, reverse shells, destructive commands, decode-then-execute obfuscation, unsafe deserialization, credential file access, exfiltration endpoints, persistence tricks, hidden Unicode characters, and text aimed at AI reviewers (prompt injection) |
| **Dependencies** | npm (`package.json`) and PyPI (`requirements*.txt`) packages checked against [OSV.dev](https://osv.dev), including its known-malicious list, plus names that look like typos of popular packages (typosquatting) |
| **MCP configs** | MCP server configuration files that launch risky commands |
| **Repository signals** | New repositories and owner accounts, sudden star counts, forks, a missing licence, committed binaries, and secret-looking files (`.env`, private keys, `credentials.json`, …) |
| **Deep scan** (optional) | Semgrep code analysis, `detect-secrets`, `pip-audit`, npm audit, OSV malicious-package lookup, and a check for dependencies that don't exist on their registry (a sign of AI-invented, "slopsquattable" names) |

## How it works

```
 Browser (GitHub Pages)                 Cloudflare Worker                 GitHub
 ──────────────────────                 ─────────────────                 ──────
 index.html + app.js ── GET /repo ────▶ agent-audit-api ──────────────▶ REST API
                     ── GET /archive ─▶ (holds the token) ────────────▶ codeload .tar.gz
   streams + unpacks the tarball in the browser (tar.js),
   runs rules.js line by line, queries OSV.dev directly

 Deep scan (optional)
                     ── POST /scan ───▶ dispatches workflow ──────────▶ Actions: scan.yml
                     ◀─ GET /result ── KV store (24 h TTL) ◀─ HMAC-signed callback ─┘
```

- **Quick scan (in your browser).** The Worker fetches repository metadata and the repository as one `.tar.gz` archive. The page streams and unpacks the archive in the browser and checks each text file against the rules in `rules.js`. Everything is treated as hostile text: shown as plain text, never executed.
- **Deep scan (on GitHub's servers).** The Worker starts the `Deep scan` workflow. Its first job clones the target with git hooks disabled, runs the analysis tools in static modes only and has **no secrets**. A second job, which never touches the scanned code, signs the report with HMAC and posts it back to the Worker. Results are kept in Cloudflare KV for 24 hours and then deleted.

## Repository layout

| Path | Purpose |
| --- | --- |
| `index.html` | The scanner page (strict Content Security Policy, no inline scripts or styles) |
| `styles.css` | Page styles |
| `config.js` | Public settings: the Worker URL and the Turnstile site key. Never put secrets here. |
| `rules.js` | Detection rules, popular-package lists for typosquat checks, and file-type groups. **Edit this file to add or tune rules.** |
| `app.js` | Scanner logic, the GitHub, OSV and Worker calls, and report rendering |
| `tar.js` | Streaming `.tar.gz` reader, so repositories of any size are read without loading them fully into memory |
| `worker/` | Cloudflare Worker (`agent-audit-api`) that proxies GitHub, starts deep scans and stores results |
| `worker/test.mjs` | Tests for the Worker, with GitHub and KV mocked |
| `scripts/deep_scan.py` | The deep scan, run by GitHub Actions |
| `scripts/requirements.txt` | Pinned versions of the deep-scan tools (Semgrep, pip-audit, detect-secrets) |
| `.github/workflows/scan.yml` | The `Deep scan` workflow (`workflow_dispatch`) |
| `.github/dependabot.yml` | Weekly updates for Actions and the pinned scan tools |

## Running locally

The page is plain static HTML and JavaScript with no build step. Serve the repository root with any static server:

```bash
python -m http.server 8000
```

Then open http://localhost:8000. `config.js` points at the production Worker, which only accepts requests from the origin listed in `ALLOWED_ORIGIN`. To develop locally, run your own Worker (below), set `apiUrl` in `config.js` to its address, and add `http://localhost:8000` to `ALLOWED_ORIGIN`. Leave `apiUrl` empty to run without the Worker.

Run the Worker tests (Node 18+):

```bash
cd worker && node test.mjs
```

## Deploying your own copy

1. **Fork** this repository and enable **GitHub Pages** (serve from the `main` branch, root folder).
2. **Worker:** in `worker/wrangler.toml`, set `ALLOWED_ORIGIN` to your Pages origin and `SCANNER_REPO` to your fork. Create a KV namespace and paste its id. Then set the secrets:
   ```bash
   cd worker
   npx wrangler kv namespace create SCANS
   npx wrangler secret put GITHUB_TOKEN
   npx wrangler secret put CALLBACK_SECRET
   npx wrangler secret put TURNSTILE_SECRET
   npx wrangler deploy
   ```
   `GITHUB_TOKEN` is a fine-grained token for your fork with **Actions: read and write**. `CALLBACK_SECRET` is any long random string.
3. **Actions:** in your fork's settings, add the repository **variable** `SCAN_API_URL` (your Worker's `https://…workers.dev` address) and the repository **secret** `CALLBACK_SECRET` (the same value as the Worker's).
4. **Page:** in `config.js`, set `apiUrl` to your Worker address and `turnstileSiteKey` to your Cloudflare Turnstile site key.

Rate limits and size caps (requests per visitor per hour, scans per hour, maximum repository size) are in the `LIMITS` object at the top of `worker/src/index.js`.

## Contributing

Contributions are welcome: new detection rules, fewer false positives, UI improvements, documentation and bug reports.

1. **Open an issue** at https://github.com/Make-Code-For-All/agent-audit/issues to report a bug, a false positive or negative, or to propose a feature.
2. **Fork** the repository and create a branch from `main`:
   ```bash
   git checkout -b my-change
   ```
3. **Make your change.**
   - *New or tuned detection rules:* edit `rules.js`. Each rule needs an `id`, a `sev` (`critical`, `high`, `medium`, `low` or `info`), a `title`, a plain-language `why`, and a `re` regular expression that is matched one line at a time. Scope it with `in` or `exts` where possible, to keep false positives down.
   - *Worker changes:* update `worker/src/index.js` and add a case to `worker/test.mjs`. Run `node test.mjs` and make sure every test passes.
   - *Deep scan changes:* `scripts/deep_scan.py` must never execute or import code from the target repository, and must start every external command from an argument list, never through a shell.
4. **Test it.** Serve the page locally and scan a few real repositories, including one that should trigger your change and one that shouldn't.
5. **Open a pull request** against `main` with a short description of what changed and why. Include an example repository or snippet for rule changes.

### Ground rules

- **Never run scanned code.** Everything from a target repository is untrusted data. Render it with `textContent`, never `innerHTML`, and never `eval` it.
- **Keep the CSP strict.** Don't add inline scripts or styles, or new third-party origins, without a good reason.
- **No secrets in the front end.** `config.js` and everything else served by Pages is public.
- **Pin tool versions** in `scripts/requirements.txt` and in workflow actions. Dependabot keeps them current.
- Keep findings plain-spoken: say what the code does and why it matters, for someone who isn't a security expert.

### Security issues

If you find a way to make the scanner itself execute code, leak secrets, or be abused, don't open a public issue. Report it privately through GitHub's **Security → Report a vulnerability** on this repository.
