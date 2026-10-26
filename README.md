# Agent Audit

A public website where anyone can paste a GitHub repository link and get a security scan of it. Built for
checking AI agents and plugins before running them. Visitors only paste a link: no accounts, no tokens.
The scan reads code as text and never runs it.

## How it works

```
Visitor's browser                      Your Cloudflare Worker                 GitHub
-----------------                      ----------------------                 ------
1. Pastes a repo link
2. Quick scan runs in the browser
3. Asks for a deep scan  ------------> checks CAPTCHA, limits, repo is public
                                       starts the scan job  ---------------> scan.yml runs
                                       (token is kept here, secret)           Semgrep, secrets, audits
4. Polls for the result  <------------ keeps result for 24 hours  <---------- posts signed report
5. Shows the report
```

The GitHub token never reaches the visitor. It lives only in the Worker, and it can do one thing: start
`scan.yml` in your scanner repository.

## What is the Cloudflare Worker?

A Worker is a tiny program that Cloudflare runs for you on its servers, so you do not rent or maintain a server of your own.
Here it is the "front desk" between the public page and GitHub. Your page is only files, and files cannot keep a secret.
The Worker can: it holds the GitHub token, checks every request (bot check, rate limits, public repository), starts the scan job
on GitHub, and hands the finished report back to the page. Visitors only ever talk to the Worker, never to GitHub with your credentials.
The free plan is enough to start.

## What is in this folder

| Path | Purpose |
| --- | --- |
| `index.html`, `styles.css`, `rules.js`, `app.js` | The scanner page and quick scan (edit `rules.js` to tune detection) |
| `config.js` | Two public settings: your Worker address and your Turnstile site key |
| `.github/workflows/scan.yml` | The deep scan job that runs on GitHub's servers |
| `scripts/deep_scan.py`, `scripts/requirements.txt` | What the job runs, with pinned tool versions |
| `worker/` | The small Cloudflare Worker that starts jobs for visitors |
| `.gitignore`, `.github/dependabot.yml` | Keep secrets out of git, and get weekly update pull requests for the workflow and tool versions |

## Setup (about 30 minutes, all free)

### A. Put the page on GitHub
1. Create a **public** GitHub repository, for example `agent-audit`, and upload everything in this folder, keeping the
   folder structure. The `.github` folder must be at the top level.
2. **Settings > Pages**, choose *Deploy from a branch*, branch `main`, folder `/ (root)`.
   Your site will be at `https://YOUR-NAME.github.io/agent-audit/`.
3. Open the **Actions** tab and enable workflows if GitHub asks.

### B. Make a token for the Worker
**Profile > Settings > Developer settings > Personal access tokens > Fine-grained tokens > Generate new token**
- Repository access: *Only select repositories*, then your scanner repository.
- Permissions: **Actions: Read and write**. Nothing else.
- Expiration: choose **No expiration** if your scanner repository is in your personal account, so you never have to renew it.
  If the repository belongs to an organization, the organization may cap tokens at 366 days. In that case pick the longest
  allowed and set a reminder.

A token that never expires is worth more to a thief, so keep its reach tiny: one repository, Actions only. It lives only as a
Cloudflare secret, never in a file or in the page.

Copy the token. You will paste it into Cloudflare in step C.

### C. Deploy the Worker
1. Create a free Cloudflare account and install Node.js.
2. In the `worker` folder, run these commands:
   ```
   npx wrangler login
   npx wrangler kv namespace create SCANS
   ```
   Copy the `id` it prints into `wrangler.toml`.
3. In `wrangler.toml`, set `ALLOWED_ORIGIN` to `https://YOUR-NAME.github.io` (no path, no trailing slash) and
   `SCANNER_REPO` to `YOUR-NAME/agent-audit`.
4. Make a shared secret (any long random text, for example the output of `openssl rand -hex 32`), then store the secrets:
   ```
   npx wrangler secret put GITHUB_TOKEN        (paste the token from step B)
   npx wrangler secret put CALLBACK_SECRET     (paste your random text)
   ```
5. Deploy: `npx wrangler deploy`. It prints your Worker address, such as `https://agent-audit-api.YOUR-NAME.workers.dev`.

### D. Add the bot check (Turnstile)
1. In the Cloudflare dashboard, open **Turnstile > Add widget**. Hostname: `YOUR-NAME.github.io`. Mode: *Managed*.
2. Copy the **secret key** into the Worker: `npx wrangler secret put TURNSTILE_SECRET`
3. Copy the **site key** for step F.

Do not skip this for a public site. Without it, bots can use up your scan limits.

### E. Connect GitHub Actions to the Worker
In your scanner repository, **Settings > Secrets and variables > Actions**:
- **Secrets** tab: new secret `CALLBACK_SECRET`, with the same random text you used in step C.
- **Variables** tab: new variable `SCAN_API_URL`, set to your Worker address (no trailing slash, no path).

### F. Tell the page where the Worker is
Edit `config.js` and set `apiUrl` to your Worker address and `turnstileSiteKey` to the site key. Commit the change.
Wait a minute for Pages to update, then open your site and scan a small repository.

### G. Turn on GitHub's own protections
In your scanner repository, **Settings > Code security**: enable **Secret scanning**, **Push protection** and **Dependabot alerts**.
Push protection stops you from accidentally committing a token.

### H. Add a rate limit for result polling
In the Cloudflare dashboard, open your domain or Worker's **Security > WAF > Rate limiting rules** and add a rule:
when the URI path starts with `/result/`, limit each IP to about 20 requests per 10 seconds (the page asks once every 5 seconds).
This protects the part of the Worker that the built-in limits do not cover.

### I. Tighten the page's connection rule (recommended)
`index.html` allows connections to `https://*.workers.dev` so that setup works the first time. Once the site works, replace that
with your exact Worker address, for example `https://agent-audit-api.YOUR-NAME.workers.dev`, in the `Content-Security-Policy` line.

## Protections for public use

- Cloudflare Turnstile blocks automated abuse.
- Each visitor gets 6 requests per hour, and the whole site starts at most 60 new jobs per hour. Change both in
  `LIMITS` at the top of `worker/src/index.js`.
- Only public repositories under about 500 MB are accepted.
- A commit that was already scanned in the last 24 hours reuses the stored result, and duplicate requests share one job.
- The token can only start this one workflow, and the workflow only analyses the target as text.
- Reports are posted back with an HMAC signature, each job id works once, and a report must match its job.
- The Worker only answers browsers from your own site.

## Security checklist: the 17 common weaknesses in AI-generated apps

How this project handles each one, and whether its scanner can look for it in other people's repositories.

| # | Weakness | How this site handles it | Does the scanner check for it? |
| --- | --- | --- | --- |
| 1 | Database without Row Level Security | There is no database. The only storage (Cloudflare KV) is reachable only through the Worker. | Yes, for SQL files (`SUPABASE-RLS`), plus Semgrep |
| 2 | Unprotected API routes | `/scan` needs an allowed site, the bot check and rate limits. `/callback` needs a valid signature. `/result` needs an unguessable id. | No. Missing authentication needs a human review |
| 3 | Committed or publicly served secrets | No secrets in the repository. Tokens live only in Cloudflare and GitHub secret stores. `.gitignore` and push protection help. | Yes: committed key files, key patterns, detect-secrets, Semgrep |
| 4 | Broken access control (IDOR) | No accounts or user data. Job ids are random 80-bit values and results cannot be listed. | No. Needs a human review |
| 5 | Secret keys and source maps in frontend code | `config.js` holds only public values (Worker address, Turnstile site key). No source maps are published. | Yes: key patterns, secrets in public frontend variables, committed source maps |
| 6 | SSRF | The Worker and the job contact fixed hosts only. Repository names and commits are checked against strict patterns first. | Yes (`SSRF-USERURL`) |
| 7 | Missing CSRF protection | There are no cookies or logins to hijack. `/scan` also needs JSON, an allowed Origin and the bot check. | Yes, as a hint (`APP-NOCSRF`) |
| 8 | Missing or weak security headers | The page has a strict policy: scripts and styles only from this site, no inline code, no framing. The Worker sends nosniff, CSP and HSTS. | Yes, as a hint (`APP-NOHEADERS`) |
| 9 | Wildcard CORS | The Worker answers only your own site's origin. | Yes (`CORS-WILDCARD`) |
| 10 | No rate limiting | Per-visitor and site-wide limits, the bot check, and a Cloudflare rule for polling (step H). | Yes, as a hint (`APP-NORATELIMIT`) |
| 11 | SQL injection | There is no SQL anywhere. | Yes (`SQLI-JS`, `SQLI-PY`), plus Semgrep |
| 12 | Cross-site scripting | All untrusted text is shown with `textContent`, invisible characters are made visible, links are built from validated parts, and the policy blocks inline scripts. | Yes (`XSS-SINK`, `XSS-PY`) |
| 13 | Unverified webhooks | The job's report to the Worker is HMAC-signed, compared in constant time, single-use, and must match its job. | Yes for Stripe (`STRIPE-NOVERIFY`) |
| 14 | Insecure file uploads | The site accepts no uploads. | No |
| 15 | Verbose errors and debug endpoints | The Worker returns generic errors and keeps details in its private logs. There are no debug endpoints. | Yes (`DEBUG-EXPOSED`) |
| 16 | Weak password hashing | There are no passwords. | Yes (`WEAK-HASH`) |
| 17 | Hallucinated packages (slopsquatting) | The job installs only pinned tools, and Dependabot proposes updates weekly. | Yes: the deep scan flags dependencies missing from npm or PyPI, plus the typo check and the OSV malware list |

Scanner results marked "hint" are heuristics. They look at one file at a time, so a protection kept in a different file can trigger a false alarm.
GitHub Pages cannot send custom HTTP headers, so the page uses a policy tag and an anti-framing script instead. If you later put your own domain
behind Cloudflare, you can add the full set of headers there.

## Limits to know about

- Cloudflare's free plan allows about 1,000 KV writes a day. Each new scan uses about 5, so roughly 200 new scans a day.
  Repeat scans of the same commit use no new jobs.
- GitHub Actions is free for public repositories on standard runners, but GitHub limits how many jobs run at once.
  At busy times, scans queue.
- A clean result means nothing was found, not that the code is safe.

## Privacy

- The repository link and commit are sent to your Worker, and results are deleted after 24 hours.
- Because the scanner repository is public, its Actions logs can show which repositories were scanned.
- Reports are not saved in your repository.
- The Worker uses visitor IP addresses only for hourly rate limits, which expire after an hour.

## Troubleshooting

| What you see | What to check |
| --- | --- |
| "Could not start the deep scan right now" | The `GITHUB_TOKEN` secret is wrong or expired, or `SCANNER_REPO` or `SCANNER_BRANCH` is wrong |
| The scan stays on "Scanning on GitHub" | Open your scanner repository's Actions tab and read the failed run |
| The run fails at "Post the result" | `SCAN_API_URL` or `CALLBACK_SECRET` is missing, or the secret differs from the Worker's |
| No browser error text, requests blocked | `ALLOWED_ORIGIN` must match your site exactly, for example `https://name.github.io` |
| The security check never appears | The site key in `config.js` is wrong, or the hostname is not registered in Turnstile |
| You use a custom Worker domain | Add it to `connect-src` in the `Content-Security-Policy` line of `index.html` |

To test the Worker logic without deploying, run `node test.mjs` inside `worker/`. To preview the page locally, run
`python3 -m http.server` in this folder and open `http://localhost:8000`.

## Maintenance

- Merge Dependabot's weekly pull requests after a quick look. They update the workflow's actions and the pinned tools.
- If your GitHub token has an expiry, renew it before then: create a new one and run `npx wrangler secret put GITHUB_TOKEN`
  in the `worker` folder. No redeploy is needed. Once a year, review your tokens on GitHub and revoke any you no longer use.
- Nothing else expires: the callback secret and the Turnstile keys stay valid until you change them.
- Update the pinned tool versions in `scripts/requirements.txt` now and then, after reading their release notes.
