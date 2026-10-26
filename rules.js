'use strict';
/* Agent Audit: detection rules and static data.
   Edit this file to add or tune rules. Loaded by index.html before app.js. */

/* ============================================================
   Detection rules
   Each rule is checked against one line at a time.
   in: file groups the rule applies to (default CODE + CONF)
   docSev: if set, the rule also applies to docs at this severity
   ============================================================ */
const GROUPS = {
  CODE: new Set(['js','mjs','cjs','ts','jsx','tsx','vue','svelte','py','pyw','sh','bash','zsh','ksh','ps1','psm1','bat','cmd','rb','go','rs','php','pl','lua','java','kt']),
  CONF: new Set(['json','yml','yaml','toml','cfg','ini','dockerfile','makefile','sql']),
  DOC:  new Set(['md','txt','html','htm'])
};
const JS_EXTS = ['js','mjs','cjs','ts','jsx','tsx','vue','svelte','html','htm'];
const PY_EXTS = ['py','pyw'];
const SHELLY  = ['sh','bash','zsh','ksh','yml','yaml','dockerfile','makefile'];
const ALL = ['CODE','CONF','DOC'];

const RULES = [
  { id:'SH-PIPE', sev:'high', docSev:'low', title:'Downloads and pipes straight into a shell',
    why:'Fetching a script and executing it immediately means whatever the remote server returns at that moment will run on your machine.',
    re:/\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:(?:ba|z|da|k)?sh|python[0-9.]*|perl|ruby|node)\b/i },
  { id:'PS-IEX', sev:'high', docSev:'low', title:'PowerShell downloads and executes remote code',
    why:'Invoke-Expression on downloaded content runs remote code without any review.',
    re:/(?:\b(?:iex|Invoke-Expression)\b[^\n]*(?:DownloadString|Invoke-WebRequest|\biwr\b|\birm\b|Net\.WebClient))|(?:(?:Invoke-WebRequest|\biwr\b|\birm\b)[^|\n]*\|\s*(?:iex|Invoke-Expression))/i },
  { id:'REV-SHELL', sev:'critical', title:'Reverse shell pattern',
    why:'These constructs open an interactive shell back to a remote machine. There are almost no legitimate uses inside an agent.',
    re:/\/dev\/tcp\/|\bbash\s+-i\s*>&|\bnc(?:at)?\s+[^\n]*\s-e\s|\bmkfifo\b[^\n]*\bnc\b|socket\.socket\([^\n]*\)[^\n]*\.connect\([^\n]*(?:dup2|subprocess|\/bin\/sh)/ },
  { id:'DESTRUCT', sev:'high', title:'Destructive system command',
    why:'Commands that wipe the filesystem or disks can corrupt your system if they run.',
    re:/\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+(?:--no-preserve-root\s+)?(?:\/|~|\$HOME|\*)(?:\s|$|["';])|\bmkfs\.\w+|\bdd\s+if=\S+\s+of=\/dev\/|:\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:/ },
  { id:'OBF-DECODE-EXEC', sev:'high', title:'Decodes hidden data and executes it',
    why:'Hiding code in an encoded blob and running it right after decoding is a classic malware technique.',
    re:/(?:\beval|\bexec|\bFunction)\s*\(\s*(?:atob|Buffer\.from|(?:base64\.)?b64decode|bytes\.fromhex|zlib\.decompress|codecs\.decode|marshal\.loads)|base64\s+(?:-d|--decode)\s*\|\s*(?:ba|z)?sh\b/ },
  { id:'PY-DESER', sev:'high', title:'Unsafe deserialization',
    why:'pickle, marshal and yaml.load without SafeLoader can run arbitrary code when given untrusted data.',
    exts:PY_EXTS,
    re:/\b(?:pickle|cPickle|dill)\.loads?\s*\(|\bmarshal\.loads?\s*\(|\byaml\.load\s*\((?![^)]*Safe(?:Loader|_load))/ },
  { id:'EXFIL-ENVSEND', sev:'high', title:'Sends secrets or credential files over the network',
    why:'A network call on the same line as environment variables or credential paths is the typical shape of data theft.',
    re:/(?:requests\.(?:post|put)|urlopen|\bfetch|axios\.(?:post|put)|http\.request|\bcurl\s+-[a-zA-Z]*d)\b[^\n]*(?:os\.environ|process\.env|\.ssh\b|id_rsa|credentials|\/etc\/passwd|keychain)/i },
  { id:'EXFIL-HOOK', sev:'high', docSev:'low', title:'Known data-drop or tunnel endpoint',
    why:'Webhooks, paste sites and tunnelling services are commonly used to receive stolen data or to host payloads.',
    re:/discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|hooks\.slack\.com\/services|webhook\.site|requestbin|pipedream\.net|\.ngrok(?:-free)?\.(?:io|app|dev)|burpcollaborator\.net|\boast\.(?:fun|live|site|pro|me)\b|interact\.sh|transfer\.sh|pastebin\.com\/raw|anonfiles|\.trycloudflare\.com|\.serveo\.net|\.loca\.lt/i },
  { id:'CRED-FILES', sev:'high', title:'Touches credential stores',
    why:'SSH keys, cloud credentials, browser profiles and wallets are the usual targets of information stealers.',
    re:/~\/\.ssh|\.ssh[\/\\](?:id_|authorized_keys|known_hosts)|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|authorized_keys|\.aws[\/\\]credentials|\.config[\/\\]gcloud|Library[\/\\]Keychains|Login Data|Cookies\.sqlite|wallet\.dat|\/etc\/shadow|\.bash_history|Local Storage[\/\\]leveldb|metamask/i },
  { id:'CRED-CONFIG', sev:'medium', title:'Reads tool credential files',
    why:'Package-manager and cluster config files often hold access tokens.',
    re:/\.npmrc|\.pypirc|\.netrc|\.docker[\/\\]config\.json|\.kube[\/\\]config|\.git-credentials/ },
  { id:'ENV-DUMP', sev:'medium', title:'Reads the whole environment',
    why:'Collecting every environment variable gathers API keys and tokens in one go.',
    re:/JSON\.stringify\(\s*process\.env|Object\.(?:keys|entries|values)\(\s*process\.env\s*\)|\.\.\.process\.env|\bdict\(os\.environ\)|\bjson\.dumps\(\s*(?:dict\()?os\.environ|\bos\.environ\.copy\(\)|\bprintenv\b/ },
  { id:'PERSIST', sev:'medium', title:'Persistence mechanism',
    why:'Cron jobs, launch agents and shell profile edits let code survive reboots and run again later.',
    re:/\bcrontab\b|\/etc\/cron|\blaunchctl\s+load|LaunchAgents|\bsystemctl\s+(?:--user\s+)?enable|\.bashrc|\.zshrc|\/etc\/rc\.local|\/etc\/profile\.d|schtasks\s+\/create|CurrentVersion\\+Run/i },
  { id:'PRIV', sev:'medium', title:'Privilege escalation or container escape settings',
    why:'Broad privileges widen the damage a compromised agent can do to the host.',
    exts:SHELLY,
    re:/\bchmod\s+(?:-R\s+)?(?:777|[ugo]*\+s)\b|\bsudo\s+\S|\bchown\s+-R\s+root|--privileged|\/var\/run\/docker\.sock|network_mode:\s*["']?host|\bsetcap\b/ },
  { id:'AGENT-NOSANDBOX', sev:'medium', title:'Disables approval or safety prompts',
    why:'Auto-approving tool calls removes the human check that limits what a misled agent can do.',
    in:ALL,
    re:/--dangerously-skip-permissions|dangerously[-_]?skip|auto[-_]?approve\s*["']?\s*[:=]\s*true|allow[-_]?all[-_]?(?:commands|tools)\s*["']?\s*[:=]\s*true|yolo[-_]?mode\s*["']?\s*[:=]\s*true/i },
  { id:'PY-SHELLTRUE', sev:'medium', title:'Runs a subprocess through a shell',
    why:'shell=True makes command injection possible if any part of the command comes from untrusted text.',
    exts:PY_EXTS, re:/\bshell\s*=\s*True\b/ },
  { id:'PY-SUBPROC', sev:'low', title:'Runs system commands (Python)',
    why:'Normal for agents, but confirm the commands cannot be shaped by untrusted input and run the agent in a sandbox.',
    exts:PY_EXTS, re:/\bsubprocess\.\w+|\bos\.(?:system|popen)\s*\(/ },
  { id:'PY-EXEC', sev:'medium', title:'Dynamic code evaluation (Python)',
    why:'eval and exec run text as code. If any of that text comes from a model or the web, it becomes remote code execution.',
    exts:PY_EXTS, re:/(?<![\w.])(?:eval|exec)\s*\(/ },
  { id:'JS-EVAL', sev:'medium', title:'Dynamic code evaluation (JavaScript)',
    why:'eval and new Function run text as code. If any of that text comes from a model or the web, it becomes remote code execution.',
    exts:JS_EXTS, re:/(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\(/ },
  { id:'JS-CHILD', sev:'low', title:'Runs system commands (Node)',
    why:'Normal for agents, but confirm the commands cannot be shaped by untrusted input and run the agent in a sandbox.',
    exts:JS_EXTS, re:/child_process|\b(?:execSync|spawnSync|execFile)\s*\(/ },
  { id:'NET-IP', sev:'medium', title:'Hardcoded public IP address',
    why:'Legitimate software normally uses domain names. A raw IP is common in command-and-control code.',
    re:/https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/,
    filter:(m)=>{ const ip=m[0].replace(/^https?:\/\//,'').split(':')[0]; return !/^(?:10\.|127\.|0\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(ip); } },
  { id:'NET-SHORT', sev:'low', title:'URL shortener',
    why:'Shortened links hide the real destination, which can change at any time.',
    re:/https?:\/\/(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy|shorturl\.at)\//i },
  { id:'OBF-B64', sev:'medium', title:'Very long encoded string',
    why:'Large base64-like blobs in source can hide payloads. Check what it decodes to.',
    skip:/\.min\.|\.map$|\.svg$|lock|\.lock$|integrity/i,
    re:/[A-Za-z0-9+\/]{220,}={0,2}/,
    filter:(m,line)=>!/data:[a-z]+\/[\w.+-]+;base64|sha(?:256|384|512)-/.test(line) },
  { id:'OBF-HEX', sev:'medium', title:'Long run of escaped characters',
    why:'Strings built from hex or unicode escapes are used to hide commands and URLs.',
    skip:/\.min\.|\.map$/i, re:/(?:\\x[0-9a-fA-F]{2}){12,}|(?:\\u[0-9a-fA-F]{4}){12,}/ },
  { id:'OBF-CHARCODE', sev:'medium', title:'String assembled from character codes',
    why:'Building text one character code at a time hides what a script really contains.',
    skip:/\.min\.|\.map$/i, re:/String\.fromCharCode\s*\((?:\s*\d+\s*,){8,}|(?:chr\(\d+\)\s*\+\s*){8,}/ },
  { id:'OBF-VARS', sev:'medium', title:'Obfuscator signature',
    why:'Identifiers like _0x1a2b are generated by JavaScript obfuscators, which legitimate open-source projects rarely use.',
    exts:JS_EXTS, skip:/\.min\.|\.map$/i, re:/\b_0x[0-9a-f]{4,6}\b/ },
  { id:'HID-BIDI', sev:'high', in:ALL, title:'Hidden direction-control characters',
    why:'Invisible bidirectional characters can make code display differently from how it executes (known as Trojan Source).',
    re:/[\u202A-\u202E\u2066-\u2069]/ },
  { id:'HID-INVIS', sev:'medium', in:ALL, title:'Invisible characters',
    why:'Zero-width and Unicode tag characters can hide instructions from human reviewers while remaining readable to AI models.',
    re:/[\u200B\u2060\u2062-\u2064\u{E0000}-\u{E007F}]/u },
  { id:'PI-REVIEWER', sev:'high', in:ALL, title:'Text aimed at an AI reviewer or scanner',
    why:'Legitimate projects have no reason to tell an AI reviewer how to classify them. Treat this as an attempt to manipulate automated review.',
    re:/(?:mark|report|rate|classify|label)\s+(?:this|it|the)(?:\s+(?:repo|repository|code|package|project))?\s+as\s+(?:safe|benign|clean|harmless)|(?:skip|bypass|disable)\s+(?:the\s+)?(?:security|safety)\s+(?:scan|check|review|audit)|(?:do\s+not|don['’]t)\s+(?:flag|report|mention)\s+(?:this|any|these)/i },
  { id:'PI-OVERRIDE', sev:'medium', in:ALL, title:'Text that tries to override AI instructions',
    why:'Phrases like these are used in prompt injection. They also appear in security test fixtures, so check the context.',
    re:/ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts?|rules)|disregard\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|your)\s+(?:instructions|rules|guidelines)|you\s+are\s+now\s+(?:in\s+)?(?:developer|jailbreak|dan)\s+mode|(?:do\s+not|don['’]t)\s+(?:tell|inform)\s+the\s+user/i },
  { id:'PI-HIDDENCOMMENT', sev:'medium', exts:['md','html','htm','txt'], title:'Hidden comment addressed to an AI or agent',
    why:'HTML comments do not show in rendered pages but are read by AI tools. Instructions hidden there are a known injection route.',
    re:/<!--[^>]{0,400}\b(?:instruction|assistant|ignore|system prompt|LLM|AI agent|you must)\b[^>]{0,400}-->/i },
  /* ---- Common weaknesses in AI-generated apps ---- */
  { id:'SECRET-LITERAL', sev:'high', in:ALL, title:'Hard-coded secret or private key',
    why:'Keys committed to a repository, or shipped in frontend code, can be copied by anyone. Rotate the key and keep it in server-side environment variables.',
    re:/-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|\bsk_live_[0-9A-Za-z]{20,}|\bsk-[A-Za-z0-9]{32,}\b|\bsk-(?:proj|ant)-[A-Za-z0-9_-]{32,}|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{50,}|\bxox[abprs]-[A-Za-z0-9-]{10,}|\bsbp_[0-9a-f]{40}\b/,
    filter:(m) => new Set(m[0].slice(-20)).size >= 6 },
  { id:'FRONTEND-SECRET-ENV', sev:'high', title:'Secret placed in a public frontend variable',
    why:'Variables starting with NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_ or PUBLIC_ are bundled into the browser code, so anyone can read them.',
    re:/\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|PUBLIC)_[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|PASSWORD)[A-Z0-9_]*\b/ },
  { id:'CORS-WILDCARD', sev:'medium', title:'CORS allows any website',
    why:'Allowing every origin lets any site call this API from a visitor’s browser. It is most dangerous with cookies, or when the origin is simply echoed back.',
    re:/Access-Control-Allow-Origin["']?\s*[:,=]\s*["']?\*|\bcors\(\s*\)|\borigin\s*:\s*(?:["']\*["']|true)\b|allow_origins\s*=\s*\[\s*["']\*["']\s*\]|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|AllowAnyOrigin\(\)/i },
  { id:'SQLI-JS', sev:'medium', exts:['js','mjs','cjs','ts','jsx','tsx'], title:'SQL built from strings',
    why:'SQL assembled with template strings or + can be hijacked by user input. Use parameterised queries instead.',
    re:/\b(?:SELECT\s[^;\n]*\sFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b[^;\n]*(?:\$\{|["'`]\s*\+\s*\w)|\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(/i },
  { id:'SQLI-PY', sev:'medium', exts:PY_EXTS, title:'SQL built from strings',
    why:'SQL assembled with f-strings, % or + can be hijacked by user input. Use parameterised queries instead.',
    re:/\b(?:execute|executemany)\s*\(\s*f["']|\b(?:SELECT\s[^;\n]*\sFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b[^\n]*["']\s*(?:%\s*[\w(]|\.format\(|\+\s*\w)/i },
  { id:'XSS-SINK', sev:'medium', exts:JS_EXTS, title:'Raw HTML inserted into the page',
    why:'Putting untrusted text into innerHTML or similar sinks allows cross-site scripting. Prefer textContent, or sanitise the HTML first.',
    re:/dangerouslySetInnerHTML|\bv-html\b|\{@html\b|\.(?:inner|outer)HTML\s*=(?!=)|\binsertAdjacentHTML\s*\(|\bdocument\.write(?:ln)?\s*\(/ },
  { id:'XSS-PY', sev:'medium', exts:PY_EXTS, title:'HTML marked as safe or template built from strings',
    why:'mark_safe, Markup and render_template_string skip escaping and can allow cross-site scripting or template injection.',
    re:/\bmark_safe\s*\(|\bMarkup\s*\(|\brender_template_string\s*\(/ },
  { id:'WEAK-HASH', sev:'medium', title:'Weak hash used for passwords',
    why:'MD5 and SHA-1 are fast to brute-force. Passwords need bcrypt, scrypt or argon2.',
    re:/\b(?:md5|sha1)\b[^\n]{0,60}\bpass(?:word|wd)?\b|\bpass(?:word|wd)?\b[^\n]{0,60}\b(?:md5|sha1)\b|createHash\(\s*["'](?:md5|sha1)["']\s*\)[^\n]*pass/i },
  { id:'SSRF-USERURL', sev:'medium', title:'Server fetches a URL taken from the request',
    why:'If the address comes from the visitor, they can make your server call internal services or cloud metadata endpoints (SSRF). Check it against an allowlist.',
    re:/\b(?:fetch|axios(?:\.\w+)?|got|request|urlopen|http\.get)\s*\(\s*req(?:uest)?\.(?:query|body|params)\b|\brequests\.(?:get|post|put|head)\s*\(\s*request\.(?:args|form|json|GET|POST|data)\b/ },
  { id:'DEBUG-EXPOSED', sev:'low', title:'Debug mode or stack traces exposed',
    why:'Debug pages and stack traces reveal internals and sometimes secrets. Turn them off in production.',
    re:/\bapp\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b|res\.(?:status\(\d+\)\.)?(?:send|json)\([^)]*\b(?:err|error)\.stack\b/ },
  { id:'PY-SETUP-CMD', sev:'medium', path:/(?:^|\/)setup\.py$/, title:'setup.py runs custom install-time code',
    why:'Code in setup.py executes when the package is installed, before you have used it.',
    re:/\bcmdclass\b|\bos\.system\b|\bsubprocess\b|\burlopen\b|\brequests\.|(?<![\w.])exec\s*\(/ },
  { id:'GH-INJECT', sev:'medium', path:/^\.github\/workflows\/.+\.ya?ml$/, title:'Untrusted GitHub text used inside a workflow',
    why:'Issue titles, branch names and similar fields placed into a workflow can inject commands into the CI job.',
    re:/\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|head_commit|commits|pages)[^}]*\.(?:title|body|message|name|label|ref|email)|head_ref)[^}]*\}\}/ },
  { id:'GH-PRT', sev:'medium', path:/^\.github\/workflows\/.+\.ya?ml$/, title:'Workflow uses pull_request_target',
    why:'This trigger runs with repository secrets and, combined with untrusted code checkout, is a common supply-chain hole.',
    re:/\bpull_request_target\b/ }
];

/* ============================================================
   Static data
   ============================================================ */
const POPULAR = {
  npm: ['react','react-dom','lodash','express','axios','chalk','commander','request','moment','debug','async','underscore','webpack','typescript','vue','next','dotenv','uuid','jquery','eslint','prettier','mongoose','socket.io','cors','body-parser','colors','color','minimist','yargs','glob','rimraf','mkdirp','inquirer','openai','langchain','zod','tslib','semver','ora','jest','mocha','chai','vite','rollup','esbuild','dayjs','date-fns','bluebird','cheerio','puppeteer','playwright','node-fetch','ws','redis','mysql','pg','sequelize','passport','jsonwebtoken','bcrypt','nodemon','pino','winston','ramda','rxjs','svelte','nuxt','electron','prisma'],
  PyPI: ['requests','numpy','pandas','urllib3','boto3','setuptools','flask','django','pytest','scipy','matplotlib','pillow','pyyaml','cryptography','openai','langchain','tensorflow','torch','beautifulsoup4','selenium','sqlalchemy','colorama','jinja2','click','certifi','httpx','pydantic','fastapi','anthropic','aiohttp','six','idna','attrs','rich','tqdm','pip','wheel','psycopg2','redis','celery','scikit-learn','transformers','uvicorn','gunicorn','paramiko','lxml','docker','jsonschema','protobuf','packaging','python-dateutil','pytz','tabulate','typer','black','flake8','mypy','poetry','virtualenv','tornado','websockets','markdown','chardet','openpyxl','pymongo']
};
const BIN_EXECUTABLE = new Set(['exe','dll','so','dylib','bin','pyd','node','msi','dmg','apk','scr','com']);
const BIN_OTHER = new Set(['jar','whl','pyc','class','o','a','deb','rpm','zip','7z','gz','tgz','rar']);
const SCAN_EXTS = new Set([...GROUPS.CODE, ...GROUPS.CONF, ...GROUPS.DOC]);
const LOCKFILES = /^(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|npm-shrinkwrap\.json|poetry\.lock|pipfile\.lock|cargo\.lock|composer\.lock|go\.sum)$/i;
const SECRET_NAMES = /^(?:\.env(?:\.(?!example$|sample$|template$|dist$)[\w.-]+)?|id_(?:rsa|dsa|ecdsa|ed25519)|.*\.(?:pem|p12|pfx|keystore)|credentials\.json|service[-_]account.*\.json|\.npmrc|\.pypirc|\.netrc)$/i;

/* Rules that look at a whole file, for problems that are an absence rather than a pattern.
   test(text, path) returns true when the problem is present; find locates the line to show. */
const SERVER_EXTS = ['js','mjs','cjs','ts','py'];
const APP_MARK = /\bexpress\(\)|Flask\(__name__\)|\bFastAPI\(\)/;
const FILE_RULES = [
  { id:'STRIPE-NOVERIFY', sev:'medium', exts:['js','mjs','cjs','ts','py','rb','php','go'], title:'Stripe webhook without a signature check',
    why:'Without verifying Stripe’s signature, anyone can post fake “payment succeeded” events to the webhook. The check may live in another file.',
    test:(t) => /stripe/i.test(t) && /webhook/i.test(t) && !/constructEvent|stripe-signature|construct_event|Stripe\.Webhook|verify_header|Webhook\.construct/i.test(t),
    find:/webhook/i },
  { id:'SUPABASE-RLS', sev:'medium', exts:['sql'], title:'Table created without Row Level Security',
    why:'In Supabase and other Postgres apps exposed through an API, tables without Row Level Security can be read or changed by anyone holding the public key. It may be enabled in another migration, so check.',
    test:(t, p) => /create\s+table/i.test(t) && !/enable\s+row\s+level\s+security/i.test(t) && (/supabase/i.test(p) || /supabase|auth\.(?:uid|users)/i.test(t)),
    find:/create\s+table/i },
  { id:'APP-NOHEADERS', sev:'low', exts:SERVER_EXTS, title:'Web app without security headers',
    why:'Headers such as CSP, HSTS and X-Content-Type-Options limit what a browser does with injected content. Helmet (Node) or Talisman (Flask) adds them. They may be set in another file.',
    test:(t) => APP_MARK.test(t) && !/helmet|talisman|secure_headers|SecurityMiddleware|X-Content-Type-Options|Content-Security-Policy/i.test(t),
    find:APP_MARK },
  { id:'APP-NORATELIMIT', sev:'low', exts:SERVER_EXTS, title:'Web app without rate limiting',
    why:'Without limits, attackers can guess passwords, scrape data or run up your bills. It may be handled by a proxy or in another file.',
    test:(t) => APP_MARK.test(t) && !/rate[-_ ]?limit|slowapi|flask_limiter|Limiter\(|throttle/i.test(t),
    find:APP_MARK },
  { id:'APP-NOCSRF', sev:'low', exts:SERVER_EXTS, title:'Cookie sessions without CSRF protection',
    why:'If login uses cookies, other websites can make a logged-in visitor’s browser send requests unless CSRF tokens or SameSite cookies are used. It may be handled in another file.',
    test:(t) => APP_MARK.test(t) && /express-session|cookie-session|flask_login|session\[|set_cookie/.test(t) && !/csrf|csurf|samesite/i.test(t),
    find:/express-session|cookie-session|flask_login|session\[|set_cookie/ }
];

const SEV = ['critical','high','medium','low','info'];
const SEV_LABEL = {critical:'Critical',high:'High',medium:'Medium',low:'Low',info:'Info'};
const LIMITS = { files:250, fileBytes:400*1024, totalBytes:8*1024*1024, perFileRule:3, shownPerGroup:20, longLine:1500, lineCap:4000, concurrency:8 };
