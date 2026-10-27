#!/usr/bin/env python3
"""Deep static scan of a public GitHub repository.

Run by .github/workflows/scan.yml. Inputs arrive as environment variables:
  TARGET   owner/name of the repository to scan
  COMMIT   optional full 40-character commit SHA
  OUT_DIR  where report.json is written

Safety rules this script follows:
  * Nothing from the target repository is ever executed or imported.
  * The target is cloned with git hooks disabled and symlinks turned into plain files.
  * Dependency tools run in static modes only (no installs, no dependency resolution).
  * Every external command is started from an argument list, never through a shell.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

TARGET = os.environ.get("TARGET", "").strip()
COMMIT = os.environ.get("COMMIT", "").strip().lower()
OUT_DIR = Path(os.environ.get("OUT_DIR", "out"))

MAX_FINDINGS = 500
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SKIP_DIRS = {".git", "node_modules"}
CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")


def clip(value, limit=300):
    text = CTRL.sub("?", str(value if value is not None else ""))
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def die(message):
    print("error: " + message, file=sys.stderr)
    sys.exit(1)


def run(cmd, cwd=None, timeout=300, extra_env=None):
    env = dict(os.environ)
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"})
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        cmd, cwd=cwd, env=env, capture_output=True, text=True, errors="replace",
        timeout=timeout, check=False,
    )


def walk(root, names=None, suffix=None, limit=20):
    """Find files under root, skipping .git and node_modules, up to limit."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            ok = (names and name in names) or (suffix and suffix(name))
            if ok:
                found.append(Path(dirpath) / name)
                if len(found) >= limit:
                    return found
    return found


def rel(path, root):
    try:
        return os.path.relpath(path, root).replace(os.sep, "/")
    except ValueError:
        return str(path)


def finish(findings):
    findings.sort(key=lambda f: SEV_ORDER.index(f["severity"]) if f["severity"] in SEV_ORDER else 9)
    return findings[:MAX_FINDINGS]


# ----------------------------------------------------------------------------
# Input validation and checkout
# ----------------------------------------------------------------------------
if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}", TARGET):
    die("TARGET must look like owner/name")
if TARGET.split("/")[1] in (".", ".."):
    die("TARGET is not a valid repository name")
if COMMIT and not re.fullmatch(r"[0-9a-f]{40}", COMMIT):
    die("COMMIT must be a full 40-character SHA or empty")

OUT_DIR.mkdir(parents=True, exist_ok=True)
work = Path(tempfile.mkdtemp(prefix="agent-audit-"))
root = work / "target"
url = "https://github.com/" + TARGET + ".git"
safe_git = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false",
            "-c", "core.fsmonitor=false", "-c", "protocol.file.allow=never"]

print("Fetching " + TARGET + (" at " + COMMIT if COMMIT else " (default branch)"))
try:
    if COMMIT:
        root.mkdir()
        for step in (
            safe_git + ["init", "-q"],
            safe_git + ["remote", "add", "origin", url],
            safe_git + ["fetch", "-q", "--depth", "1", "--no-tags", "origin", COMMIT],
            safe_git + ["checkout", "-q", "FETCH_HEAD"],
        ):
            p = run(step, cwd=root, timeout=600)
            if p.returncode != 0:
                die("git step failed: " + clip(p.stderr, 400))
    else:
        p = run(safe_git + ["clone", "-q", "--depth", "1", "--no-tags", url, str(root)], timeout=600)
        if p.returncode != 0:
            die("clone failed: " + clip(p.stderr, 400))
except subprocess.TimeoutExpired:
    die("fetching the repository took too long")

head = run(["git", "rev-parse", "HEAD"], cwd=root).stdout.strip()
if not re.fullmatch(r"[0-9a-f]{40}", head):
    die("could not determine the scanned commit")

notes = []
tools = {}


# ----------------------------------------------------------------------------
# Semgrep (code patterns and a few secret rules)
# ----------------------------------------------------------------------------
def tool_semgrep():
    cmd = ["semgrep", "scan", "--config", "p/security-audit", "--config", "p/secrets",
           "--metrics", "off", "--json", "--quiet", "--disable-version-check",
           "--timeout", "20", "--max-target-bytes", "1000000", "--exclude", "node_modules", str(root)]
    try:
        p = run(cmd, timeout=1200)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timed out after 20 minutes", "findings": []}
    try:
        data = json.loads(p.stdout)
    except ValueError:
        return {"ok": False, "error": clip(p.stderr or "no output", 300), "findings": []}
    mapping = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    out = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        out.append({
            "rule": clip(r.get("check_id", ""), 160),
            "severity": mapping.get(extra.get("severity"), "low"),
            "file": clip(rel(r.get("path", ""), root), 300),
            "line": (r.get("start") or {}).get("line"),
            "message": clip(extra.get("message", ""), 300),
        })
    result = {"ok": True, "findings": finish(out)}
    errors = data.get("errors") or []
    if errors:
        result["note"] = str(len(errors)) + " files could not be parsed by Semgrep."
    return result


# ----------------------------------------------------------------------------
# detect-secrets (reports type and location only, never the value)
# ----------------------------------------------------------------------------
def tool_secrets():
    cmd = ["detect-secrets", "scan", "--all-files", "--exclude-files", r"(^|/)(\.git|node_modules)/", "."]
    try:
        p = run(cmd, cwd=root, timeout=900)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timed out", "findings": []}
    try:
        data = json.loads(p.stdout)
    except ValueError:
        return {"ok": False, "error": clip(p.stderr or "no output", 300), "findings": []}
    out = []
    for path, items in (data.get("results") or {}).items():
        for item in items:
            kind = str(item.get("type", "Secret"))
            noisy = "High Entropy" in kind or kind == "Secret Keyword"
            out.append({
                "rule": clip(kind, 80),
                "severity": "medium" if noisy else "high",
                "file": clip(path.lstrip("./") if path.startswith("./") else path, 300),
                "line": item.get("line_number"),
                "message": "Possible secret of type '" + clip(kind, 60) + "'. The value is not stored in this report.",
            })
    result = {"ok": True, "findings": finish(out)}
    if out:
        result["note"] = "Entropy and keyword matches are often false positives. Check each location."
    return result


# ----------------------------------------------------------------------------
# Dependency inventory (shared by pip-audit and the OSV malware check)
# ----------------------------------------------------------------------------
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.!+_-]+)")


def pinned_python_requirements():
    pins = {}
    for path in walk(root, suffix=lambda n: re.fullmatch(r"requirements.*\.txt", n) is not None, limit=20):
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            clean = re.sub(r"\s+#.*$", "", line).split(";")[0].strip()
            m = PIN.match(clean)
            if m:
                pins[(m.group(1).lower(), m.group(2))] = rel(path, root)
    return pins


def npm_lock_packages():
    pkgs = {}
    for path in walk(root, names={"package-lock.json"}, limit=5):
        try:
            data = json.loads(path.read_text(errors="replace"))
        except (OSError, ValueError):
            continue
        for key, info in (data.get("packages") or {}).items():
            if not key or not isinstance(info, dict) or "node_modules/" not in key:
                continue
            name = key.rsplit("node_modules/", 1)[1]
            version = info.get("version")
            if name and isinstance(version, str) and not info.get("link"):
                pkgs[(name, version)] = rel(path, root)
        for name, info in (data.get("dependencies") or {}).items():
            if isinstance(info, dict) and isinstance(info.get("version"), str) and re.match(r"\d", info["version"]):
                pkgs.setdefault((name, info["version"]), rel(path, root))
    return pkgs


def tool_pip_audit():
    pins = pinned_python_requirements()
    if not pins:
        return {"ok": True, "findings": [], "note": "No requirements file with exact pins (name==version) was found, so nothing was audited."}
    req = work / "pinned-requirements.txt"
    req.write_text("\n".join(name + "==" + ver for name, ver in sorted(pins)) + "\n")
    cmd = ["pip-audit", "-r", str(req), "--no-deps", "--disable-pip", "--format", "json", "--progress-spinner", "off"]
    try:
        p = run(cmd, timeout=600)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timed out", "findings": []}
    try:
        data = json.loads(p.stdout)
    except ValueError:
        return {"ok": False, "error": clip(p.stderr or "no output", 300), "findings": []}
    deps = data.get("dependencies", data if isinstance(data, list) else [])
    out = []
    for dep in deps:
        for v in dep.get("vulns", []) or []:
            fixes = ", ".join(v.get("fix_versions") or []) or "no fix listed"
            out.append({
                "rule": clip(v.get("id", "advisory"), 80),
                "severity": "medium",
                "file": pins.get((str(dep.get("name", "")).lower(), str(dep.get("version", ""))), "requirements"),
                "line": None,
                "message": clip(str(dep.get("name")) + " " + str(dep.get("version")) + " (fixed in: " + fixes + ")", 300),
            })
    return {"ok": True, "findings": finish(out),
            "note": "Only packages pinned with == were audited (" + str(len(pins)) + " found). Unpinned ones are skipped."}


def tool_npm_audit():
    findings = []
    ran = 0
    skipped = []
    for pkg_json in walk(root, names={"package.json"}, limit=5):
        folder = pkg_json.parent
        lock = folder / "package-lock.json"
        if not lock.exists():
            skipped.append(rel(folder, root) or ".")
            continue
        scratch = Path(tempfile.mkdtemp(prefix="npm-audit-", dir=work))
        # Copy only the two manifest files: the repository's own .npmrc is never used.
        (scratch / "package.json").write_bytes(pkg_json.read_bytes())
        (scratch / "package-lock.json").write_bytes(lock.read_bytes())
        try:
            p = run(["npm", "audit", "--package-lock-only", "--ignore-scripts", "--json"],
                    cwd=scratch, timeout=300, extra_env={"npm_config_ignore_scripts": "true"})
            data = json.loads(p.stdout)
        except (subprocess.TimeoutExpired, ValueError):
            continue
        ran += 1
        sev_map = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low", "info": "info"}
        for name, v in (data.get("vulnerabilities") or {}).items():
            via = [x for x in (v.get("via") or []) if isinstance(x, dict)]
            title = via[0].get("title", "") if via else "vulnerable through a dependency"
            link = via[0].get("url", "") if via else ""
            findings.append({
                "rule": clip(name, 80),
                "severity": sev_map.get(v.get("severity"), "medium"),
                "file": rel(lock, root),
                "line": None,
                "message": clip(name + ": " + title + (" " + link if link else ""), 300),
            })
    result = {"ok": True, "findings": finish(findings)}
    if skipped:
        result["note"] = ("Skipped " + ", ".join(clip(s, 60) for s in skipped[:5]) +
                          ": no package-lock.json. Creating one would mean resolving dependencies, which can run code from git dependencies.")
    elif not ran:
        result["note"] = "No package.json with a lockfile was found."
    return result


# ----------------------------------------------------------------------------
# OSV: known malicious packages (MAL- ids), including transitive npm packages
# ----------------------------------------------------------------------------
def tool_osv_malicious():
    queries = []
    owners = []
    for (name, version), file in npm_lock_packages().items():
        queries.append({"package": {"name": name, "ecosystem": "npm"}, "version": version})
        owners.append((name, version, file))
    for (name, version), file in pinned_python_requirements().items():
        queries.append({"package": {"name": name, "ecosystem": "PyPI"}, "version": version})
        owners.append((name, version, file))
    if not queries:
        return {"ok": True, "findings": [], "note": "No lockfile or pinned requirements to check."}
    queries, owners = queries[:3000], owners[:3000]
    out = []
    try:
        for i in range(0, len(queries), 1000):
            body = json.dumps({"queries": queries[i:i + 1000]}).encode()
            req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                results = json.load(resp).get("results", [])
            for j, res in enumerate(results):
                mal = [v["id"] for v in (res.get("vulns") or []) if str(v.get("id", "")).startswith("MAL-")]
                if mal:
                    name, version, file = owners[i + j]
                    out.append({"rule": clip(mal[0], 80), "severity": "critical", "file": file, "line": None,
                                "message": clip(name + "@" + version + " is listed as malicious: " + ", ".join(mal[:5]), 300)})
    except Exception as exc:  # network or parse problems must not lose the other results
        return {"ok": False, "error": clip(exc, 200), "findings": finish(out)}
    return {"ok": True, "findings": finish(out), "note": str(len(queries)) + " package versions checked."}


# ----------------------------------------------------------------------------
# Registry check: dependencies that do not exist (AI tools sometimes invent
# package names, and attackers register those names with malware: "slopsquatting")
# ----------------------------------------------------------------------------
NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
NON_REGISTRY_SPEC = re.compile(r"^(?:workspace:|file:|link:|git|https?:|github:|npm:|portal:|patch:)|^[\w.-]+/[\w.-]+(?:#.+)?$")


def registry_exists(kind, name):
    """True if the package exists, False if the registry answers 404, None if unknown."""
    if kind == "npm":
        url = "https://registry.npmjs.org/" + name.replace("/", "%2F")
        accept = "application/vnd.npm.install-v1+json"
    else:
        url = "https://pypi.org/pypi/" + name + "/json"
        accept = "application/json"
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "agent-audit-deep-scan"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            resp.read(1)
        return True
    except urllib.error.HTTPError as exc:
        return False if exc.code == 404 else None
    except Exception:
        return None


def declared_packages():
    """(kind, name) -> manifest file, for registry-style dependencies only."""
    wanted = {}
    local_names = set()
    manifests = walk(root, names={"package.json"}, limit=20)
    for path in manifests:
        try:
            data = json.loads(path.read_text(errors="replace"))
        except (OSError, ValueError):
            continue
        if isinstance(data.get("name"), str):
            local_names.add(data["name"])
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            for name, spec in (data.get(section) or {}).items():
                if isinstance(spec, str) and not NON_REGISTRY_SPEC.match(spec) and NPM_NAME.match(name):
                    wanted[("npm", name)] = rel(path, root)
    for path in walk(root, suffix=lambda n: re.fullmatch(r"requirements.*\.txt", n) is not None, limit=20):
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            clean = re.sub(r"\s+#.*$", "", line).split(";")[0].strip()
            if not clean or clean.startswith(("-", "#")) or re.match(r"^(?:git\+|https?:|ssh:|file:)", clean):
                continue
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", clean)
            if m and PYPI_NAME.match(m.group(1)):
                wanted[("pypi", m.group(1))] = rel(path, root)
    return {k: v for k, v in wanted.items() if k[1] not in local_names}


def tool_registry():
    wanted = declared_packages()
    if not wanted:
        return {"ok": True, "findings": [], "note": "No registry dependencies were found to check."}
    items = list(wanted.items())[:300]
    with ThreadPoolExecutor(max_workers=8) as pool:
        answers = list(pool.map(lambda kv: registry_exists(kv[0][0], kv[0][1]), items))
    out = []
    unknown = 0
    for ((kind, name), file), exists in zip(items, answers):
        if exists is None:
            unknown += 1
        elif exists is False:
            where = "npm" if kind == "npm" else "PyPI"
            out.append({"rule": "DEP-NOT-IN-REGISTRY", "severity": "high", "file": file, "line": None,
                        "message": clip(name + " is not on " + where + ". If an AI tool invented this name, an attacker can publish malware under it. Check the name before installing.", 300)})
    note = str(len(items)) + " package names checked."
    if unknown:
        note += " " + str(unknown) + " could not be checked because the registry did not answer."
    if len(wanted) > 300:
        note += " Only the first 300 were checked."
    return {"ok": True, "findings": finish(out), "note": note}


for key, fn in (("semgrep", tool_semgrep), ("secrets", tool_secrets), ("pip_audit", tool_pip_audit),
                ("npm_audit", tool_npm_audit), ("osv_malicious", tool_osv_malicious), ("registry", tool_registry)):
    print("Running " + key)
    try:
        tools[key] = fn()
    except Exception as exc:  # one broken tool should not sink the whole report
        tools[key] = {"ok": False, "error": clip(exc, 200), "findings": []}

summary = {s: 0 for s in SEV_ORDER}
for t in tools.values():
    for f in t.get("findings", []):
        summary[f["severity"] if f["severity"] in summary else "info"] += 1

report = {
    "schema": 1,
    "tool": "agent-audit deep scan",
    "target": TARGET,
    "commit": head,
    "requestedCommit": COMMIT or None,
    "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    "tools": tools,
    "summary": summary,
    "notes": notes,
}
(OUT_DIR / "report.json").write_text(json.dumps(report, indent=2))
print("Wrote " + str(OUT_DIR / "report.json") + " with summary " + json.dumps(summary))
