#!/usr/bin/env python3
# safe-install: pre-flight check before running npm/pip/cargo/etc.
#
# Got tired of seeing people get hit by supply chain attacks that a
# 30-second sanity check would've caught.  This doesn't replace a
# proper SBOM audit, but it stops the obvious stuff cold.
#
# Supported: npm, yarn, pnpm, pip, pip3, uv, cargo, gem, go, composer, nuget
#
# Usage:
#   safe-install npm install lodash express
#   safe-install pip install -r requirements.txt
#   safe-install cargo add serde tokio
#   safe-install -y pip install flask   # skip confirmation prompts
#   safe-install --dry-run npm install react
#
# Flags (come before the package manager name):
#   -y / --yes     don't prompt on warnings, just proceed
#   --dry-run      scan only, don't actually run the install
#   --no-check     bypass everything (emergency escape hatch)

import sys
import os
import json
import re
import subprocess
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone

VERSION = "1.0.0"

# Fix Windows console encoding — without this any non-ASCII in package
# descriptions will throw UnicodeEncodeError on cp932/cp1252 terminals
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Color output.  Respects NO_COLOR env var (https://no-color.org/).
_use_color = (
    sys.stdout.isatty()
    and not os.environ.get("NO_COLOR")
    and not os.environ.get("SI_NO_COLOR")
)
if _use_color:
    R = "\033[91m"; Y = "\033[93m"; G = "\033[92m"
    C = "\033[96m"; B = "\033[1m";  D = "\033[2m";  RST = "\033[0m"
else:
    R = Y = G = C = B = D = RST = ""

_API_TIMEOUT = int(os.environ.get("SI_TIMEOUT", "12"))


# ---------------------------------------------------------------------------
# Known-bad packages
#
# These are packages confirmed malicious or sabotaged in the wild.
# Keeping a short list of famous cases is useful because the same names
# get recycled and attackers watch what worked before.
#
# Format: lowercased-pkg-name -> (short note, severity)
#         severity: "block" = always abort, "warn" = flag but still prompt
# ---------------------------------------------------------------------------

KNOWN_BAD = {
    # npm – typosquatting campaigns (2017 Npm audit leak)
    "crossenv":        ("typosquats cross-env; harvests env vars", "block"),
    "babelcli":        ("typosquats babel-cli; harvests env vars", "block"),
    "loadyaml":        ("typosquats js-yaml", "block"),
    "twilio-npm":      ("typosquats twilio", "block"),
    "nodecaffe":       ("typosquats node-caffe", "block"),
    "nodemssql":       ("typosquats node-mssql", "block"),
    "mongose":         ("typosquats mongoose", "block"),
    "gruntcli":        ("typosquats grunt-cli", "block"),
    "jquery.js":       ("fake jquery with cryptominer", "block"),

    # npm – hijacked legitimate packages (2021)
    "ua-parser-js":    ("hijacked 2021-10; postinstall cryptominer + RAT", "block"),
    "coa":             ("hijacked 2021-11; same campaign as ua-parser-js", "block"),
    "rc":              ("hijacked 2021-11; same campaign as ua-parser-js", "block"),

    # npm – author-sabotaged packages (2022)
    "colors":          ("author sabotage 2022-01; infinite loop DoS", "warn"),
    "faker":           ("author sabotage 2022-01; same author as colors", "warn"),
    "node-ipc":        ("author sabotage 2022-03; deleted files on RU/BY IPs", "block"),
    "peacenotwar":     ("malicious payload dropped by node-ipc", "block"),

    # npm – other
    "flatmap-stream":  ("embedded backdoor targeting copay wallet (2018)", "block"),
    "event-stream":    ("compromised 2018; carried flatmap-stream payload", "warn"),
    "eslint-scope":    ("credential stealer added to compromised release (2018)", "block"),
    "everything":      ("installs entire npm registry; probably not what you want", "warn"),

    # PyPI – typosquatting / malicious
    "colourama":       ("typosquats colorama; clipboard hijacker", "block"),
    "jellyfish":       ("look-alike package (capital I vs lowercase l)", "warn"),
    "jeIlyfish":       ("typosquats jellyfish with capital-I", "block"),
    "python-sqlite":   ("malicious; no relation to stdlib sqlite3", "block"),
    "acqusition":      ("credential stealer (2021 PyPI campaign)", "block"),
    "apidev-coop":     ("malicious (2021 PyPI campaign)", "block"),
    "bzip":            ("malicious; typosquats bzip2", "block"),
    "maratlib":        ("malicious; typosquats matplotlib", "block"),
    "matplotlb":       ("typosquats matplotlib", "block"),
    "py-ftp":          ("backdoor disguised as FTP library (2023)", "block"),
    "loglib-modules":  ("infostealer disguised as logging library (2024)", "block"),
    "requests-darwin": ("fake requests variant with data exfil (2024)", "block"),
    "mlflow-nessie":   ("fake mlflow with credential stealer (2024)", "block"),
    "ultralytics":     ("compromised 2024-12; cryptominer injected via CI", "warn"),

    # Cargo
    "rustdecimal":     ("typosquats rust_decimal; data exfil (2022)", "block"),
}


# ---------------------------------------------------------------------------
# Popular packages used for typosquatting detection.
# The attacker's goal is to get you to mistype a common name, so we
# only need to track the ones people actually type from memory.
# ---------------------------------------------------------------------------

_TOP_NPM = [
    "lodash","express","react","react-dom","axios","moment","webpack",
    "typescript","eslint","prettier","jest","mocha","chalk","commander",
    "dotenv","uuid","yargs","minimist","semver","glob","async","bluebird",
    "underscore","request","node-fetch","cross-env","rimraf","mkdirp",
    "debug","colors","inquirer","ora","got","cheerio","puppeteer",
    "playwright","socket.io","mongoose","sequelize","pg","mysql2","redis",
    "ioredis","nodemailer","bcrypt","jsonwebtoken","passport","cors",
    "helmet","morgan","multer","sharp","next","vue","angular","svelte",
    "nuxt","gatsby","vite","rollup","parcel","esbuild","@babel/core",
    "webpack-cli","ts-node","nodemon","concurrently","pm2","rxjs",
    "mobx","zustand","redux","@reduxjs/toolkit","react-query","swr",
    "formik","react-hook-form","zod","yup","joi","date-fns","dayjs",
    "luxon","clsx","styled-components","tailwindcss","babel-cli",
    "cross-fetch","superagent","ws","node-gyp","node-pre-gyp",
    "js-yaml","toml","ini","dotenv-expand","ncp","mkdirp","del",
    "chokidar","glob","minimatch","micromatch","nanoid","cuid",
]

_TOP_PIP = [
    "numpy","pandas","requests","scipy","matplotlib","setuptools","pip",
    "six","python-dateutil","pytz","certifi","urllib3","chardet","idna",
    "attrs","cryptography","cffi","Pillow","boto3","botocore","PyYAML",
    "click","Flask","Django","FastAPI","SQLAlchemy","pytest","black",
    "flake8","mypy","isort","tqdm","rich","typer","pydantic","httpx",
    "aiohttp","paramiko","celery","redis","pymongo","psycopg2","asyncpg",
    "alembic","beautifulsoup4","selenium","playwright","scrapy","lxml",
    "openpyxl","torch","tensorflow","keras","scikit-learn","xgboost",
    "lightgbm","transformers","openai","anthropic","colorama","tabulate",
    "loguru","structlog","arrow","pendulum","Werkzeug","Jinja2","gunicorn",
    "uvicorn","starlette","httptools","websockets","pytest-asyncio",
    "pytest-cov","hypothesis","faker","factory-boy","invoke","nox","tox",
    "pre-commit","bandit","safety","pyinstaller","pycryptodome","passlib",
    "bcrypt","boto","google-cloud-storage","azure-storage-blob","sqlparse",
    "peewee","aiofiles","watchdog","apscheduler","rq","dramatiq",
]

_TOP_CARGO = [
    "serde","tokio","rand","clap","log","anyhow","thiserror","reqwest",
    "hyper","actix-web","axum","rocket","diesel","sqlx","sea-orm",
    "chrono","uuid","regex","lazy_static","once_cell","rayon","crossbeam",
    "parking_lot","dashmap","indexmap","smallvec","bytes","futures",
    "async-trait","tracing","env_logger","structopt","indicatif","dialoguer",
    "console","colored","prettytable","csv","serde_json","toml","config",
    "dotenv","dirs","tempfile","glob","walkdir","notify","zip","flate2",
    "base64","hex","md5","sha2","aes","rsa","ring","rustls","openssl",
    "rust_decimal","bigdecimal","num","nalgebra","ndarray",
]

_TOP_GEMS = [
    "rails","rack","activerecord","activesupport","actionpack","bundler",
    "rake","rspec","minitest","rubocop","devise","pundit","sidekiq",
    "puma","unicorn","sinatra","faraday","httparty","nokogiri","mechanize",
    "capybara","selenium-webdriver","factory_bot","faker","shoulda",
    "byebug","pry","dotenv","figaro","bcrypt","jwt","oj","multi_json",
]


# ---------------------------------------------------------------------------
# Patterns in install scripts that suggest the package does something
# beyond just putting files on disk.  Every hit gets flagged — some are
# legitimate (e.g. building native addons with node-gyp) but the user
# should know about them.
# ---------------------------------------------------------------------------

_BAD_SCRIPT_PATTERNS = [
    (r"curl\s+['\"]?https?://",           "network download (curl)"),
    (r"wget\s+['\"]?https?://",           "network download (wget)"),
    (r"Invoke-WebRequest|iwr\s",          "network download (PowerShell)"),
    (r"Invoke-Expression|iex\b",          "remote code execution (IEX)"),
    (r"\beval\s*\(",                       "dynamic eval()"),
    (r"\bexec\s*\(",                       "exec() call"),
    (r"base64[_\-]?decode\b",             "base64 decode — possible obfuscation"),
    (r"\bpowershell\b.{0,30}(-[eE]|-[eE][nN]|-[eE][nN][cC])",
                                          "PowerShell encoded command"),
    (r"cmd\.exe\s*/[cC]\b",              "CMD execution"),
    (r"\bsh\s+-c\b",                      "shell -c exec"),
    (r"/dev/tcp/",                        "bash TCP socket (rev shell pattern)"),
    (r"\bnc\s+-",                          "netcat"),
    (r"chmod\s+[0-7]*\+?x\s",            "chmod +x"),
    (r"os\.system\s*\(",                  "os.system()"),
    (r"subprocess\.(call|run|Popen)\s*\(","subprocess exec"),
    (r"__import__\s*\(",                  "dynamic __import__"),
    (r"\\\\[A-Za-z0-9_-]+\\[A-Za-z$]",  "UNC path (possible NTLM leak)"),
    (r"\.onion\b",                         "Tor hidden service"),
    (r"discord(?:app)?\.com/api/webhooks","Discord webhook exfil"),
    (r"t(?:elegram)?\.me/|api\.telegram","Telegram exfil"),
]


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _get(url, timeout=None):
    """Simple GET, returns parsed JSON or None on any error."""
    if timeout is None:
        timeout = _API_TIMEOUT
    try:
        req = urllib.request.Request(
            url, headers={"Accept": "application/json", "User-Agent": f"safe-install/{VERSION}"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        return None
    except Exception:
        return None


def _post(url, payload, timeout=None):
    if timeout is None:
        timeout = _API_TIMEOUT
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json", "User-Agent": f"safe-install/{VERSION}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Registry lookups — each returns a small dict with normalized fields
# so the caller doesn't have to know the registry's response shape
# ---------------------------------------------------------------------------

def _npm_meta(pkg):
    data = _get(f"https://registry.npmjs.org/{urllib.parse.quote(pkg, safe='@%')}")
    if data is None:
        return {"found": False}
    latest = data.get("dist-tags", {}).get("latest", "")
    ver_data = data.get("versions", {}).get(latest, {})
    created = data.get("time", {}).get("created", "")
    return {
        "found":       True,
        "version":     latest,
        "description": data.get("description", ""),
        "created":     created[:10] if created else "",
        "scripts":     ver_data.get("scripts", {}),
        "maintainers": [m.get("name","") for m in data.get("maintainers", [])[:5]],
        "unpublished": "unpublished" in data,
    }


def _npm_downloads(pkg):
    """Last-month download count from npm stats API. Returns -1 on failure."""
    data = _get(f"https://api.npmjs.org/downloads/point/last-month/{urllib.parse.quote(pkg)}")
    if data is None:
        return -1
    return data.get("downloads", -1)


def _pypi_meta(pkg):
    data = _get(f"https://pypi.org/pypi/{urllib.parse.quote(pkg, safe='')}/json")
    if data is None:
        return {"found": False}
    info = data.get("info", {})
    # Grab the earliest upload date across all releases
    releases = data.get("releases", {})
    first_upload = ""
    for files in releases.values():
        for f in files:
            t = f.get("upload_time", "")
            if t and (not first_upload or t < first_upload):
                first_upload = t
    return {
        "found":       True,
        "version":     info.get("version", ""),
        "description": info.get("summary", ""),
        "author":      info.get("author", ""),
        "home_page":   info.get("home_page") or info.get("project_url") or "",
        "created":     first_upload[:10] if first_upload else "",
        "classifiers": info.get("classifiers", []),
        "requires_python": info.get("requires_python") or "",
    }


def _crates_meta(pkg):
    data = _get(f"https://crates.io/api/v1/crates/{urllib.parse.quote(pkg)}")
    if data is None:
        return {"found": False}
    crate = data.get("crate", {})
    return {
        "found":       True,
        "version":     crate.get("newest_version", ""),
        "description": crate.get("description", ""),
        "created":     (crate.get("created_at") or "")[:10],
        "downloads":   crate.get("downloads", -1),
    }


def _gem_meta(pkg):
    data = _get(f"https://rubygems.org/api/v1/gems/{urllib.parse.quote(pkg)}.json")
    if data is None:
        return {"found": False}
    return {
        "found":       True,
        "version":     data.get("version", ""),
        "description": data.get("info", ""),
        "downloads":   data.get("downloads", -1),
    }


def _nuget_meta(pkg):
    # NuGet's registration API returns a big blob; we just want to know
    # if the package exists and what the latest version is.
    data = _get(
        f"https://api.nuget.org/v3/registration5/{pkg.lower()}/index.json"
    )
    if data is None:
        return {"found": False}
    try:
        latest = data["items"][-1]["upper"]
        desc = data["items"][0]["items"][0]["catalogEntry"].get("description","")
    except (KeyError, IndexError):
        latest = ""
        desc = ""
    return {"found": True, "version": latest, "description": desc}


def _packagist_meta(pkg):
    # composer packages are vendor/name
    if "/" not in pkg:
        return {"found": None, "description": "composer packages should be vendor/name"}
    data = _get(f"https://repo.packagist.org/p2/{urllib.parse.quote(pkg, safe='/')}.json")
    if data is None:
        return {"found": False}
    try:
        versions = list(data["packages"][pkg].keys())
        latest = versions[0] if versions else ""
    except (KeyError, IndexError):
        latest = ""
    return {"found": True, "version": latest, "description": ""}


# go module proxy is trickier — module paths contain slashes and version
# info is separate from the module path.
def _go_meta(pkg):
    # Strip version suffix (@v1.2.3)
    mod_path = pkg.split("@")[0]
    # The proxy returns version list
    quoted = urllib.parse.quote(mod_path, safe="/")
    data = _get(f"https://proxy.golang.org/{quoted}/@latest")
    if data is None:
        # 404 means module not found or not cached
        return {"found": None, "description": ""}
    return {
        "found":   True,
        "version": data.get("Version", ""),
        "description": "",
    }


# ---------------------------------------------------------------------------
# OSV.dev — free and covers all ecosystems we care about
# ---------------------------------------------------------------------------

_OSV_ECOSYSTEM = {
    "npm": "npm", "yarn": "npm", "pnpm": "npm",
    "pip": "PyPI", "pip3": "PyPI", "uv": "PyPI",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "go": "Go",
    "composer": "Packagist",
    "nuget": "NuGet", "dotnet": "NuGet",
}


def _osv_vulns(pkg, pm):
    eco = _OSV_ECOSYSTEM.get(pm, "")
    if not eco:
        return []
    result = _post(
        "https://api.osv.dev/v1/query",
        {"package": {"name": pkg, "ecosystem": eco}},
    )
    if result is None:
        return []
    return result.get("vulns", [])


# ---------------------------------------------------------------------------
# Typosquatting
# ---------------------------------------------------------------------------

def _levenshtein(a, b):
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _typosquatting_candidates(pkg, pm):
    if pm in ("npm", "yarn", "pnpm"):
        pool = _TOP_NPM
    elif pm in ("pip", "pip3", "uv"):
        pool = _TOP_PIP
    elif pm == "cargo":
        pool = _TOP_CARGO
    elif pm == "gem":
        pool = _TOP_GEMS
    else:
        return []

    name = pkg.lower()
    # Strip npm scopes for comparison (@babel/core -> core, babel/core -> core)
    if name.startswith("@"):
        name = name.split("/", 1)[-1]

    hits = []
    for ref in pool:
        ref_l = ref.lower()
        if name == ref_l:
            return []  # exact match, not a typo
        dist = _levenshtein(name, ref_l)
        # Threshold: 1 edit for names <= 6 chars, 2 for 7-12, 3 for longer
        threshold = 1 if len(name) <= 6 else (2 if len(name) <= 12 else 3)
        if 0 < dist <= threshold:
            hits.append(ref)
    return hits[:4]


# ---------------------------------------------------------------------------
# Install script analysis
# ---------------------------------------------------------------------------

def _bad_scripts(scripts):
    """scripts: dict of {name: command_string}"""
    findings = []
    for script_name, cmd in scripts.items():
        for pattern, desc in _BAD_SCRIPT_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                findings.append((script_name, desc, cmd[:120]))
                break  # one finding per script is enough
    return findings


# ---------------------------------------------------------------------------
# Package age check
# ---------------------------------------------------------------------------

def _days_old(date_str):
    """date_str: YYYY-MM-DD or ISO-8601 prefix.  Returns -1 if unparseable."""
    if not date_str:
        return -1
    try:
        d = datetime.fromisoformat(date_str[:10])
        return (datetime.now() - d).days
    except Exception:
        return -1


# ---------------------------------------------------------------------------
# Namespace squatting check (npm scoped packages)
#
# Attack pattern: official package is @company/tool, attacker publishes
# company-tool or companytool to catch people who drop the scope.
# ---------------------------------------------------------------------------

def _check_namespace(pkg, pm):
    if pm not in ("npm", "yarn", "pnpm"):
        return []
    if pkg.startswith("@"):
        # Scoped package — check if there's also an unscoped version that
        # could shadow it (less common direction but worth flagging)
        return []
    warnings = []
    # Check if a popular scoped equivalent exists
    # e.g. "babel-core" while "@babel/core" is the real thing
    scoped_equivalents = {
        "babel-core": "@babel/core",
        "babel-cli": "@babel/cli",
        "babel-preset-env": "@babel/preset-env",
        "babel-plugin-transform-runtime": "@babel/plugin-transform-runtime",
    }
    if pkg.lower() in scoped_equivalents:
        warnings.append(
            f"'{pkg}' — the maintained version is '{scoped_equivalents[pkg.lower()]}'"
        )
    return warnings


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------

def scan_package(pkg_spec, pm, auto_yes):
    """
    Scan a single package spec.
    Returns True if installation should proceed, False to abort.
    """
    # Strip version specifier.  Handles pkg>=1.0, pkg@^1.0, pkg:1.0, etc.
    pkg = re.split(r"[>=<!@^~\[:]", pkg_spec)[0].strip()
    if not pkg:
        return True

    print(f"\n{C}{B}[ {pkg} ]{RST}  ({pm})")

    issues = []     # list of (level, message)  — "high", "warn", "info"
    meta = {}

    # --- 1. Known-bad list (fast path, no network needed) ---
    bad = KNOWN_BAD.get(pkg.lower()) or KNOWN_BAD.get(pkg)
    if bad:
        note, sev = bad
        issues.append(("high", f"KNOWN BAD PACKAGE: {note}"))

    # --- 2. Typosquatting ---
    typos = _typosquatting_candidates(pkg, pm)
    if typos:
        issues.append(("high", f"Possible typosquat of: {', '.join(typos)}"))

    # --- 3. Namespace squatting ---
    for w in _check_namespace(pkg, pm):
        issues.append(("warn", w))

    # --- 4. OSV vulnerability check ---
    print(f"  {D}checking OSV...{RST}", end="", flush=True)
    vulns = _osv_vulns(pkg, pm)
    print(f"\r  OSV: ", end="")
    if vulns:
        # Try to extract a rough severity from CVSS vectors.
        # OSV gives us strings like "CVSS:3.1/AV:N/AC:L/..." not numeric scores.
        # Look for the C(onfidentiality)/I(ntegrity)/A(vailability) impact values —
        # if any of them is :H that's a high-impact vuln.
        has_high_impact = False
        for v in vulns:
            for s in v.get("severity", []):
                vec = s.get("score", "")
                if re.search(r"[CIA]:H", vec):
                    has_high_impact = True
                    break

        label = f"{len(vulns)} vuln(s)"
        if has_high_impact:
            label += f"  [{R}HIGH IMPACT{RST}]"
            issues.append(("warn", f"{len(vulns)} CVE(s), includes high-impact vulnerabilities"))
        elif len(vulns) >= 5:
            issues.append(("warn", f"{len(vulns)} known CVE(s) — that's a lot"))
        else:
            issues.append(("info", f"{len(vulns)} known CVE(s)"))
        print(f"{Y}{label}{RST}        ")
    else:
        print(f"{G}clean{RST}        ")

    # --- 5. Registry metadata ---
    print(f"  {D}checking registry...{RST}", end="", flush=True)

    if pm in ("npm", "yarn", "pnpm"):
        meta = _npm_meta(pkg)
    elif pm in ("pip", "pip3", "uv"):
        meta = _pypi_meta(pkg)
    elif pm == "cargo":
        meta = _crates_meta(pkg)
    elif pm == "gem":
        meta = _gem_meta(pkg)
    elif pm in ("nuget", "dotnet"):
        meta = _nuget_meta(pkg)
    elif pm == "composer":
        meta = _packagist_meta(pkg)
    elif pm == "go":
        meta = _go_meta(pkg)
    else:
        meta = {"found": None}

    print(f"\r  registry: ", end="")

    if meta.get("found") is False:
        print(f"{R}NOT FOUND{RST}        ")
        issues.append(("high", "package not found on registry — dependency confusion? phantom package?"))
    elif meta.get("found") is True:
        ver = meta.get("version", "")
        print(f"{G}found{RST} (v{ver})        ")

        if meta.get("unpublished"):
            issues.append(("high", "package has been unpublished from registry"))

        # Age check — very new packages in a high-risk context are worth flagging
        age = _days_old(meta.get("created", ""))
        if 0 <= age < 7:
            issues.append(("high", f"package is only {age} day(s) old — brand new packages are a common attack vector"))
        elif 0 <= age < 30:
            issues.append(("warn", f"package is only {age} days old"))

        # Download count sanity check (npm and crates.io)
        downloads = meta.get("downloads", -1)
        if pm in ("npm", "yarn", "pnpm") and downloads == -1:
            downloads = _npm_downloads(pkg)
        if downloads == 0:
            issues.append(("warn", "zero downloads on record — never been installed before"))
        elif 0 < downloads < 50:
            issues.append(("warn", f"only {downloads} downloads ever — unusually low"))

        # Install script analysis (npm/yarn/pnpm)
        bad_scripts = _bad_scripts(meta.get("scripts", {}))
        if bad_scripts:
            for sname, desc, _ in bad_scripts:
                issues.append(("warn", f"install script '{sname}' does: {desc}"))

    else:
        # found is None = check failed or not supported
        print(f"{D}check failed{RST}        ")

    # --- Display results ---
    print()
    if meta.get("description"):
        print(f"  {D}{meta['description'][:100]}{RST}")
    if meta.get("maintainers"):
        print(f"  {D}maintainers: {', '.join(meta['maintainers'])}{RST}")
    if meta.get("created"):
        print(f"  {D}first published: {meta['created']}{RST}")
    if vulns:
        print()
        for v in vulns[:3]:
            vid = v.get("aliases", [v.get("id","?")])[0]
            summary = v.get("summary","")[:75]
            sevs = v.get("severity",[])
            cvss = f" [{sevs[0]['score']}]" if sevs else ""
            print(f"  {R}!{RST} {vid}{cvss}: {summary}")
        if len(vulns) > 3:
            print(f"  {D}  ... {len(vulns)-3} more at https://osv.dev{RST}")

    # --- Show issues summary ---
    high_issues = [m for lvl, m in issues if lvl == "high"]
    warn_issues = [m for lvl, m in issues if lvl == "warn"]
    info_issues = [m for lvl, m in issues if lvl == "info"]

    if issues:
        print()
    for msg in high_issues:
        print(f"  {R}[HIGH]{RST}  {msg}")
    for msg in warn_issues:
        print(f"  {Y}[WARN]{RST}  {msg}")
    for msg in info_issues:
        print(f"  {D}[INFO]  {msg}{RST}")

    if not issues:
        print(f"  {G}OK{RST}  no issues found")
        return True

    if not high_issues and not warn_issues:
        # Only info-level, proceed automatically
        return True

    if bad and bad[1] == "block":
        # Hard block — no prompt
        print(f"\n  {R}Aborting.  Remove this package from your install command.{RST}")
        return False

    if auto_yes:
        severity = "HIGH" if high_issues else "WARN"
        print(f"\n  {Y}[-y] Proceeding despite {severity} findings.{RST}")
        return True

    print()
    try:
        ans = input(f"  Proceed anyway? [y/N]  ").strip().lower()
        return ans in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        print()
        return False


# ---------------------------------------------------------------------------
# Extract package names from raw CLI arguments
# ---------------------------------------------------------------------------

# Flags that consume a following value
_NPM_VALUE_FLAGS = {
    "-w","--workspace","--tag","--otp","--access","--registry",
    "--before","--prefix","--cache","--userconfig","--globalconfig",
}

_PIP_VALUE_FLAGS = {
    "-r","--requirement","-c","--constraint","-t","--target",
    "-d","--dest","--prefix","--src","-i","--index-url",
    "--extra-index-url","--trusted-host","--proxy","--retries",
    "--timeout","--exists-action","--cert","--client-cert",
    "--cache-dir","--log","--python-version","--implementation",
    "--abi","--platform","--only-binary","--prefer-binary",
    "--config-settings","--hash","--progress-bar",
}


def _extract_npm_pkgs(args):
    pkgs, skip = [], False
    for a in args:
        if skip:
            skip = False; continue
        if a in _NPM_VALUE_FLAGS:
            skip = True; continue
        if "=" in a and a.split("=")[0] in _NPM_VALUE_FLAGS:
            continue
        if a.startswith("-"):
            continue
        pkgs.append(a)
    return pkgs


def _extract_pip_pkgs(args):
    pkgs, req_files, skip = [], [], False
    want_req = False
    for a in args:
        if skip:
            skip = False; continue
        if want_req:
            req_files.append(a); want_req = False; continue
        if a in ("-r", "--requirement"):
            want_req = True; continue
        if a in _PIP_VALUE_FLAGS:
            skip = True; continue
        if "=" in a and a.split("=")[0] in _PIP_VALUE_FLAGS:
            continue
        if a.startswith("-"):
            continue
        # Skip local paths and URLs
        if a.startswith((".", "/", "http://", "https://", "git+")) or "\\" in a:
            continue
        # Skip path-like strings (e.g. ./package, /usr/local/...)
        if os.path.exists(a):
            continue
        pkgs.append(a)
    return pkgs, req_files


def _extract_cargo_pkgs(args):
    # cargo add serde tokio --features full
    pkgs, skip = [], False
    skip_flags = {"--features","-F","--manifest-path","--target","--branch",
                  "--tag","--rev","--path","--git","--registry"}
    for a in args:
        if skip:
            skip = False; continue
        if a in skip_flags or a.split("=")[0] in skip_flags:
            if "=" not in a: skip = True
            continue
        if a.startswith("-"):
            continue
        pkgs.append(a)
    return pkgs


def _extract_gem_pkgs(args):
    pkgs, skip = [], False
    skip_flags = {"-v","--version","--source","-s","--install-dir","--bindir",
                  "-n","--pre","-g","--file","--platform"}
    for a in args:
        if skip:
            skip = False; continue
        if a in skip_flags:
            skip = True; continue
        if a.startswith("-"):
            continue
        pkgs.append(a)
    return pkgs


def _extract_generic_pkgs(args):
    """Fallback: everything that doesn't start with -"""
    return [a for a in args if not a.startswith("-") and "=" not in a]


def _read_requirements(path):
    pkgs = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(("#", "-")):
                    continue
                pkgs.append(line)
    except OSError as e:
        print(f"{Y}[!] Cannot read {path}: {e}{RST}", file=sys.stderr)
    return pkgs


# ---------------------------------------------------------------------------
# Ecosystem dispatch table
# install_cmds: subcommands that install packages (vs update, publish, etc.)
# extract_fn: parses raw args after the subcommand
# registry_note: displayed if we can't fetch registry metadata
# ---------------------------------------------------------------------------

_ECOSYSTEMS = {
    "npm":      ("install i add ci",      _extract_npm_pkgs),
    "yarn":     ("add",                   _extract_npm_pkgs),
    "pnpm":     ("add install",           _extract_npm_pkgs),
    "pip":      ("install",               None),       # pip is handled separately (req files)
    "pip3":     ("install",               None),
    "uv":       ("add",                   _extract_generic_pkgs),
    "cargo":    ("add install",           _extract_cargo_pkgs),
    "gem":      ("install",               _extract_gem_pkgs),
    "go":       ("get install",           _extract_generic_pkgs),
    "composer": ("require",               _extract_generic_pkgs),
    "nuget":    ("install",               _extract_generic_pkgs),
    "dotnet":   ("add",                   _extract_generic_pkgs),
}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    argv = list(sys.argv[1:])

    # Pull out our own flags before the package manager name
    auto_yes  = any(a in ("-y", "--yes") for a in argv)
    dry_run   = "--dry-run"   in argv
    no_check  = "--no-check"  in argv
    show_ver  = "--version"   in argv or "-V" in argv

    argv = [a for a in argv if a not in ("-y","--yes","--dry-run","--no-check","--version","-V")]

    if show_ver:
        print(f"safe-install {VERSION}")
        return

    if not argv:
        print(__doc__)
        return

    pm   = argv[0].lower()
    rest = argv[1:]

    _shell = sys.platform == "win32"

    if pm not in _ECOSYSTEMS:
        # Not an ecosystem we know — pass through unchanged
        subprocess.run([pm] + rest, shell=_shell)
        return

    install_cmds, extract_fn = _ECOSYSTEMS[pm]
    install_cmds = set(install_cmds.split())

    # Figure out the actual subcommand
    # "dotnet add package Foo" has an extra word before the package name
    subcmd = rest[0].lower() if rest else ""

    # dotnet is special: "dotnet add package <name>"
    if pm == "dotnet":
        if subcmd != "add" or len(rest) < 2:
            subprocess.run(["dotnet"] + rest, shell=_shell)
            return
        # Skip the word "package" if present
        pkg_args = rest[2:] if rest[1].lower() == "package" else rest[1:]
        original_cmd = ["dotnet"] + rest
    elif subcmd not in install_cmds:
        subprocess.run([pm] + rest, shell=_shell)
        return
    else:
        pkg_args = rest[1:]
        original_cmd = [pm] + rest

    if no_check:
        print(f"{D}[safe-install] --no-check: skipping all checks{RST}")
        subprocess.run(original_cmd, shell=_shell)
        return

    # Collect packages
    if pm in ("pip", "pip3"):
        packages, req_files = _extract_pip_pkgs(pkg_args)
        for rf in req_files:
            packages.extend(_read_requirements(rf))
    elif pm == "uv":
        # "uv add" uses simple package names, no -r support
        packages = _extract_generic_pkgs(pkg_args)
    elif extract_fn is not None:
        packages = extract_fn(pkg_args)
    else:
        packages = _extract_generic_pkgs(pkg_args)

    packages = list(dict.fromkeys(p for p in packages if p))  # dedup, preserve order

    if not packages:
        print(f"{D}[safe-install] No packages to check — running directly{RST}")
        subprocess.run(original_cmd, shell=_shell)
        return

    print(f"\n{B}[safe-install] Scanning {len(packages)} package(s) — {pm}{RST}")

    aborted = []
    for pkg in packages:
        ok = scan_package(pkg, pm, auto_yes)
        if not ok:
            aborted.append(pkg)

    print()
    if aborted:
        print(f"{R}{B}Aborted.{RST} Blocked packages: {', '.join(aborted)}")
        if not dry_run:
            sys.exit(1)
        return

    if dry_run:
        print(f"{G}Dry run complete — all checks passed.{RST}")
        return

    print(f"{G}{B}All checks passed.{RST} Running:")
    print(f"  {D}{' '.join(original_cmd)}{RST}\n")
    result = subprocess.run(original_cmd, shell=_shell)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
