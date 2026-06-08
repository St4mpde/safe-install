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
#   --no-scan      skip source tarball download + analysis (faster)
#   --whitelist F  only allow packages listed in file F

import sys
import os
import json
import re
import subprocess
import urllib.request
import urllib.error
import urllib.parse
import tempfile
import tarfile
import zipfile
import shutil
from datetime import datetime, timezone

VERSION = "2.1.0"

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

try:
    _API_TIMEOUT = int(os.environ.get("SI_TIMEOUT", "12"))
except ValueError:
    _API_TIMEOUT = 12

# Per-session registry data cache.  Avoids hitting the same registry
# endpoint 3-4x for the same package (meta, version check, github check,
# source tarball URL all need the same data).
_registry_cache = {}


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


def _get_cached(url, timeout=None):
    """GET with per-session cache — use for registry endpoints that get
    hit multiple times for the same package."""
    if url in _registry_cache:
        return _registry_cache[url]
    result = _get(url, timeout)
    _registry_cache[url] = result  # cache None too to avoid retrying dead endpoints
    return result


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
    data = _get_cached(f"https://registry.npmjs.org/{urllib.parse.quote(pkg, safe='@%')}")
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
    data = _get_cached(f"https://pypi.org/pypi/{urllib.parse.quote(pkg, safe='')}/json")
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
        return {"found": False, "description": ""}
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
        # Parse as naive date (YYYY-MM-DD) and compare against today
        d = datetime.strptime(date_str[:10], "%Y-%m-%d")
        return (datetime.utcnow() - d).days
    except (ValueError, TypeError):
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
# Homoglyph / confusable character detection
#
# Unicode substitution attacks: "rеquests" uses Cyrillic е (U+0435)
# instead of Latin e (U+0065).  Levenshtein sees 0 edits because the
# glyph count is the same.  We normalize confusable chars to ASCII and
# re-check against popular packages.
# ---------------------------------------------------------------------------

# Map of Unicode chars that look like ASCII letters to their ASCII equivalent.
# This covers the most common attack vectors (Cyrillic, Greek, math symbols).
# Not exhaustive — there are 4000+ confusables in Unicode — but these are the
# ones that actually show up in package name attacks.
_CONFUSABLES = str.maketrans({
    # Cyrillic -> Latin
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0458": "j", "\u04bb": "h", "\u0455": "s", "\u0442": "t",
    "\u0432": "v", "\u043a": "k", "\u043c": "m", "\u043d": "n",
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K",
    "\u041c": "M", "\u041d": "H", "\u041e": "O", "\u0420": "P",
    "\u0421": "C", "\u0422": "T", "\u0425": "X",
    # Greek -> Latin
    "\u03b1": "a", "\u03b5": "e", "\u03b9": "i", "\u03bf": "o",
    "\u03c1": "p", "\u03c5": "u", "\u03ba": "k", "\u03bd": "v",
    # Common lookalikes
    "\u0131": "i",  # dotless i
    "\u0049": "I",  # sometimes capital I is used for lowercase l
    "\u006c": "l",  # itself, but check I/l confusion:
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-",
    "\u2014": "-", "\u2212": "-",  # various dashes -> hyphen
    "\uff0d": "-",  # fullwidth hyphen
    "\u2024": ".", "\uff0e": ".",  # one-dot leader, fullwidth period
    "\uff3f": "_", "\u2017": "_",  # fullwidth underscore, double-low-line
})


def _normalize_confusables(name):
    """Normalize confusable Unicode characters to ASCII."""
    return name.translate(_CONFUSABLES)


def _check_homoglyphs(pkg, pm):
    """Detect Unicode character substitution attacks."""
    normalized = _normalize_confusables(pkg)
    if normalized == pkg:
        return []  # no confusable characters present

    # The name contained non-ASCII lookalikes.  Check if the normalized
    # form matches a known popular package.
    if pm in ("npm", "yarn", "pnpm"):
        pool = _TOP_NPM
    elif pm in ("pip", "pip3", "uv"):
        pool = _TOP_PIP
    elif pm == "cargo":
        pool = _TOP_CARGO
    elif pm == "gem":
        pool = _TOP_GEMS
    else:
        pool = []

    norm_lower = normalized.lower()
    for ref in pool:
        if norm_lower == ref.lower():
            return [f"contains Unicode lookalike characters — looks like '{ref}' but isn't"]
    # Even if we don't find a match in our list, the presence of confusable
    # chars in a package name is suspicious on its own.
    return [f"contains confusable Unicode characters (normalized: '{normalized}')"]


# ---------------------------------------------------------------------------
# Source tarball analysis
#
# This is the heavy check.  We download the actual package archive and
# scan the source files for patterns that show up in real supply chain
# attacks: env var exfiltration, obfuscated payloads, reverse shells,
# credential file access, etc.
#
# Only runs for npm and pip packages (others don't have a convenient
# single-tarball download).  Skip with --no-scan.
# ---------------------------------------------------------------------------

# Patterns to look for in source files.  These are regex patterns, each with
# a severity and a short description.  We scan up to 50KB per file.
_SOURCE_SCAN_PATTERNS = [
    # Environment variable theft — the #1 payload in npm/pip malware
    (r"process\.env\b.{0,80}(http|fetch|request|axios|got\(|\.send|\.post)",
     "high", "reads process.env and makes HTTP request (env exfil pattern)"),
    (r"os\.environ\b.{0,80}(urlopen|requests?\.|httpx\.|urllib|http\.client)",
     "high", "reads os.environ and makes HTTP request (env exfil pattern)"),

    # Obfuscated code — long base64/hex blobs are a dead giveaway
    (r"['\"][A-Za-z0-9+/]{200,}={0,2}['\"]",
     "high", "large base64-encoded string (>200 chars) — likely obfuscated payload"),
    (r"['\"][0-9a-fA-F]{200,}['\"]",
     "high", "large hex-encoded string (>200 chars) — likely obfuscated payload"),
    (r"eval\s*\(\s*Buffer\.from\s*\(",
     "high", "eval(Buffer.from(...)) — obfuscated execution"),
    (r"exec\s*\(\s*(?:compile|bytes\.fromhex|codecs\.decode)",
     "high", "exec(compile/fromhex/decode(...)) — obfuscated Python execution"),

    # Reverse shells and C2 callbacks
    (r"(?:net\.Socket|dgram\.createSocket|new\s+WebSocket)\s*\(.{0,60}\d{1,3}\.\d{1,3}\.",
     "high", "network socket opened to hardcoded IP address"),
    (r"socket\.(?:connect|create_connection)\s*\(\s*\(.{0,40}\d{1,3}\.\d{1,3}\.",
     "high", "Python socket to hardcoded IP"),
    (r"/bin/(?:ba)?sh.{0,20}-[ic]\b",
     "high", "shell invocation with -i/-c (reverse shell pattern)"),

    # Credential file access — reading SSH keys, AWS creds, etc.
    (r"\.ssh[/\\](?:id_rsa|id_ed25519|id_ecdsa|known_hosts|authorized_keys)",
     "high", "accesses SSH key files"),
    (r"\.aws[/\\]credentials|\.aws[/\\]config",
     "high", "accesses AWS credential files"),
    (r"\.npmrc\b",
     "warn", "accesses .npmrc (may contain auth tokens)"),
    (r"\.pypirc\b",
     "warn", "accesses .pypirc (may contain auth tokens)"),
    (r"\.docker[/\\]config\.json",
     "warn", "accesses Docker config (may contain registry auth)"),
    (r"\.kube[/\\]config",
     "warn", "accesses kubeconfig"),
    (r"\.gnupg[/\\]",
     "warn", "accesses GPG keyring"),

    # Crypto mining
    (r"stratum\+tcp://",
     "high", "stratum mining pool connection"),
    (r"(?:xmr|monero|coinhive|cryptonight)",
     "warn", "possible cryptominer reference"),

    # Exfil channels
    (r"discord(?:app)?\.com/api/webhooks/\d+/",
     "high", "Discord webhook URL (exfiltration channel)"),
    (r"api\.telegram\.org/bot[A-Za-z0-9:_-]+/send",
     "high", "Telegram bot API call (exfiltration channel)"),

    # DNS exfiltration
    (r"dns\.resolve.*TXT\b|TXT.*dns\.resolve",
     "warn", "DNS TXT resolution (possible DNS exfil)"),

    # Persistence mechanisms
    (r"(?:HKEY_CURRENT_USER|HKCU|HKLM).{0,40}\\Run\b",
     "high", "Windows registry Run key (persistence mechanism)"),
    (r"crontab\s+-|/etc/cron",
     "high", "crontab modification (persistence mechanism)"),
    (r"\.bashrc|\.bash_profile|\.profile|\.zshrc",
     "warn", "modifies shell profile (possible persistence)"),
    (r"LaunchAgents|LaunchDaemons",
     "high", "macOS LaunchAgent/Daemon (persistence mechanism)"),
    (r"(?:systemd|systemctl).{0,30}enable",
     "high", "systemd service installation (persistence)"),

    # Suspicious network calls with hardcoded IPs
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:/]",
     "warn", "HTTP request to raw IP address"),
]


def _get_tarball_url(pkg, pm, meta):
    """Return (url, format) for the package tarball, or (None, None)."""
    if pm in ("npm", "yarn", "pnpm"):
        # npm registry includes the tarball URL in the version metadata
        ver = meta.get("version", "")
        if not ver:
            return None, None
        data = _get(f"https://registry.npmjs.org/{urllib.parse.quote(pkg, safe='@%')}/{ver}")
        if data and data.get("dist", {}).get("tarball"):
            return data["dist"]["tarball"], "tgz"
        return None, None

    elif pm in ("pip", "pip3", "uv"):
        data = _get_cached(f"https://pypi.org/pypi/{urllib.parse.quote(pkg, safe='')}/json")
        if not data:
            return None, None
        # Prefer sdist (tar.gz) over wheel — wheels are zips with less source to scan
        for finfo in data.get("urls", []):
            if finfo.get("packagetype") == "sdist":
                return finfo["url"], "tgz"
        # Fall back to first wheel
        for finfo in data.get("urls", []):
            if finfo.get("filename", "").endswith(".whl"):
                return finfo["url"], "whl"
        return None, None

    return None, None


def _is_scannable(filename):
    """Should we scan this file for suspicious patterns?"""
    # Only scan text-ish source files, not images/binaries/minified bundles
    exts = {
        ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx",
        ".py", ".pyw",
        ".sh", ".bash", ".zsh", ".fish", ".bat", ".cmd", ".ps1",
        ".rb", ".rs", ".go", ".php", ".pl", ".lua",
        ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini",
    }
    _, ext = os.path.splitext(filename.lower())
    if ext in exts:
        return True
    # Also scan files with no extension (often shell scripts)
    if not ext and not filename.startswith("."):
        return True
    return False


_TRUSTED_TARBALL_HOSTS = {
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "files.pythonhosted.org",
    "pypi.org",
    "crates.io",
    "static.crates.io",
    "rubygems.org",
}


def _safe_extract_zip(archive_path, dest):
    """Extract zip/whl with path traversal protection (zip slip)."""
    dest_real = os.path.realpath(dest)
    with zipfile.ZipFile(archive_path) as zf:
        for info in zf.infolist():
            target = os.path.realpath(os.path.join(dest, info.filename))
            if not target.startswith(dest_real + os.sep) and target != dest_real:
                continue  # silently skip path traversal entries
            zf.extract(info, dest)


def _safe_extract_tar(archive_path, dest):
    """Extract tar.gz/tgz with path traversal + symlink protection."""
    dest_real = os.path.realpath(dest)
    with tarfile.open(archive_path, "r:*") as tf:
        for member in tf.getmembers():
            # Block symlinks — they can point outside the extraction dir
            if member.issym() or member.islnk():
                continue
            target = os.path.realpath(os.path.join(dest, member.name))
            if not target.startswith(dest_real + os.sep) and target != dest_real:
                continue  # path traversal attempt
            tf.extract(member, dest)


def _scan_source(pkg, pm, meta):
    """
    Download package tarball, extract, scan source files for malicious patterns.
    Returns list of (severity, message) tuples.
    """
    url, fmt = _get_tarball_url(pkg, pm, meta)
    if not url:
        return []

    # Validate tarball URL domain to prevent SSRF via compromised registry data
    try:
        host = urllib.parse.urlparse(url).hostname or ""
        if host not in _TRUSTED_TARBALL_HOSTS:
            return [("warn", f"tarball URL points to untrusted host: {host}")]
    except Exception:
        return [("warn", "could not parse tarball URL")]

    tmpdir = tempfile.mkdtemp(prefix="si_scan_")
    try:
        # Download
        archive_path = os.path.join(tmpdir, f"pkg.{fmt}")
        try:
            urllib.request.urlretrieve(url, archive_path)
        except Exception:
            return [("info", "could not download package for source scan")]

        # Size gate — skip anything over 10MB to keep scans fast
        if os.path.getsize(archive_path) > 10 * 1024 * 1024:
            return [("info", "package >10MB, skipping source scan")]

        # Extract with path traversal protection
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir, exist_ok=True)
        try:
            if fmt == "whl":
                _safe_extract_zip(archive_path, src_dir)
            else:
                _safe_extract_tar(archive_path, src_dir)
        except Exception:
            return [("info", "could not extract package for source scan")]

        # Scan
        findings = []
        seen_messages = set()
        files_scanned = 0
        for root, dirs, files in os.walk(src_dir):
            # Skip node_modules and __pycache__ if somehow present
            dirs[:] = [d for d in dirs if d not in ("node_modules", "__pycache__", ".git")]
            for fname in files:
                if not _is_scannable(fname):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read(50_000)  # first 50KB per file
                except Exception:
                    continue
                files_scanned += 1
                for pattern, sev, desc in _SOURCE_SCAN_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        # Deduplicate: only report each pattern type once
                        if desc not in seen_messages:
                            seen_messages.add(desc)
                            rel = os.path.relpath(fpath, src_dir)
                            findings.append((sev, f"{desc}  [{rel}]"))
                            if len(findings) >= 15:
                                return findings  # cap output
        return findings

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# GitHub repo verification (starjacking / link fraud detection)
#
# If the registry metadata links to a GitHub repo, check that:
# 1. The repo actually exists
# 2. It was not recently transferred or is archived
# 3. The description/topics somewhat relate to the package
# This catches starjacking where an attacker sets their malicious
# package's repo URL to point at a popular unrelated project.
# ---------------------------------------------------------------------------

def _check_github_repo(pkg, meta, pm):
    """Returns list of (severity, message) tuples."""
    issues = []

    # Extract GitHub URL from registry metadata
    repo_url = ""
    if pm in ("npm", "yarn", "pnpm"):
        data = _get_cached(f"https://registry.npmjs.org/{urllib.parse.quote(pkg, safe='@%')}")
        if data:
            repo = data.get("repository", {})
            if isinstance(repo, dict):
                repo_url = repo.get("url", "")
            elif isinstance(repo, str):
                repo_url = repo
    elif pm in ("pip", "pip3", "uv"):
        repo_url = meta.get("home_page", "")

    if not repo_url:
        return []

    # Extract owner/repo from the URL
    m = re.search(r"github\.com[/:]([^/]+)/([^/.#]+)", repo_url)
    if not m:
        return []
    owner, repo = m.group(1), m.group(2)

    gh_data = _get(f"https://api.github.com/repos/{owner}/{repo}")
    if gh_data is None:
        issues.append(("warn", f"linked GitHub repo {owner}/{repo} does not exist or is private"))
        return issues

    if gh_data.get("archived"):
        issues.append(("warn", f"linked GitHub repo {owner}/{repo} is archived"))

    # Starjacking detection: if the repo name doesn't resemble the package name
    # at all, it might be pointing at someone else's popular repo.
    repo_name = gh_data.get("name", "").lower()
    repo_desc = (gh_data.get("description") or "").lower()
    pkg_lower = pkg.lower().replace("-", "").replace("_", "")
    repo_clean = repo_name.replace("-", "").replace("_", "")

    # Generous match: package name substring of repo name, or vice versa
    name_related = (
        pkg_lower in repo_clean
        or repo_clean in pkg_lower
        or pkg_lower in repo_desc
    )
    if not name_related and gh_data.get("stargazers_count", 0) > 500:
        # The package links to a popular repo that doesn't seem related.
        # This is the classic starjacking pattern.
        stars = gh_data["stargazers_count"]
        issues.append((
            "high",
            f"possible starjacking — links to {owner}/{repo} ({stars} stars) "
            f"but repo name doesn't match package name"
        ))

    return issues


# ---------------------------------------------------------------------------
# Version anomaly detection
# ---------------------------------------------------------------------------

def _check_version_anomaly(pkg, pm, meta):
    """Flag suspicious version patterns."""
    issues = []
    ver = meta.get("version", "")
    if not ver:
        return issues

    # Check if only one version has ever been published
    # (We can infer this cheaply from npm's time field or PyPI's releases)
    if pm in ("npm", "yarn", "pnpm"):
        data = _get_cached(f"https://registry.npmjs.org/{urllib.parse.quote(pkg, safe='@%')}")
        if data and "time" in data:
            # "time" has "created", "modified", and one entry per version
            version_count = len(data["time"]) - 2  # subtract created+modified
            if version_count == 1:
                issues.append(("warn", "only 1 version ever published"))
            elif version_count <= 0:
                issues.append(("warn", "no version history found"))
    elif pm in ("pip", "pip3", "uv"):
        data = _get_cached(f"https://pypi.org/pypi/{urllib.parse.quote(pkg, safe='')}/json")
        if data and "releases" in data:
            non_empty = sum(1 for v, files in data["releases"].items() if files)
            if non_empty == 1:
                issues.append(("warn", "only 1 release ever published"))

    # Suspicious version number: starts very high (attacker trying to win
    # "latest" in dependency confusion), or 0.0.x (throwaway test)
    try:
        major = int(ver.split(".")[0])
        if major >= 99:
            issues.append(("high",
                f"version {ver} — extremely high major version (dependency confusion pattern)"))
    except (ValueError, IndexError):
        pass

    return issues


# ---------------------------------------------------------------------------
# Whitelist support
#
# If a whitelist file is active, packages not on it are hard-blocked.
# File format: one package name per line, # comments, blank lines ignored.
# The file path can be passed with --whitelist or set via SI_WHITELIST env.
# Default location: ~/.config/safe-install/whitelist.txt
# ---------------------------------------------------------------------------

def _load_whitelist(path=None):
    """Returns a set of lowercased package names, or None if no whitelist."""
    if path is None:
        path = os.environ.get("SI_WHITELIST")
    if path is None:
        default = os.path.join(
            os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")),
            "safe-install", "whitelist.txt"
        )
        if os.path.isfile(default):
            path = default
    if path is None:
        return None
    try:
        names = set()
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    names.add(line.lower())
        return names
    except OSError as e:
        print(f"{Y}[!] Cannot read whitelist {path}: {e}{RST}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------

def scan_package(pkg_spec, pm, auto_yes, do_source_scan=True, whitelist=None):
    """
    Scan a single package spec.
    Returns True if installation should proceed, False to abort.
    """
    # Strip version specifier.  Handles pkg>=1.0, pkg@^1.0, pkg:1.0, etc.
    pkg = re.split(r"[>=<!@^~\[:]", pkg_spec)[0].strip()
    if not pkg:
        return True

    print(f"\n{C}{B}[ {pkg} ]{RST}  ({pm})")

    # --- 0. Whitelist check (instant, before anything else) ---
    if whitelist is not None and pkg.lower() not in whitelist:
        print(f"  {R}[BLOCKED]{RST}  not on whitelist")
        return False

    issues = []     # list of (level, message)  — "high", "warn", "info"
    meta = {}

    # --- 1. Known-bad list (fast path, no network needed) ---
    bad = KNOWN_BAD.get(pkg.lower()) or KNOWN_BAD.get(pkg)
    if bad:
        note, sev = bad
        issues.append(("high", f"KNOWN BAD PACKAGE: {note}"))

    # --- 2. Typosquatting (Levenshtein) ---
    typos = _typosquatting_candidates(pkg, pm)
    if typos:
        issues.append(("high", f"Possible typosquat of: {', '.join(typos)}"))

    # --- 3. Homoglyph / Unicode confusable detection ---
    for msg in _check_homoglyphs(pkg, pm):
        issues.append(("high", msg))

    # --- 4. Namespace squatting ---
    for w in _check_namespace(pkg, pm):
        issues.append(("warn", w))

    # --- 5. OSV vulnerability check ---
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

    # --- 6. Registry metadata ---
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

    # --- 7. GitHub repo verification (starjacking) ---
    if meta.get("found") and pm in ("npm","yarn","pnpm","pip","pip3","uv"):
        print(f"  {D}checking GitHub repo...{RST}", end="", flush=True)
        gh_issues = _check_github_repo(pkg, meta, pm)
        for sev, msg in gh_issues:
            issues.append((sev, msg))
        print(f"\r  GitHub: {R + str(len(gh_issues)) + ' issue(s)' + RST if gh_issues else G + 'OK' + RST}        ")

    # --- 8. Version anomaly ---
    if meta.get("found"):
        ver_issues = _check_version_anomaly(pkg, pm, meta)
        for sev, msg in ver_issues:
            issues.append((sev, msg))

    # --- 9. Source code scan ---
    if do_source_scan and meta.get("found") and pm in ("npm","yarn","pnpm","pip","pip3","uv"):
        print(f"  {D}scanning source code...{RST}", end="", flush=True)
        src_issues = _scan_source(pkg, pm, meta)
        if src_issues:
            print(f"\r  source: {R}{len(src_issues)} finding(s){RST}        ")
            for sev, msg in src_issues:
                issues.append((sev, msg))
        else:
            print(f"\r  source: {G}clean{RST}        ")

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
# Safe subprocess execution — avoids shell=True to prevent command injection
# when package names come from untrusted sources (lockfiles, CI vars, etc.)
# ---------------------------------------------------------------------------

def _run_cmd(cmd_list):
    """Run a package manager command safely.  On Windows, .cmd/.bat wrappers
    (npm.cmd, pip.cmd, etc.) need shell=True to run under cmd.exe, but
    using shell=True with user-controlled arguments is a command injection
    risk.  We resolve the executable via shutil.which() and call it directly."""
    exe = shutil.which(cmd_list[0])
    if exe is None:
        # Fall back to shell=True if we can't find the executable
        # (better than crashing — the tool is still useful)
        return subprocess.run(cmd_list, shell=True)
    return subprocess.run([exe] + cmd_list[1:])


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    argv = list(sys.argv[1:])

    # Pull out our own flags before the package manager name
    auto_yes  = any(a in ("-y", "--yes") for a in argv)
    dry_run   = "--dry-run"   in argv
    no_check  = "--no-check"  in argv
    no_scan   = "--no-scan"   in argv
    show_ver  = "--version"   in argv or "-V" in argv

    # --whitelist <path>
    wl_path = None
    for i, a in enumerate(argv):
        if a == "--whitelist" and i + 1 < len(argv):
            wl_path = argv[i + 1]
            break

    strip_flags = {"-y","--yes","--dry-run","--no-check","--no-scan","--version","-V","--whitelist"}
    new_argv = []
    skip_next = False
    for a in argv:
        if skip_next:
            skip_next = False; continue
        if a == "--whitelist":
            skip_next = True; continue
        if a in strip_flags:
            continue
        new_argv.append(a)
    argv = new_argv

    whitelist = _load_whitelist(wl_path)

    if show_ver:
        print(f"safe-install {VERSION}")
        return

    if not argv:
        print(__doc__)
        return

    pm   = argv[0].lower()
    rest = argv[1:]

    if pm not in _ECOSYSTEMS:
        # Not an ecosystem we know — pass through unchanged
        _run_cmd([pm] + rest)
        return

    install_cmds, extract_fn = _ECOSYSTEMS[pm]
    install_cmds = set(install_cmds.split())

    # Figure out the actual subcommand
    # "dotnet add package Foo" has an extra word before the package name
    subcmd = rest[0].lower() if rest else ""

    # dotnet is special: "dotnet add package <name>"
    if pm == "dotnet":
        if subcmd != "add" or len(rest) < 2:
            _run_cmd(["dotnet"] + rest)
            return
        # Skip the word "package" if present
        pkg_args = rest[2:] if rest[1].lower() == "package" else rest[1:]
        original_cmd = ["dotnet"] + rest
    elif subcmd not in install_cmds:
        _run_cmd([pm] + rest)
        return
    else:
        pkg_args = rest[1:]
        original_cmd = [pm] + rest

    if no_check:
        print(f"{D}[safe-install] --no-check: skipping all checks{RST}")
        _run_cmd(original_cmd)
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
        _run_cmd(original_cmd)
        return

    print(f"\n{B}[safe-install] Scanning {len(packages)} package(s) — {pm}{RST}")

    aborted = []
    for pkg in packages:
        ok = scan_package(pkg, pm, auto_yes, do_source_scan=not no_scan, whitelist=whitelist)
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
    result = _run_cmd(original_cmd)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
