# safe-install

Pre-flight security check for package managers.  Scans packages against
known-malicious databases, detects typosquatting, checks for CVEs, and
flags suspicious install scripts — all before anything touches your system.

```
$ safe-install npm install react-dom lodash
  [ react-dom ]  (npm)
    OSV: clean
    registry: found (v19.1.0)
    OK  no issues found

  [ lodash ]  (npm)
    OSV: 10 vuln(s)  [HIGH IMPACT]
    registry: found (v4.18.1)
    [WARN]  10 CVE(s), includes high-impact vulnerabilities
    Proceed anyway? [y/N]
```

## What it catches

| Check | What it does |
|-------|-------------|
| **Known-bad list** | Instant block on ~35 packages confirmed malicious in the wild (node-ipc, colourama, ua-parser-js, etc.) |
| **Typosquatting** | Levenshtein distance against top packages per ecosystem |
| **Homoglyph detection** | Catches Unicode lookalike attacks (Cyrillic `e` in `rеquests`) that Levenshtein misses |
| **CVE/vulnerability** | Queries [OSV.dev](https://osv.dev/) — free, no API key needed |
| **Install scripts** | Regex scan for network downloads, eval, reverse shells, exfil patterns in declared scripts |
| **Source code scan** | Downloads the actual tarball and scans source files for env exfil, obfuscated payloads, credential access, reverse shells, crypto miners, persistence mechanisms |
| **GitHub repo check** | Verifies linked repo exists and isn't a [starjacking](https://snyk.io/blog/open-source-npm-packages-colors-702k/) attempt |
| **Version anomaly** | Flags single-version packages and suspiciously high major versions (dependency confusion) |
| **Package age** | Flags packages less than 7 days old (common attack vector) |
| **Download count** | Warns on suspiciously low download numbers |
| **Registry existence** | Catches dependency confusion and phantom packages |
| **Namespace squatting** | Detects unscoped npm packages shadowing scoped ones (e.g. `babel-core` vs `@babel/core`) |
| **Whitelist** | Lock down to approved packages only — the strongest defense for teams |

## Supported package managers

`npm` `yarn` `pnpm` `pip` `pip3` `uv` `cargo` `gem` `go` `composer` `nuget` `dotnet`

## Install

No dependencies — just Python 3.8+ and the standard library.

```bash
pip install git+https://github.com/St4mpde/safe-install.git
```

That's it.  Now you have `si` and `safe-install` commands globally.

**Or with [pipx](https://pipx.pypa.io/) (isolated install):**
```bash
pipx install git+https://github.com/St4mpde/safe-install.git
```

**Or just clone and run directly:**
```bash
git clone https://github.com/St4mpde/safe-install.git
cd safe-install
pip install .
```

## Usage

```bash
# basic — just prefix your normal install command
si npm install express lodash
si pip install requests flask
si cargo add serde tokio
si gem install rails

# skip confirmation prompts (CI / automation)
si -y pip install -r requirements.txt

# check only, don't actually install
si --dry-run npm install react

# skip source tarball scan (faster, still runs all other checks)
si --no-scan pip install numpy

# whitelist mode — only allow approved packages
si --whitelist approved.txt npm install react

# bypass all checks (emergency)
si --no-check npm install something-urgent

# version
si --version
```

`safe-install` recognizes install subcommands for each package manager
(`install`, `add`, `i`, `require`, `get`, etc.) and passes everything
else through unchanged — so `si npm publish` just runs `npm publish`.

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SI_TIMEOUT` | `12` | API request timeout in seconds |
| `SI_WHITELIST` | — | Path to whitelist file (one package name per line) |
| `NO_COLOR` | — | Disable colored output ([no-color.org](https://no-color.org/)) |
| `SI_NO_COLOR` | — | Same as above |

Default whitelist location (auto-loaded if it exists):
`~/.config/safe-install/whitelist.txt`

## How it works

For each package in your install command, `safe-install` runs these checks
in order:

0. **Whitelist gate** — if a whitelist is active, unlisted packages are
   blocked before any other check runs.
1. **Known-bad lookup** — instant dict lookup against ~35 packages confirmed
   malicious or sabotaged.  Hard-blocked packages abort even with `-y`.
2. **Typosquatting** — Levenshtein distance against the top ~100 packages
   in the relevant ecosystem.
3. **Homoglyph detection** — normalizes confusable Unicode characters
   (Cyrillic, Greek, math symbols) and re-checks against popular names.
4. **Namespace check** — npm-specific scoped vs unscoped package confusion.
5. **OSV.dev query** — checks for known CVEs.  Covers npm, PyPI, crates.io,
   RubyGems, Go, Packagist, and NuGet.
6. **Registry metadata** — checks if the package actually exists, how old it
   is, download counts, and what install scripts it declares.
7. **GitHub repo verification** — confirms the linked repo exists and the name
   matches (starjacking detection).
8. **Version anomaly** — flags single-version packages and absurdly high
   major versions (dependency confusion pattern).
9. **Source code scan** — downloads the tarball, extracts it, and scans every
   source file for ~30 malicious patterns (env exfil, obfuscated payloads,
   credential access, reverse shells, persistence, crypto miners).

Results are aggregated and the package gets one of three verdicts:
- **OK** — no issues, install proceeds automatically
- **WARN/HIGH** — issues found, user is prompted (unless `-y`)
- **BLOCK** — known-bad package, aborted unconditionally

Only then does the actual package manager command run.

## Limitations

This is a best-effort pre-install filter, not a comprehensive supply chain
audit tool.  Things it does **not** do:

- Scan transitive dependencies (only checks what you explicitly install)
- Analyze compiled binaries or native extensions inside packages
- Verify package signatures or checksums
- Monitor for post-install runtime behavior
- Detect zero-day attacks with no known signature

For production environments, combine this with a lockfile, hash pinning,
and a proper SBOM audit pipeline.

## License

MIT
