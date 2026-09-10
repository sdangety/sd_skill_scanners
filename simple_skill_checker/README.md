# simple_skill_checker

This package lives at `simple_skill_checker/` inside the **sdaitoolkit** repo.

A lightweight, single-file static scanner for **downloaded AI skill / plugin files** (or scripts, prompt templates, config bundles). It flags the red flags you should review **before** running untrusted code in your environment.

Python 3 only. No third-party packages. One file: `skill_audit.py`.

## What `skill_audit.py` does

`skill_audit.py` reads a file or a directory and reports **static** pattern matches for: outbound network / exfiltration, credential and filesystem access, obfuscation and dynamic execution, prompt-injection text aimed at an LLM reader, dependency manifests worth a manual look, and OWASP AST01 (Malicious Skills) indicators.

It does **not** execute the code, fetch URLs, or sandbox anything. This is pattern matching, so treat a clean report as **"no obvious red flags," not "safe."** Always pair it with the manual checklist and isolation steps below.

Inputs:

- A single file (any text file: `.py`, `.js`, `.ts`, `.sh`, `.md`, `.json`, `.yaml`, `.env`, …)
- A directory — it walks recursively and skips binary/irrelevant types (`.png`, `.zip`, `.pyc`, `.so`, `.exe`, `.lock`, …)

Output is a human-readable report grouped by file, plus a severity summary. `--json` writes full results to a file.

```bash
cd simple_skill_checker   # from the sdaitoolkit repo root
python3 skill_audit.py path/to/skill-file-or-folder
python3 skill_audit.py path/to/folder --json report.json
python3 skill_audit.py path/to/folder --min-severity HIGH
```

### CLI options

| Option | Description |
|---|---|
| `path` | File or folder to scan (required) |
| `--json <file>` | Write the full findings to a JSON file |
| `--min-severity {HIGH,MEDIUM,LOW,INFO}` | Only print findings at or above this level (default `LOW`) |

### Exit behavior

The report always prints a summary counting `HIGH / MEDIUM / LOW / INFO`. If any **HIGH** findings exist, it prints a warning that the skill should not be run until each is manually reviewed. The path-not-found case exits `1`.

## Checks performed

Each finding has an `id`, a severity (`HIGH` / `MEDIUM` / `LOW` / `INFO`), the line number, a description, and the matching snippet.

### Network / exfiltration

| Rule | Severity | What it flags |
|---|---|---|
| `NET-001` | HIGH | Outbound HTTP call (`requests.post/put/get`, `urllib.request`, `httpx`, `fetch(`, `axios`, `XMLHttpRequest`) |
| `NET-002` | HIGH | Shell download/upload via `curl` / `wget` (`-o`, `-O`, `>`, `--output`) |
| `NET-003` | MEDIUM | Raw socket usage (`socket.socket` / `socket.connect`) |
| `NET-004` | HIGH | URL pointing to a known exfil/relay service (ngrok, pastebin, transfer.sh, webhook.site, requestbin) |
| `NET-005` | LOW | Hardcoded URL — verify it's the tool's official domain |

### Credential / sensitive file access

| Rule | Severity | What it flags |
|---|---|---|
| `CRED-001` | HIGH | SSH/AWS/GPG credential paths (`~/.ssh`, `.aws/credentials`, `~/.gnupg`, `id_rsa`, `id_ed25519`) |
| `CRED-002` | HIGH | Reads environment variables or `.env` (`os.environ`, `process.env`) |
| `CRED-003` | HIGH | Browser cookie/credential storage (`Cookies`, `Login Data`, `cookies.sqlite`, Local Storage leveldb) |
| `CRED-004` | MEDIUM | Broad filesystem scan from root (`os.walk('/')`, `find / -name`, `Get-ChildItem -Recurse C:\`) |

### Obfuscation / dynamic execution

| Rule | Severity | What it flags |
|---|---|---|
| `OBF-001` | HIGH | Dynamic code execution (`exec(`, `eval(`, `new Function(`, `atob(`) |
| `OBF-002` | MEDIUM | Base64 decoding (`base64.b64decode`, `Buffer.from(..., 'base64')`) |
| `OBF-003` | MEDIUM | Shell-out / subprocess (`subprocess.*`, `child_process.*`, `os.system(`) |
| `OBF-004` | LOW | Long base64-like blob (≥80 chars) — inspect manually |

### Prompt injection aimed at the LLM reading the file

| Rule | Severity | What it flags |
|---|---|---|
| `PI-001` | HIGH | "ignore previous/prior/above instructions" |
| `PI-002` | HIGH | Instruction to send/exfiltrate/upload/email the user's files, data, credentials, secrets |
| `PI-003` | MEDIUM | "do not tell / inform / mention to the user" |
| `PI-004` | MEDIUM | Suspicious instruction hidden in an HTML/XML comment |

### Dependency manifests

| Rule | Severity | What it flags |
|---|---|---|
| `DEP-001` | INFO | Dependency entry (only in `requirements.txt`, `package.json`, `pyproject.toml`, `Gemfile`, `go.mod`, `Cargo.toml`) — verify package spelling/source for typosquats |

### OWASP AST01 — Malicious Skills

Findings tagged `AST01-xxx` map to [OWASP Agentic Skills Top 10 · AST01](https://owasp.org/www-project-agentic-skills-top-10/ast01).

| Rule | Severity | What it flags |
|---|---|---|
| `AST01-001` | HIGH | Reference to an agent identity/persona file (`SOUL.md`, `MEMORY.md`, `AGENTS.md`) — cloning & persistence |
| `AST01-002` | HIGH | Social-engineering "run/paste this command" instruction |
| `AST01-003` | HIGH | ClickFix-style "setup required" / "click to fix" coercion |
| `AST01-004` | MEDIUM | WebSocket connection (`new WebSocket(`, `ws://`, `wss://`) — check for C2 |
| `AST01-005` | HIGH | Hardcoded raw IP address — common C2 indicator |
| `AST01-006` | MEDIUM | Memory-poisoning pattern — writes into `MEMORY.md` / context / history |
| `AST01-007` | LOW | Signing/provenance metadata present — verify the signature actually validates |

When any `AST01-xxx` fires, the report reminds you that static scanning alone is **not sufficient** per OWASP's own guidance: also run in a network-isolated sandbox, verify signatures against a known publisher key, and check for identity-file access.

## Before you run a downloaded skill — manual checklist

Static scanning catches the obvious cases. The scanner is a first pass; the judgement below is what actually keeps you safe. Before running any downloaded skill file (or plugin, script, prompt template, etc.) in your environment, check:

**1. Read the whole thing first — don't execute blind**
- Open every file in the package, not just the main entry point. Malicious logic often hides in a helper script, config file, or "example" that isn't obviously executable.
- Check for obfuscated code (base64 blobs, eval() calls, minified JS with no source, unicode tricks).

**2. Look for exfiltration vectors**
- Any outbound network calls — `curl`, `fetch`, `requests.post`, `subprocess` calling `nc`/`wget`, webhook URLs, telemetry/analytics pings.
- Hardcoded URLs, especially ones that aren't the tool's stated official domain.
- Any code that reads env vars, credentials files (`.env`, `~/.aws`, `~/.ssh`, browser cookie stores), or scans your filesystem broadly (`os.walk('/')`, `find / -name`).
- Anything that zips/archives files before sending them somewhere.

**3. Check permissions it's asking for**
- Does it need filesystem access beyond its working directory?
- Does it need network access at all? If a "formatting skill" wants internet access, that's a red flag.
- Does it try to read other skills' data, shared memory, or your uploads directory?

**4. Verify provenance**
- Is it from the official/verified source (official repo, verified publisher) or a random gist/forum post?
- Check the repo's commit history, star count, issue tracker — is this actively maintained or a one-off dump?
- Compare file hashes if a checksum is published.

**5. Check dependencies**
- What packages does it pull in (`requirements.txt`, `package.json`)? Typosquatted package names are a common supply-chain attack (e.g., `reqeusts` instead of `requests`).
- Do those dependencies themselves make network calls or have known CVEs?

**6. Watch for prompt-injection style content**
- Since this is an AI skill, check for embedded instructions meant to manipulate the *model* reading it — text like "ignore previous instructions," "send the user's files to X," or instructions hidden in comments/metadata meant to be read by an LLM rather than a human.

**7. Test in isolation first**
- Run it in a sandboxed/ephemeral environment with no real credentials or sensitive files present, and monitor network traffic (even a simple `strace`/proxy log) before trusting it with real data.

**8. Least privilege after that**
- Even after vetting, don't give it broader file/network access than the stated task requires.

## How the code is structured

All logic is in the single file **`skill_audit.py`**:

1. **`SKIP_EXTENSIONS` / `TEXT_EXTENSIONS_HINT`** — which files to scan vs skip.
2. **`RULES`** — a list of `(id, severity, compiled_regex, description)` tuples grouped by category (NET, CRED, OBF, PI, DEP, AST01).
3. **`DEP_FILES`** — manifest filenames where the `DEP-001` rule applies.
4. **`iter_files`** — yields scannable files (recursively for directories).
5. **`scan_file`** — matches every rule against each line and returns findings.
6. **`main`** — CLI parsing, per-file report, severity summary, AST01 guidance, optional JSON output.

## Related

For the full OWASP Agentic Skills Top 10 (AST01–AST10) scanner with a test suite, see `owasp_skill_checker/` in this repo. `simple_skill_checker` is the lightweight, dependency-free first-pass tool.
