# skill_checker

This package lives at `skill_checker/` inside the **sdaitoolkit** repo.

Static security scanner for **agent skill** packages (`SKILL.md` and companion files). Rules come from the [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/) (AST01–AST10).

Python 3 only. No third-party packages.

## What `scan_skill.py` does

`scan_skill.py` reads a skill file or a skill directory and reports **static** indicators of malicious, over-privileged, poorly pinned, or poorly governed skills. It does **not** execute the skill, fetch remote URLs, or run a sandbox.

Typical inputs:

- A single `SKILL.md`
- A skill directory (markdown, YAML/JSON, scripts, `requirements.txt` / `package.json`, `.claude/settings.json`, binaries such as `.pyc` / `.docx` / ZIP)

Output is a human-readable report (rule id, severity, file, line, evidence, OWASP URL) or JSON (`--json`). Exit code `1` if any finding is at or above `--fail-on` (default `high`); `2` if the path does not exist.

```bash
cd skill_checker   # from the sdaitoolkit repo root
python3 scan_skill.py path/to/SKILL.md
python3 scan_skill.py path/to/skill-directory --json
python3 scan_skill.py path/to/SKILL.md --fail-on medium
```

## Checks performed

Each finding uses a `rule_id` such as `AST01-B64`. Sources: [AST01](https://owasp.org/www-project-agentic-skills-top-10/ast01) through [AST10](https://owasp.org/www-project-agentic-skills-top-10/ast10).

### AST01 — Malicious Skills

| Rule | What it flags |
|---|---|
| `AST01-B64` | Base64 payloads that decode to shells, stealers, or binary blobs |
| `AST01-HTTP` | `http://` URLs |
| `AST01-IDENTITY` | Access to `SOUL.md` / `MEMORY.md` / `AGENTS.md` (except protective `deny_write`) |
| `AST01-PERSIST` | Writes/appends to identity or memory files |
| `AST01-TYPO` | Typosquatting of known brand/skill names |
| `AST01-SIG` | Missing cryptographic signature on `SKILL.md` |
| `AST01-PUB` | Missing publisher/author identity |
| `AST01-OBFUSC` | Long hex / `\x` encoded blobs |
| `AST01-EVAL` | `eval` / `exec` / `compile` / `__import__` |
| `AST01-YAML` | Unusual YAML frontmatter keys |
| `AST01-PERMS` | `permissions: *` / all / unrestricted |
| `AST01-SOCENG` | ClickFix / copy-paste-this-command / Prerequisites paste |
| `AST01-SHELL` | Reverse shells, `curl \| bash`, stealers |
| `AST01-EXFIL` | SSH keys, wallets, browser credentials |
| `AST01-HIDDEN` | “Do not mention this to the user” / shadow features |
| `AST01-WS` | WebSocket / C2-style connections |

### AST02 — Supply Chain Compromise

| Rule | What it flags |
|---|---|
| `AST02-RANGE` | Unpinned version ranges in `requirements.txt` / `package.json` |
| `AST02-NOHASH` | Dependencies without sha256 / integrity pins |
| `AST02-CONFUSE` | Typosquat nested packages (e.g. `yutube-dl-core`) |
| `AST02-GIT` | Unpinned `git+` / GitHub dependencies |
| `AST02-CONFIG` | `.claude/settings.json`, hooks, `ANTHROPIC_BASE_URL` as execution paths |

### AST03 — Over-Privileged Skills

| Rule | What it flags |
|---|---|
| `AST03-MANIFEST` | Missing `permissions` manifest |
| `AST03-NET-BOOL` | Binary `network: true/false` instead of a domain allowlist |
| `AST03-SHELL` | Unscoped `shell: true` |
| `AST03-WILDCARD` | Wildcard filesystem permissions |
| `AST03-ENV` | Reads of `.env` / `os.environ` / `~/.clawdbot/.env` |
| `AST03-DESTRUCTIVE` | `DROP TABLE`, `rm -rf`, wipe/format |
| `AST03-CRON` | Cron / scheduled jobs without a scoped grant |

### AST04 — Insecure Metadata

| Rule | What it flags |
|---|---|
| `AST04-YAML-RCE` | `!!python/object`, `yaml.load(`, pickle gadgets |
| `AST04-ZWS` | Zero-width / bidi Unicode smuggling |
| `AST04-ASCII` | ASCII control-character smuggling |
| `AST04-PROTO` | JSON `__proto__` / `constructor.prototype` |
| `AST04-UNDERSTATE` | `network: false` while `curl`/`wget`/HTTP clients are used |
| `AST04-RISK` | `risk_tier: L0` with destructive, shell, or network behavior |
| `AST04-BRAND` | Brand tokens in `name` without matching publisher |

### AST05 — Untrusted External Instructions

| Rule | What it flags |
|---|---|
| `AST05-FETCH` | Fetching remote docs/runbooks as instructions / `web_fetch` |
| `AST05-CHAIN` | Transitive “then fetch the next…” references |
| `AST05-HOST` | Gist, raw GitHub, pastebin, ngrok, free-tier hosts |
| `AST05-UNPINNED` | URLs without a nearby `sha256` / `content_hash` |

### AST06 — Weak Isolation

| Rule | What it flags |
|---|---|
| `AST06-BIND` | Bind to `0.0.0.0` or port 18789 |
| `AST06-HOST-EXEC` | `os.system` / `subprocess` / `child_process` host spawn |
| `AST06-NO-SANDBOX` | Sandbox disabled, host-mode, `--privileged`, `--network host` |
| `AST06-HOT-RELOAD` | Hot-reload / SkillsWatcher / workspace skill shadowing |
| `AST06-WS-NOAUTH` | Unauthenticated WebSocket |

### AST07 — Update Drift

| Rule | What it flags |
|---|---|
| `AST07-MUTABLE-REF` | `@latest`, `@main`, `releases/latest`, `:latest`, branch refs |
| `AST07-AUTO-UPDATE` | Auto-update / self-update enabled |
| `AST07-NO-PIN` | Skill has `version` but no `content_hash` |

### AST08 — Poor Scanning

| Rule | What it flags |
|---|---|
| `AST08-PADDING` | Excessive leading newlines (truncation padding) |
| `AST08-NL-EXFIL` | Prose-only “download and run the binary” |
| `AST08-JUDGE` | Prompt injection aimed at an LLM skill scanner |
| `AST08-CONDITIONAL` | Date/user/prod-gated malicious paths |
| `AST08-IMPERSONATE` | Skill named like a scanner / Skill Defender |
| `AST08-BINARY` | `.pyc`, `.docx`, ZIP, and similar files scanners often skip |

### AST09 — No Governance

| Rule | What it flags |
|---|---|
| `AST09-CRED` | Hardcoded keys / tokens / PEM private keys |
| `AST09-PII` | PII/PHI handling with no audit trail |
| `AST09-INSTALL` | One-line `skill install` with no review |
| `AST09-AUDIT` | Shell/network/destructive skill with no declared audit logging |

### AST10 — Cross-Platform Reuse

| Rule | What it flags |
|---|---|
| `AST10-USF` | Missing Universal Skill Format fields (`version`, `risk_tier`, `signature`, `content_hash`) |
| `AST10-DENY-WRITE` | No `deny_write` for identity files |

Some OWASP mitigations (live hash re-verify, Docker-by-default, registry revocation, CMDB inventory) are **not** implemented; they need runtime or enterprise process, not a file scan.

## How the code is structured

All scanner logic lives in **`scan_skill.py`**.

1. **Constants** — OWASP source URLs, severity order, file globs, and regex/pattern tuples grouped by AST (malicious payloads, isolation, drift, governance, and so on).
2. **`Finding`** — dataclass for one hit: `rule_id`, title, severity, file, line, evidence, rationale.
3. **Helpers** — frontmatter parse, file collection (text vs binary), Levenshtein typosquat, line/snippet extraction, base64 payload heuristics.
4. **Check functions** — `check_*` for AST01 building blocks; `check_ast02_supply_file` through `check_ast10_format` for later standards. Each returns a list of `Finding`.
5. **`scan_text`** — runs the check set on one file’s contents.
6. **`scan_path`** — walks a file or directory, flags unscanned binary formats (`AST08-BINARY`), deduplicates, sorts by severity.
7. **`main`** — CLI: text or JSON report and `--fail-on` exit status.

`tests/test_scan_skill.py` imports `scan_skill` and calls `scan_text` / `scan_path` / `main` against small fixtures. It does not duplicate the scanner.

## How to run the tests

Tests are in **`tests/`** (`test_scan_skill.py`). Stdlib `unittest` only.

From `skill_checker/` (inside the sdaitoolkit repo):

```bash
./tests/run_tests.sh
```

Or:

```bash
python3 -m unittest discover -s tests -v
python3 tests/test_scan_skill.py
```

Exit `0` means:

- A well-formed Universal Skill Format sample still has **zero** findings.
- Each AST01–AST10 rule still fires on a crafted fixture.
- `TestCoverage` still sees a test class per AST standard.

Non-zero means a check or baseline regressed. More detail: `tests/README.md`.
