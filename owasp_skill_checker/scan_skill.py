#!/usr/bin/env python3
"""Static security scanner for agent skill files (SKILL.md + skill directory).

Checks are derived from OWASP Agentic Skills Top 10:
  AST01 Malicious Skills
  AST02 Supply Chain Compromise
  AST03 Over-Privileged Skills
  AST04 Insecure Metadata
  AST05 Untrusted External Instructions
  AST08 Poor Scanning
  AST10 Cross-Platform Reuse

https://owasp.org/www-project-agentic-skills-top-10/
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

SOURCES = {
    "AST01": "https://owasp.org/www-project-agentic-skills-top-10/ast01",
    "AST02": "https://owasp.org/www-project-agentic-skills-top-10/ast02",
    "AST03": "https://owasp.org/www-project-agentic-skills-top-10/ast03",
    "AST04": "https://owasp.org/www-project-agentic-skills-top-10/ast04",
    "AST05": "https://owasp.org/www-project-agentic-skills-top-10/ast05",
    "AST06": "https://owasp.org/www-project-agentic-skills-top-10/ast06",
    "AST07": "https://owasp.org/www-project-agentic-skills-top-10/ast07",
    "AST08": "https://owasp.org/www-project-agentic-skills-top-10/ast08",
    "AST09": "https://owasp.org/www-project-agentic-skills-top-10/ast09",
    "AST10": "https://owasp.org/www-project-agentic-skills-top-10/ast10",
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".tox"}

TEXT_SUFFIXES = {
    ".md",
    ".markdown",
    ".yml",
    ".yaml",
    ".json",
    ".txt",
    ".toml",
    ".sh",
    ".bash",
    ".zsh",
    ".py",
    ".js",
    ".ts",
    ".mjs",
    ".cjs",
}

BINARY_SUFFIXES = {".pyc", ".pyo", ".docx", ".zip", ".whl", ".egg", ".so", ".dylib", ".bin"}

NAMED_TEXT_FILES = {
    "skill.md",
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "pyproject.toml",
    "poetry.lock",
    "pipfile",
    "manifest.json",
    "hooks.json",
    "agents.md",
}

CONFIG_HIJACK_NAMES = {
    "settings.json",
    "hooks.json",
    ".mcp.json",
    "claude_desktop_config.json",
}

IDENTITY_FILES = (
    "soul.md",
    "memory.md",
    "hooks.json",
    "persona.md",
    "identity.md",
    "agent.md",
    "agents.md",
)

TRUSTED_NAMES = (
    "google",
    "google-workspace",
    "youtube",
    "youtube-dl",
    "github",
    "microsoft",
    "openai",
    "anthropic",
    "aws",
    "amazon",
    "solana",
    "polymarket",
    "clawhub",
    "vscode",
    "cursor",
    "vercel",
)

BRAND_TOKENS = (
    "google",
    "youtube",
    "solana",
    "polymarket",
    "microsoft",
    "openai",
    "anthropic",
    "vercel",
    "aws",
    "amazon",
    "github",
)

UNTRUSTED_DOC_HOSTS = (
    "pastebin.com",
    "gist.github.com",
    "raw.githubusercontent.com",
    "ngrok.io",
    "trycloudflare.com",
    "vercel.app",
    "netlify.app",
    "pages.dev",
    "github.io",
    "replit.dev",
    "glitch.me",
    "herokuapp.com",
    "dropbox.com",
    "notion.so",
    "docs.google.com",
)

YAML_RCE_PATTERNS = (
    r"!!python/object",
    r"!!python/apply",
    r"!!python/name",
    r"yaml\.load\s*\(",
    r"pickle\.loads\s*\(",
)

SOCENG_PATTERNS = (
    r"run this command to (?:enable|install|unlock|fix|continue|activate)",
    r"copy[- ]paste (?:this|the following) (?:command|into (?:your )?terminal)",
    r"paste (?:this|the following) into (?:your )?(?:terminal|shell|console)",
    r"setup required",
    r"click (?:here )?to (?:fix|enable|unlock|continue)",
    r"to continue,? (?:run|execute|paste)",
    r"install helper tools? from",
    r"prerequisites?:?\s*(?:\n|.).{0,80}(?:curl|wget|bash|powershell|invoke-webrequest)",
)

SHELL_PATTERNS = (
    r"bash\s+-i\s+>&\s*/dev/tcp/",
    r"nc\s+-e\s+/bin/(?:ba)?sh",
    r"ncat\s+.*-e",
    r"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+",
    r"powershell\s+-enc\s+",
    r"invoke-expression|iex\s*\(",
    r"curl\s+[^\n|]*\|\s*(?:ba)?sh",
    r"wget\s+[^\n|]*\|\s*(?:ba)?sh",
    r"pip(?:3)?\s+install\s+[^\n]*https?://",
    r"npm\s+install\s+-g\s+https?://",
)

# Invoke a .py/.sh (or similar) file — AST01 hidden payload / AST02 staged loader
EXT_SCRIPT_PATTERNS = (
    r"\b(?:python3?|py)\s+(?:-[^\s]+\s+)*['\"]?(?:https?://|[./~]|[A-Za-z]:\\)?[^\s'\"]+\.py\b",
    r"\b(?:ba)?sh\s+(?:-[^\s]+\s+)*['\"]?(?:https?://|[./~]|[A-Za-z]:\\)?[^\s'\"]+\.(?:sh|bash|zsh)\b",
    r"\b(?:zsh|dash)\s+[^\s]+\.(?:sh|zsh)\b",
    r"(?:^|[\s;`])\./[^\s]+\.(?:py|sh|bash|zsh|ps1|js)\b",
    r"subprocess\.(?:run|Popen|call|check_output)\s*\([^)]*\.(?:py|sh|bash|ps1|js)",
    r"os\.system\s*\(\s*['\"][^'\"]*\.(?:py|sh|bash|ps1)",
    r"exec\s*\(\s*open\s*\(\s*['\"][^'\"]+\.py",
    r"\brunpy\.run_path\s*\(",
    r"spec_from_file_location\s*\(",
    r"\bsource\s+[^\s]+\.(?:sh|bash|zsh)\b",
    r"\b(?:powershell|pwsh)\s+[^\n]*\.ps1\b",
    r"\bnode(?:js)?\s+[^\s]+\.js\b",
    r"\b(?:run|execute|launch|invoke)\s+(?:the\s+)?(?:python\s+)?(?:script|file)\s+['\"]?[^\s'\"]+\.(?:py|sh|bash|ps1|js)\b",
    r"\b(?:run|execute)\s+['\"]?[^\s'\"]+\.(?:py|sh|bash|ps1)\b",
)

EXFIL_PATTERNS = (
    r"~/\.ssh/",
    r"id_rsa",
    r"id_ed25519",
    r"authorized_keys",
    r"wallet\.dat",
    r"aws_secret_access_key",
    r"browser (?:cookies|credentials|passwords)",
    r"login\.keychain",
    r"cookies\.sqlite",
    r"exfiltrat",
    r"atomic.?stealer|\bamos\b",
    r"~/\.clawdbot/\.env",
)

HIDDEN_PATTERNS = (
    r"do not (?:mention|tell|inform|disclose) (?:this )?(?:to )?the user",
    r"never (?:mention|reveal|tell) (?:this|these instructions) to the user",
    r"hidden from the user",
    r"shadow feature",
    r"ignore (?:previous|prior) instructions",
    r"you must not disclose these instructions",
)

WEBSOCKET_PATTERNS = (
    r"wss?://",
    r"websocket",
    r"websockets\.connect",
    r"new\s+WebSocket\s*\(",
)

IDENTITY_WRITE_PATTERNS = (
    r"(?:write|append|overwrite|edit|modify|update).{0,40}(soul\.md|memory\.md|hooks\.json|agents\.md)",
    r"(soul\.md|memory\.md|hooks\.json|agents\.md).{0,40}(?:write|append|overwrite|persist)",
)

NL_EXFIL_PATTERNS = (
    r"download and run the binary",
    r"retrieve the file at (?:the )?path.{0,120}send it",
    r"using the system(?:'s)? default HTTP client",
    r"send (?:it|the (?:file|contents?|data)) to the (?:address|url|endpoint) below",
    r"read (?:the )?(?:file|path).{0,80}(?:POST|upload|transmit|exfil)",
)

EXTERNAL_INSTRUCTION_PATTERNS = (
    r"(?:fetch|load|read|follow|open|browse)\s+(?:the\s+)?(?:docs?|documentation|runbook|schema|instructions?|guide).{0,80}https?://",
    r"(?:see|follow|read)\s+(?:this|the)\s+(?:url|link)\s+https?://",
    r"point(?:ing)? the agent at (?:a |the )?(?:url|https?://)",
    r"always (?:fetch|read) (?:latest|live|current) (?:docs?|instructions?)",
    r"\b(?:web_fetch|webfetch)\b",
)

TRANSITIVE_REF_PATTERNS = (
    r"then (?:read|fetch|follow|open) (?:the )?(?:next|linked|referenced)",
    r"follow (?:every|all|any) (?:link|reference|url)",
    r"recursively (?:fetch|read|follow)",
)

SCANNER_INJECT_PATTERNS = (
    r"rate (?:this|the skill) as (?:benign|safe|pass|low)",
    r"this (?:is|meets) (?:corporate|company) standards",
    r"ignore (?:this|the following) for scanning",
    r"scanner should (?:skip|ignore|approve)",
)

CONDITIONAL_MALICE_PATTERNS = (
    r"if (?:hostname|username|os\.environ|datetime|date)\b.{0,80}(?:then )?(?:curl|wget|exfil|eval)",
    r"only when (?:in )?(?:production|prod|ci)\b.{0,80}(?:curl|wget|shell|exfil)",
    r"if .{0,40}(?:user|file) (?:is |exists).{0,80}(?:malicious|payload|backdoor)",
)

HTTP_URL_RE = re.compile(r"https?://[^\s)\]>'\"`]+", re.I)
COMMENT_RE = re.compile(r"(?:^|\n)\s*#([^\n]*)")
FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?", re.S)
B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
HEX_BLOB_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}|[0-9a-fA-F]{80,}")
EVAL_RE = re.compile(r"\b(?:eval|exec|compile|__import__)\s*\(", re.I)
ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]")
CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
REQ_RANGE_RE = re.compile(r"^[A-Za-z0-9_.-]+\s*(>=|<=|~=|>|<|\^|~|\*)", re.M)
PIP_HASH_RE = re.compile(r"--hash=sha256:", re.I)
NETWORK_BOOL_RE = re.compile(r"\bnetwork\s*:\s*(true|false|yes|no|1|0)\b", re.I)
SHELL_TRUE_RE = re.compile(r"\bshell\s*:\s*(true|yes|1|\*)\b", re.I)
RISK_L0_RE = re.compile(r"\brisk_tier\s*:\s*L0\b", re.I)
CURL_LIKE_RE = re.compile(r"\b(?:curl|wget|invoke-webrequest|requests\.(?:get|post)|urllib|fetch\s*\()\b", re.I)
DESTRUCTIVE_RE = re.compile(
    r"\b(?:drop\s+table|delete\s+from|rm\s+-rf|format\s+(?:disk|volume)|wipe\s+(?:disk|db|database))\b",
    re.I,
)
ANTHROPIC_BASE_RE = re.compile(r"ANTHROPIC_BASE_URL", re.I)
PROTO_RE = re.compile(r'["\']__proto__["\']|constructor\.prototype')
ENV_READ_RE = re.compile(r"~/\.clawdbot/\.env|\.env\b|process\.env|os\.environ", re.I)
CRON_RE = re.compile(r"\b(?:cron|crontab|schedule(?:d)? jobs?)\b", re.I)
WILDCARD_PERM_RE = re.compile(r"(?:files|filesystem|paths?)\s*:\s*(?:\*|\"\*\*\"|'?\*\*'?)", re.I)
UNPINNED_GIT_RE = re.compile(r"(?:git\+|github:).*(?:@|#)?(?!sha256)", re.I)
USF_FIELDS = ("name", "version", "permissions", "risk_tier", "signature", "content_hash")

# AST06 — Weak Isolation
BIND_ADDR_RE = re.compile(r"\b0\.0\.0\.0\b|\bhost\s*[:=]\s*['\"]?0\.0\.0\.0|\bport\s*[:=]?\s*18789\b", re.I)
SUBPROCESS_RE = re.compile(
    r"\b(?:os\.system|subprocess\.(?:Popen|run|call|check_output)|child_process|require\(['\"]child_process|\bspawn\s*\(|\bexecSync\s*\()",
    re.I,
)
NO_SANDBOX_PATTERNS = (
    r"sandbox\s*[:=]\s*(?:false|none|off|disabled|0)",
    r"isolation\s*[:=]\s*(?:false|none|off|disabled)",
    r"host[_-]?mode\s*[:=]\s*(?:true|on|yes|1)",
    r"docker\s*[:=]\s*(?:false|off|disabled)",
    r"run(?:s|ning)? (?:directly )?on the host",
    r"--privileged\b",
    r"--network[ =]host\b",
    r"-v\s+/:/",
    r"--cap-add\b",
)
HOT_RELOAD_PATTERNS = (
    r"hot[- ]?reload",
    r"skillswatcher",
    r"workspace (?:precedence|override|shadow)",
    r"skill shadow(?:ing)?",
    r"reload(?:s|ed)? without (?:a )?restart",
    r"picks? up changes without restart",
)
WS_NOAUTH_PATTERNS = (
    r"websocket[^\n]{0,60}(?:no|without) (?:auth|authentication|token)",
    r"(?:no|without) (?:auth|authentication)[^\n]{0,60}websocket",
    r"unauthenticated (?:localhost )?websocket",
)

# AST07 — Update Drift
MUTABLE_REF_PATTERNS = (
    r"@latest\b",
    r"@main\b",
    r"@master\b",
    r"releases/latest",
    r":latest\b",
    r"#(?:main|master|head)\b",
    r"\bgit pull\b",
    r"branch\s*[:=]\s*['\"]?(?:main|master)\b",
)
AUTO_UPDATE_PATTERNS = (
    r"auto[_-]?update\s*[:=]\s*(?:true|on|yes|1|enabled)",
    r"autoupdate",
    r"updates? (?:itself )?automatically",
    r"self[- ]?updat(?:e|ing)",
    r"always (?:pull|fetch) (?:the )?latest version",
)

# AST09 — No Governance
PII_RE = re.compile(
    r"\b(?:pii|phi|ssn|social security(?: number)?|credit[- ]card|patient (?:data|records?)|health records?|medical records?|passport number)\b",
    re.I,
)
AUDIT_DECL_RE = re.compile(r"\b(?:audit|audit[_-]?log|logging|telemetry|receipt)\b", re.I)
ONELINE_INSTALL_RE = re.compile(
    r"\b(?:openclaw|claude|cursor)?\s*skill(?:s)?\s+install\b|\bnpx\s+skill-install\b|\bpip install .*skill.* &&",
    re.I,
)
HARDCODED_CRED_PATTERNS = (
    r"AKIA[0-9A-Z]{16}",
    r"ghp_[A-Za-z0-9]{30,}",
    r"github_pat_[A-Za-z0-9_]{20,}",
    r"sk-[A-Za-z0-9]{20,}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    r"(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"][A-Za-z0-9/+_-]{16,}['\"]",
)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    evidence: str
    rationale: str


def standard_of(rule_id: str) -> str:
    return rule_id.split("-", 1)[0]


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            ins, delete, sub = prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)
            cur.append(min(ins, delete, sub))
        prev = cur
    return prev[-1]


def line_of(text: str, index: int) -> int:
    return text[:index].count("\n") + 1


def snippet(text: str, index: int, width: int = 120) -> str:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    if end == -1:
        end = len(text)
    return text[start:end].strip()[:width]


def is_protective_identity_mention(text: str, index: int) -> bool:
    window = text[max(0, index - 90) : index + 50].lower()
    return any(token in window for token in ("deny_write", "deny:", "do not write", "never write", "forbid"))


def collect_files(target: Path) -> tuple[list[Path], list[Path]]:
    if target.is_file():
        if target.suffix.lower() in BINARY_SUFFIXES:
            return [], [target]
        return [target], []
    if not target.is_dir():
        raise FileNotFoundError(target)
    text_files: list[Path] = []
    binary_files: list[Path] = []
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        suffix = path.suffix.lower()
        name = path.name.lower()
        if suffix in BINARY_SUFFIXES:
            binary_files.append(path)
        elif suffix in TEXT_SUFFIXES or name in NAMED_TEXT_FILES or name in CONFIG_HIJACK_NAMES:
            text_files.append(path)
        elif path.parent.name == ".claude" and suffix == ".json":
            text_files.append(path)
    return text_files, binary_files


def parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    working = text
    match = FRONTMATTER_RE.match(working)
    if not match:
        working = text.lstrip("\n")
        match = FRONTMATTER_RE.match(working)
    if not match:
        return {}, text
    raw = match.group(1)
    meta: dict[str, str] = {}
    current_key: str | None = None
    for line in raw.splitlines():
        if re.match(r"^\s*#", line):
            continue
        keyed = re.match(r"^([A-Za-z0-9_.-]+)\s*:\s*(.*)$", line)
        if keyed:
            current_key = keyed.group(1).strip().lower()
            meta[current_key] = keyed.group(2).strip().strip("\"'")
        elif current_key and (line.startswith("  ") or line.startswith("\t") or line.startswith(" -")):
            meta[current_key] = (meta.get(current_key, "") + " " + line.strip()).strip()
    return meta, working[match.end() :]


def looks_like_payload(blob: str) -> bool:
    try:
        padding = (-len(blob)) % 4
        decoded = base64.b64decode(blob + ("=" * padding), validate=False)
    except Exception:
        return False
    if len(decoded) < 16:
        return False
    if decoded.startswith((b"\x7fELF", b"MZ", b"\x89PNG", b"PK\x03\x04")):
        return True
    text = decoded.decode("utf-8", errors="ignore")
    suspicious = (
        "bash -i",
        "/dev/tcp",
        "os.system",
        "subprocess",
        "powershell",
        "curl ",
        "wget ",
        "ssh-",
        "BEGIN OPENSSH",
        "exfil",
    )
    return any(token in text.lower() or token in text for token in suspicious) or (
        sum(32 <= b < 127 for b in decoded) / len(decoded) < 0.6
    )


def check_base64(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for match in B64_RE.finditer(text):
        blob = match.group(0)
        if blob in seen or not looks_like_payload(blob):
            continue
        seen.add(blob)
        findings.append(
            Finding(
                rule_id="AST01-B64",
                title="Base64-encoded payload",
                severity="critical",
                file=str(path),
                line=line_of(text, match.start()),
                evidence=blob[:80] + ("..." if len(blob) > 80 else ""),
                rationale="AST01 detection signature: base64-encoded payloads in YAML comments or skill content.",
            )
        )
    return findings


def check_http_urls(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in HTTP_URL_RE.finditer(text):
        url = match.group(0).rstrip(".,);")
        if url.lower().startswith("https://"):
            continue
        findings.append(
            Finding(
                rule_id="AST01-HTTP",
                title="Non-HTTPS download or URL",
                severity="high",
                file=str(path),
                line=line_of(text, match.start()),
                evidence=url,
                rationale="AST01 detection signature: instructions to download from non-HTTPS URLs.",
            )
        )
    return findings


def check_regex_rules(
    path: Path,
    text: str,
    rule_id: str,
    title: str,
    severity: str,
    patterns: tuple[str, ...],
    rationale: str,
    flags: int = re.I,
) -> list[Finding]:
    findings: list[Finding] = []
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags | re.S):
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    file=str(path),
                    line=line_of(text, match.start()),
                    evidence=snippet(text, match.start()),
                    rationale=rationale,
                )
            )
    return findings


def check_identity_access(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lower = text.lower()
    for name in IDENTITY_FILES:
        start = 0
        while True:
            idx = lower.find(name, start)
            if idx == -1:
                break
            start = idx + len(name)
            if is_protective_identity_mention(text, idx):
                continue
            findings.append(
                Finding(
                    rule_id="AST01-IDENTITY",
                    title="Access to agent identity or memory artifacts",
                    severity="critical",
                    file=str(path),
                    line=line_of(text, idx),
                    evidence=snippet(text, idx),
                    rationale=(
                        "AST01/AST03: skills that read/write SOUL.md, MEMORY.md, or AGENTS.md "
                        "enable persistence, memory poisoning, and identity cloning."
                    ),
                )
            )
    persist = check_regex_rules(
        path,
        text,
        "AST01-PERSIST",
        "Persistence via identity/memory file writes",
        "critical",
        IDENTITY_WRITE_PATTERNS,
        "AST01 SOUL.md persistence and MEMORY.md poisoning; AST03 identity-file backdoors.",
    )
    findings.extend(
        item
        for item in persist
        if "deny_write" not in item.evidence.lower() and "deny:" not in item.evidence.lower()
    )
    return findings


def check_typosquat(path: Path, meta: dict[str, str], text: str) -> list[Finding]:
    findings: list[Finding] = []
    candidates = [
        meta.get("name", ""),
        meta.get("publisher", ""),
        *re.findall(r"^#\s+(.+)$", text, re.M),
    ]
    for raw in candidates:
        name = re.sub(r"[^a-z0-9-]+", "-", raw.strip().lower()).strip("-")
        if not name or len(name) < 4:
            continue
        for trusted in TRUSTED_NAMES:
            dist = levenshtein(name, trusted)
            if 0 < dist <= 2 and name != trusted:
                findings.append(
                    Finding(
                        rule_id="AST01-TYPO",
                        title="Possible typosquatting of a well-known skill/brand name",
                        severity="high",
                        file=str(path),
                        line=1,
                        evidence=f"{raw.strip()} ≈ {trusted} (distance {dist})",
                        rationale="AST01 typosquatting (e.g. google-workspace vs gogle-workspace).",
                    )
                )
    return findings


def check_signature(path: Path, meta: dict[str, str], is_skill_md: bool) -> list[Finding]:
    if not is_skill_md:
        return []
    sig = meta.get("signature") or meta.get("ed25519") or meta.get("code_signature")
    publisher = meta.get("publisher") or meta.get("author") or meta.get("author.name")
    findings: list[Finding] = []
    if not sig:
        findings.append(
            Finding(
                rule_id="AST01-SIG",
                title="Missing cryptographic skill signature",
                severity="medium",
                file=str(path),
                line=1,
                evidence="No signature / ed25519 field in YAML frontmatter",
                rationale="AST01/AST02/AST10: require ed25519 (or ES256) signatures bound to a revocable publisher identity.",
            )
        )
    if not publisher:
        findings.append(
            Finding(
                rule_id="AST01-PUB",
                title="Missing publisher identity",
                severity="medium",
                file=str(path),
                line=1,
                evidence="No publisher/author field in YAML frontmatter",
                rationale="AST01: bind signatures to a resolvable, revocable publisher identity, not a bare key.",
            )
        )
    return findings


def check_obfuscation(path: Path, text: str, meta: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    for match in HEX_BLOB_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="AST01-OBFUSC",
                title="Obfuscated or unusual encoded blob",
                severity="high",
                file=str(path),
                line=line_of(text, match.start()),
                evidence=match.group(0)[:80] + ("..." if len(match.group(0)) > 80 else ""),
                rationale="AST01/AST08 static analysis: obfuscated code or unusual YAML/content structures.",
            )
        )
    for match in EVAL_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="AST01-EVAL",
                title="Dynamic code execution",
                severity="high",
                file=str(path),
                line=line_of(text, match.start()),
                evidence=snippet(text, match.start()),
                rationale="AST01 best practice: avoid dynamic code execution in skills.",
            )
        )
    unusual_keys = [k for k in meta if re.search(r"[^\x20-\x7e]", k) or len(k) > 40]
    if unusual_keys:
        findings.append(
            Finding(
                rule_id="AST01-YAML",
                title="Unusual YAML frontmatter keys",
                severity="medium",
                file=str(path),
                line=1,
                evidence=", ".join(unusual_keys)[:120],
                rationale="AST01/AST04 static analysis: unusual YAML structures; allowlist permitted keys.",
            )
        )
    return findings


PERM_STAR_RE = re.compile(
    r"""^[ \t]*permissions[ \t]*:[ \t]*["']?(?:\*|all|unrestricted|full)["']?[ \t]*$""",
    re.I | re.M,
)


def check_excessive_permissions(path: Path, text: str, meta: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    match = PERM_STAR_RE.search(text)
    granted = (meta.get("permissions") or "").strip().lower()
    if match or granted in {"*", "all", "unrestricted", "full"}:
        idx = match.start() if match else 0
        findings.append(
            Finding(
                rule_id="AST01-PERMS",
                title="Excessive or unrestricted permissions",
                severity="high",
                file=str(path),
                line=line_of(text, idx) if match else 1,
                evidence=snippet(text, idx) if match else granted,
                rationale="AST01/AST03: malicious or over-privileged skills execute with full host-agent permissions.",
            )
        )
    return findings


def check_ast03_privilege(path: Path, text: str, meta: dict[str, str], is_skill_md: bool) -> list[Finding]:
    findings: list[Finding] = []
    if is_skill_md and not meta.get("permissions"):
        findings.append(
            Finding(
                rule_id="AST03-MANIFEST",
                title="Missing permission manifest",
                severity="high",
                file=str(path),
                line=1,
                evidence="No permissions field in YAML frontmatter",
                rationale="AST03: reject skills without a declared permission manifest (files, network, shell, tools).",
            )
        )
    for match in NETWORK_BOOL_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="AST03-NET-BOOL",
                title="Binary network permission instead of domain allowlist",
                severity="high",
                file=str(path),
                line=line_of(text, match.start()),
                evidence=snippet(text, match.start()),
                rationale="AST03/AST10: use network.allow domain allowlists, not network: true/false.",
            )
        )
    for match in SHELL_TRUE_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="AST03-SHELL",
                title="Unscoped shell execution permission",
                severity="high",
                file=str(path),
                line=line_of(text, match.start()),
                evidence=snippet(text, match.start()),
                rationale="AST03: OpenClaw-style host shell access expands blast radius; declare shell: false unless required.",
            )
        )
    for match in WILDCARD_PERM_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="AST03-WILDCARD",
                title="Wildcard filesystem permission",
                severity="high",
                file=str(path),
                line=line_of(text, match.start()),
                evidence=snippet(text, match.start()),
                rationale="AST03/AST10 Universal Skill Format: explicit paths only; no wildcards.",
            )
        )
    for match in ENV_READ_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="AST03-ENV",
                title="Reads shared agent secrets or environment files",
                severity="high",
                file=str(path),
                line=line_of(text, match.start()),
                evidence=snippet(text, match.start()),
                rationale="AST03: weather-assistant-style skills reading ~/.clawdbot/.env or shared API keys exceed stated function.",
            )
        )
    for match in DESTRUCTIVE_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="AST03-DESTRUCTIVE",
                title="Destructive privileged action in skill instructions",
                severity="high",
                file=str(path),
                line=line_of(text, match.start()),
                evidence=snippet(text, match.start()),
                rationale="AST03: over-privilege plus prompt injection can turn SELECT-like skills into DROP TABLE / wipe operations.",
            )
        )
    for match in CRON_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="AST03-CRON",
                title="Unscoped job scheduling capability",
                severity="medium",
                file=str(path),
                line=line_of(text, match.start()),
                evidence=snippet(text, match.start()),
                rationale="AST03: host-mode skills can schedule cron jobs without per-skill permission scope.",
            )
        )
    return findings


def check_ast04_metadata(path: Path, text: str, meta: dict[str, str], is_skill_md: bool) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(
        check_regex_rules(
            path,
            text,
            "AST04-YAML-RCE",
            "Unsafe YAML deserialization gadget",
            "critical",
            YAML_RCE_PATTERNS,
            "AST04: !!python/object and yaml.load execute on parse, before the skill is run.",
        )
    )
    for match in ZERO_WIDTH_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="AST04-ZWS",
                title="Zero-width or bidi Unicode smuggling",
                severity="high",
                file=str(path),
                line=line_of(text, match.start()),
                evidence=f"U+{ord(match.group(0)):04X} hidden character",
                rationale="AST04/AST08: ASCII/Unicode smuggling hides instructions from human reviewers.",
            )
        )
        break  # one finding is enough; files can contain many ZWSP
    for match in CTRL_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="AST04-ASCII",
                title="ASCII control-character smuggling",
                severity="high",
                file=str(path),
                line=line_of(text, match.start()),
                evidence=f"control byte 0x{ord(match.group(0)):02x}",
                rationale="AST04: Snyk toxicskills-goof documents hidden instructions via ASCII control characters.",
            )
        )
        break
    for match in PROTO_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="AST04-PROTO",
                title="JSON prototype pollution key",
                severity="high",
                file=str(path),
                line=line_of(text, match.start()),
                evidence=snippet(text, match.start()),
                rationale="AST04: manifest.json __proto__ can poison Node.js skill loaders.",
            )
        )
    network_denied = bool(re.search(r"\bnetwork\s*:\s*(false|no|none|deny)\b", text, re.I))
    if network_denied and CURL_LIKE_RE.search(text):
        match = CURL_LIKE_RE.search(text)
        findings.append(
            Finding(
                rule_id="AST04-UNDERSTATE",
                title="Permission understating: network denied but HTTP client used",
                severity="high",
                file=str(path),
                line=line_of(text, match.start()) if match else 1,
                evidence=snippet(text, match.start()) if match else "network: false + curl",
                rationale="AST04: declare network: false while scripts call curl to an external endpoint.",
            )
        )
    if RISK_L0_RE.search(text) and (DESTRUCTIVE_RE.search(text) or SHELL_TRUE_RE.search(text) or CURL_LIKE_RE.search(text)):
        match = RISK_L0_RE.search(text)
        findings.append(
            Finding(
                rule_id="AST04-RISK",
                title="Risk-tier spoofing (L0 with destructive or network/shell behavior)",
                severity="high",
                file=str(path),
                line=line_of(text, match.start()) if match else 1,
                evidence=snippet(text, match.start()) if match else "risk_tier: L0",
                rationale="AST04: self-classify as risk_tier: L0 while embedding destructive operations.",
            )
        )
    if is_skill_md:
        name = (meta.get("name") or "").lower()
        publisher = (meta.get("publisher") or meta.get("author") or "").lower()
        for brand in BRAND_TOKENS:
            if brand in name and brand not in publisher:
                findings.append(
                    Finding(
                        rule_id="AST04-BRAND",
                        title="Brand impersonation in skill metadata",
                        severity="high",
                        file=str(path),
                        line=1,
                        evidence=f"name={meta.get('name')} publisher={publisher or '(missing)'}",
                        rationale="AST04: ClawHub brand impersonation (Google, Solana, Polymarket) with no trademark validation.",
                    )
                )
                break
    return findings


def nearby_has_pin(text: str, url_start: int, url_end: int) -> bool:
    window = text[max(0, url_start - 160) : min(len(text), url_end + 160)].lower()
    return "sha256" in window or "content_hash" in window or "pinned" in window or "integrity" in window


def check_ast05_external(path: Path, text: str, meta: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(
        check_regex_rules(
            path,
            text,
            "AST05-FETCH",
            "Runtime fetch of external documentation as instructions",
            "high",
            EXTERNAL_INSTRUCTION_PATTERNS,
            "AST05: referenced docs become skill instructions; unlike packages they are mutable and unpinned.",
        )
    )
    findings.extend(
        check_regex_rules(
            path,
            text,
            "AST05-CHAIN",
            "Transitive external reference chaining",
            "high",
            TRANSITIVE_REF_PATTERNS,
            "AST05: referenced documents tell the agent to read still more external resources.",
        )
    )
    for match in HTTP_URL_RE.finditer(text):
        url = match.group(0).rstrip(".,);")
        host = re.sub(r"^https?://", "", url, flags=re.I).split("/")[0].lower()
        if any(host.endswith(bad) or host == bad for bad in UNTRUSTED_DOC_HOSTS):
            findings.append(
                Finding(
                    rule_id="AST05-HOST",
                    title="Untrusted or reclaimable host for external instructions",
                    severity="high",
                    file=str(path),
                    line=line_of(text, match.start()),
                    evidence=url,
                    rationale="AST05/AST02: free-tier hosts, gists, and raw GitHub URLs are SkillJacking/rug-pull surfaces.",
                )
            )
        if not nearby_has_pin(text, match.start(), match.end()) and not meta.get("content_hash"):
            findings.append(
                Finding(
                    rule_id="AST05-UNPINNED",
                    title="External URL without content hash pin",
                    severity="medium",
                    file=str(path),
                    line=line_of(text, match.start()),
                    evidence=url,
                    rationale="AST05: pin and re-verify a content hash for every external document; refuse unpinned fetches.",
                )
            )
    return findings


def check_ast08_evasion(path: Path, text: str, meta: dict[str, str], is_skill_md: bool) -> list[Finding]:
    findings: list[Finding] = []
    leading = 0
    for ch in text:
        if ch == "\n":
            leading += 1
        else:
            break
    if leading >= 50:
        findings.append(
            Finding(
                rule_id="AST08-PADDING",
                title="Excessive leading newlines (scanner truncation padding)",
                severity="high",
                file=str(path),
                line=1,
                evidence=f"{leading} leading newlines",
                rationale="AST08/Trail of Bits: padding with ~100k newlines caused scanners to truncate and miss payloads.",
            )
        )
    findings.extend(
        check_regex_rules(
            path,
            text,
            "AST08-NL-EXFIL",
            "Natural-language exfil/execution with no code signature",
            "high",
            NL_EXFIL_PATTERNS,
            "AST08: intent expressed in prose ('download and run the binary') bypasses regex scanners.",
        )
    )
    findings.extend(
        check_regex_rules(
            path,
            text,
            "AST08-JUDGE",
            "Prompt injection aimed at an LLM skill scanner",
            "high",
            SCANNER_INJECT_PATTERNS,
            "AST08: wrap malice in 'corporate standards' prose so the scanner's LLM rates the skill benign.",
        )
    )
    findings.extend(
        check_regex_rules(
            path,
            text,
            "AST08-CONDITIONAL",
            "Context-dependent / delayed malicious path",
            "medium",
            CONDITIONAL_MALICE_PATTERNS,
            "AST08: skill behaves safely in tests; activates when user, file, or date conditions match.",
        )
    )
    name = (meta.get("name") or path.stem).lower()
    if is_skill_md and re.search(r"scanner|skill.?defender|skillspector|malware.?scan", name):
        findings.append(
            Finding(
                rule_id="AST08-IMPERSONATE",
                title="Skill impersonates a security scanner",
                severity="high",
                file=str(path),
                line=1,
                evidence=meta.get("name") or path.name,
                rationale="AST08: ClawHub Skill Defender was used as a false-trust signal; scanner skills were themselves malicious.",
            )
        )
    return findings


def check_ast10_format(path: Path, meta: dict[str, str], text: str, is_skill_md: bool) -> list[Finding]:
    if not is_skill_md:
        return []
    findings: list[Finding] = []
    missing = [field for field in USF_FIELDS if field not in meta and not (field == "permissions" and meta.get("permissions"))]
    # permissions already covered by AST03-MANIFEST; don't double missing-permissions here
    missing = [f for f in missing if f != "permissions"]
    if missing:
        findings.append(
            Finding(
                rule_id="AST10-USF",
                title="Incomplete Universal Skill Format security metadata",
                severity="medium",
                file=str(path),
                line=1,
                evidence="missing: " + ", ".join(missing),
                rationale="AST10: normalize risk_tier, permissions, signature, and content_hash across platforms or they are dropped in translation.",
            )
        )
    if "deny_write" not in text.lower():
        findings.append(
            Finding(
                rule_id="AST10-DENY-WRITE",
                title="No deny_write protection for identity files",
                severity="medium",
                file=str(path),
                line=1,
                evidence="permissions.deny_write not declared for SOUL.md/MEMORY.md/AGENTS.md",
                rationale="AST10 Universal Skill Format: deny_write protects identity files by default and must be explicit.",
            )
        )
    return findings


def check_ast06_isolation(path: Path, text: str, meta: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    for match in BIND_ADDR_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="AST06-BIND",
                title="Agent interface bound to all interfaces / exposed port",
                severity="high",
                file=str(path),
                line=line_of(text, match.start()),
                evidence=snippet(text, match.start()),
                rationale="AST06: bind control interfaces to localhost with auth, never 0.0.0.0; 135k+ OpenClaw instances were exposed on port 18789.",
            )
        )
    for match in SUBPROCESS_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="AST06-HOST-EXEC",
                title="Host process/shell spawn (isolation escape)",
                severity="high",
                file=str(path),
                line=line_of(text, match.start()),
                evidence=snippet(text, match.start()),
                rationale="AST06: os.system/subprocess/child_process run in the host context and can plant cron jobs that survive uninstall.",
            )
        )
    findings.extend(
        check_regex_rules(
            path,
            text,
            "AST06-NO-SANDBOX",
            "Sandboxing disabled or host-mode execution",
            "high",
            NO_SANDBOX_PATTERNS,
            "AST06: require Docker/container isolation by default; host-mode should be explicit opt-in.",
        )
    )
    findings.extend(
        check_regex_rules(
            path,
            text,
            "AST06-HOT-RELOAD",
            "Hot-reload / workspace skill shadowing",
            "medium",
            HOT_RELOAD_PATTERNS,
            "AST06: restrict hot-reload and workspace precedence; overrides activate immediately and can shadow built-ins.",
        )
    )
    findings.extend(
        check_regex_rules(
            path,
            text,
            "AST06-WS-NOAUTH",
            "Unauthenticated WebSocket surface",
            "high",
            WS_NOAUTH_PATTERNS,
            "AST06: rate-limit and authenticate all WebSocket connections, including localhost (ClawJacked CVE-2026-28363).",
        )
    )
    return findings


def check_ast07_drift(path: Path, text: str, meta: dict[str, str], is_skill_md: bool) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(
        check_regex_rules(
            path,
            text,
            "AST07-MUTABLE-REF",
            "Mutable dependency/source reference (no immutable pin)",
            "high",
            MUTABLE_REF_PATTERNS,
            "AST07: pin to immutable content hashes; @latest / releases-latest / branch refs drift or can be hijacked without a version change.",
        )
    )
    findings.extend(
        check_regex_rules(
            path,
            text,
            "AST07-AUTO-UPDATE",
            "Automatic update / self-update enabled",
            "high",
            AUTO_UPDATE_PATTERNS,
            "AST07: auto-updating agents silently receive a malicious v-next; require signature verification and human approval on every update.",
        )
    )
    if is_skill_md and meta.get("version") and not meta.get("content_hash"):
        findings.append(
            Finding(
                rule_id="AST07-NO-PIN",
                title="Versioned skill not pinned to a content hash",
                severity="medium",
                file=str(path),
                line=1,
                evidence=f"version={meta.get('version')} but no content_hash",
                rationale="AST07: a 'fix' version is unverifiable without cryptographic pinning; attacker can push v1.0.1 with a new payload.",
            )
        )
    return findings


def check_ast09_governance(path: Path, text: str, meta: dict[str, str], is_skill_md: bool) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(
        check_regex_rules(
            path,
            text,
            "AST09-CRED",
            "Hardcoded credential or private key (orphaned-credential risk)",
            "high",
            HARDCODED_CRED_PATTERNS,
            "AST09: skills installed with individual credentials and no deprovisioning; hardcoded secrets outlive the installer.",
            flags=0,
        )
    )
    for match in PII_RE.finditer(text):
        if not AUDIT_DECL_RE.search(text):
            findings.append(
                Finding(
                    rule_id="AST09-PII",
                    title="Regulated data handling without an audit trail",
                    severity="medium",
                    file=str(path),
                    line=line_of(text, match.start()),
                    evidence=snippet(text, match.start()),
                    rationale="AST09: PII/PHI processed by an unreviewed skill with no audit trail creates regulatory exposure (EU AI Act Art. 12).",
                )
            )
            break
    for match in ONELINE_INSTALL_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="AST09-INSTALL",
                title="One-line skill install with no review workflow",
                severity="medium",
                file=str(path),
                line=line_of(text, match.start()),
                evidence=snippet(text, match.start()),
                rationale="AST09: single-line installs bypass approval workflows and SOC visibility, creating shadow-AI blind spots.",
            )
        )
    if is_skill_md:
        sensitive = bool(
            SHELL_TRUE_RE.search(text)
            or NETWORK_BOOL_RE.search(text)
            or DESTRUCTIVE_RE.search(text)
            or SUBPROCESS_RE.search(text)
            or "network" in (meta.get("permissions", "").lower())
        )
        if sensitive and not AUDIT_DECL_RE.search(text) and "audit" not in " ".join(meta.keys()).lower():
            findings.append(
                Finding(
                    rule_id="AST09-AUDIT",
                    title="Sensitive skill without declared audit logging",
                    severity="medium",
                    file=str(path),
                    line=1,
                    evidence="skill performs shell/network/destructive actions but declares no audit/logging",
                    rationale="AST09: enable comprehensive audit logging for file, network, shell, and memory actions; tamper-evident receipts for compliance.",
                )
            )
    return findings


def check_ast02_supply_file(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    name = path.name.lower()
    if name in {"requirements.txt", "requirements-dev.txt"}:
        if REQ_RANGE_RE.search(text):
            match = REQ_RANGE_RE.search(text)
            findings.append(
                Finding(
                    rule_id="AST02-RANGE",
                    title="Unpinned dependency version range",
                    severity="high",
                    file=str(path),
                    line=line_of(text, match.start()) if match else 1,
                    evidence=snippet(text, match.start()) if match else name,
                    rationale="AST02: pin nested dependencies to immutable hashes (sha256), not version ranges.",
                )
            )
        if text.strip() and not PIP_HASH_RE.search(text):
            findings.append(
                Finding(
                    rule_id="AST02-NOHASH",
                    title="Python dependencies lack sha256 hashes",
                    severity="high",
                    file=str(path),
                    line=1,
                    evidence=path.name,
                    rationale="AST02 code example: requirements.txt should use --hash=sha256, not floating versions.",
                )
            )
        if re.search(r"yutube|youtubee|beautifulsoup4l|reqeusts", text, re.I):
            findings.append(
                Finding(
                    rule_id="AST02-CONFUSE",
                    title="Possible dependency-confusion / typosquat package",
                    severity="critical",
                    file=str(path),
                    line=1,
                    evidence=snippet(text, 0),
                    rationale="AST02: nested typosquats such as yutube-dl-core bypass surface-level skill scans.",
                )
            )
    if name in {"package.json", "package-lock.json"}:
        if re.search(r'"(?:dependencies|devDependencies)"\s*:\s*\{[^}]*"[^"]+"\s*:\s*"[~^><*]', text, re.S):
            findings.append(
                Finding(
                    rule_id="AST02-RANGE",
                    title="Unpinned npm dependency version range",
                    severity="high",
                    file=str(path),
                    line=1,
                    evidence=path.name,
                    rationale="AST02: pin nested dependencies; a clean SKILL.md can still pull a poisoned package.json dep.",
                )
            )
        if name == "package.json" and "integrity" not in text.lower() and re.search(r'"dependencies"', text):
            findings.append(
                Finding(
                    rule_id="AST02-NOHASH",
                    title="npm dependencies without integrity hashes in the skill package",
                    severity="medium",
                    file=str(path),
                    line=1,
                    evidence="package.json has dependencies but no integrity field (lockfile may still pin)",
                    rationale="AST02: recursive dependency trees must be hash-pinned; SkillJacking hijacks unpinned sources.",
                )
            )
    if UNPINNED_GIT_RE.search(text) and "sha256" not in text.lower():
        match = UNPINNED_GIT_RE.search(text)
        findings.append(
            Finding(
                rule_id="AST02-GIT",
                title="Unpinned git/GitHub dependency",
                severity="high",
                file=str(path),
                line=line_of(text, match.start()) if match else 1,
                evidence=snippet(text, match.start()) if match else "git+ dependency",
                rationale="AST02 SkillJacking: deleted GitHub accounts and unregistered packages are reclaimable.",
            )
        )
    if ANTHROPIC_BASE_RE.search(text) or path.name.lower() in CONFIG_HIJACK_NAMES or ".claude" in path.parts:
        if path.suffix.lower() == ".json" or ANTHROPIC_BASE_RE.search(text):
            findings.append(
                Finding(
                    rule_id="AST02-CONFIG",
                    title="Repository config treated as an execution path",
                    severity="high",
                    file=str(path),
                    line=1,
                    evidence=str(path.name),
                    rationale="AST02: .claude/settings.json, hooks, and ANTHROPIC_BASE_URL become RCE paths on clone/open (CVE-2025-59536 / CVE-2026-21852).",
                )
            )
    return findings


def check_ast08_binaries(binaries: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in binaries:
        findings.append(
            Finding(
                rule_id="AST08-BINARY",
                title="Binary or archive that pattern scanners often skip",
                severity="high",
                file=str(path),
                line=0,
                evidence=path.name,
                rationale="AST08: Trail of Bits hid payloads in .pyc and .docx/ZIP because scanners ignore binary/archive formats. Scan the entire skill directory.",
            )
        )
    return findings


def scan_text(path: Path, text: str) -> list[Finding]:
    meta, _body = parse_frontmatter(text)
    is_skill_md = path.name.lower() in {"skill.md", "skill.markdown"}
    findings: list[Finding] = []
    findings.extend(check_base64(path, text))
    findings.extend(check_http_urls(path, text))
    findings.extend(check_identity_access(path, text))
    findings.extend(check_typosquat(path, meta, text))
    findings.extend(check_signature(path, meta, is_skill_md))
    findings.extend(check_obfuscation(path, text, meta))
    findings.extend(check_excessive_permissions(path, text, meta))
    findings.extend(
        check_regex_rules(
            path,
            text,
            "AST01-SOCENG",
            "Social engineering / ClickFix / paste-this-command prompt",
            "critical",
            SOCENG_PATTERNS,
            "AST01: Prerequisites paste, ClickFix dialogs, and social-engineering helper installs.",
        )
    )
    findings.extend(
        check_regex_rules(
            path,
            text,
            "AST01-SHELL",
            "Reverse shell, stealer, or pipe-to-shell install",
            "critical",
            SHELL_PATTERNS,
            "AST01: hidden malicious payloads — credential stealers, reverse shells, backdoors.",
        )
    )
    findings.extend(
        check_regex_rules(
            path,
            text,
            "AST01-EXT-SCRIPT",
            "Invokes an external script or Python file",
            "high",
            EXT_SCRIPT_PATTERNS,
            "AST01/AST02: skills that run .py/.sh/.ps1/.js files (or exec(open(...))) load code outside the reviewed SKILL.md — staged loaders and hidden payloads.",
        )
    )
    findings.extend(
        check_regex_rules(
            path,
            text,
            "AST01-EXFIL",
            "Credential, wallet, or browser-data collection",
            "critical",
            EXFIL_PATTERNS,
            "AST01: skills that target SSH keys, wallets, browser data, and API credentials.",
        )
    )
    findings.extend(
        check_regex_rules(
            path,
            text,
            "AST01-HIDDEN",
            "Shadow / hidden-from-user instructions",
            "high",
            HIDDEN_PATTERNS,
            "AST01 / USENIX 2026: shadow features hidden from the user.",
        )
    )
    findings.extend(
        check_regex_rules(
            path,
            text,
            "AST01-WS",
            "WebSocket / persistent C2-style connection",
            "high",
            WEBSOCKET_PATTERNS,
            "AST01 WebSocket hijacking: persistent connections to attacker C2.",
        )
    )
    findings.extend(check_ast03_privilege(path, text, meta, is_skill_md))
    findings.extend(check_ast04_metadata(path, text, meta, is_skill_md))
    findings.extend(check_ast05_external(path, text, meta))
    findings.extend(check_ast06_isolation(path, text, meta))
    findings.extend(check_ast07_drift(path, text, meta, is_skill_md))
    findings.extend(check_ast08_evasion(path, text, meta, is_skill_md))
    findings.extend(check_ast09_governance(path, text, meta, is_skill_md))
    findings.extend(check_ast10_format(path, meta, text, is_skill_md))
    findings.extend(check_ast02_supply_file(path, text))
    return findings


def scan_path(target: Path) -> list[Finding]:
    findings: list[Finding] = []
    text_files, binary_files = collect_files(target)
    findings.extend(check_ast08_binaries(binary_files))
    print("inside scan_path")
    for path in text_files:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            findings.append(
                Finding(
                    rule_id="AST01-IO",
                    title="Could not read file",
                    severity="low",
                    file=str(path),
                    line=0,
                    evidence=str(exc),
                    rationale="Scanner I/O error.",
                )
            )
            continue
        text = raw.decode("utf-8", errors="replace")
        findings.extend(scan_text(path, text))
    uniq: list[Finding] = []
    seen: set[tuple] = set()
    for item in findings:
        key = (item.rule_id, item.file, item.line, item.evidence)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(item)
    uniq.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.file, f.line, f.rule_id))
    return uniq


def render_text(findings: list[Finding], target: Path) -> str:
    lines = [
        f"OWASP Agentic Skills Top 10 scan: {target}",
        "Sources: " + ", ".join(SOURCES.values()),
        f"Findings: {len(findings)}",
        "",
    ]
    if not findings:
        lines.append("No static indicators found.")
        return "\n".join(lines)
    for item in findings:
        src = SOURCES.get(standard_of(item.rule_id), "")
        lines.extend(
            [
                f"[{item.severity.upper()}] {item.rule_id} {item.title}",
                f"  file: {item.file}:{item.line}",
                f"  evidence: {item.evidence}",
                f"  why: {item.rationale}",
                f"  url: {src}" if src else "  url:",
                "",
            ]
        )
    return "\n".join(lines)


def max_severity(findings: list[Finding]) -> str:
    if not findings:
        return "info"
    return max(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan a SKILL.md file or skill directory using OWASP Agentic Skills Top 10 "
            "AST01–AST10 rules."
        )
    )
    parser.add_argument("path", help="Path to SKILL.md or a skill directory")
    parser.add_argument("--json", action="store_true", help="Emit JSON findings")
    parser.add_argument(
        "--fail-on",
        default="high",
        choices=list(SEVERITY_ORDER),
        help="Exit 1 if any finding is at least this severity (default: high)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    target = Path(args.path).expanduser()
    if not target.exists():
        print(f"error: path not found: {target}", file=sys.stderr)
        return 2
    findings = scan_path(target)
    if args.json:
        payload = {
            "sources": SOURCES,
            "target": str(target),
            "finding_count": len(findings),
            "max_severity": max_severity(findings),
            "findings": [asdict(f) | {"standard": standard_of(f.rule_id)} for f in findings],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(render_text(findings, target))
    threshold = SEVERITY_ORDER[args.fail_on]
    if any(SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
