#!/usr/bin/env python3
"""
skill_audit.py — Static security scanner for downloaded AI skill/plugin files.

Scans a file or directory for red flags before you trust it with real data:
network calls, credential/filesystem access, obfuscation, prompt-injection
style text aimed at an LLM reader, and dependency manifests worth checking
by hand.

This is static pattern-matching, not a sandbox. It will not catch everything
(especially cleverly obfuscated code) — treat a clean report as "no obvious
red flags," not "safe." Always pair with running untrusted code in isolation.

Usage:
    python3 skill_audit.py <path-to-file-or-folder>
    python3 skill_audit.py <path> --json report.json
"""

import argparse
import json
import re
import sys
from pathlib import Path

# Skip binary / irrelevant file types
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2",
    ".ttf", ".otf", ".pdf", ".zip", ".tar", ".gz", ".pyc", ".so", ".dll",
    ".exe", ".bin", ".lock",
}

TEXT_EXTENSIONS_HINT = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash", ".md", ".txt",
    ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".env", ".rb",
    ".go", ".rs", ".java", ".php", ".ps1", ".html",
}

# Each rule: (id, severity, compiled_regex, human description)
RULES = [
    # --- Network / exfiltration ---
    ("NET-001", "HIGH",
     re.compile(r"\b(requests\.(post|put|get)|urllib\.request|httpx\.|fetch\(|axios\.|XMLHttpRequest)\b"),
     "Outbound HTTP call"),
    ("NET-002", "HIGH",
     re.compile(r"\b(curl|wget)\b.*\s(-o|-O|>|--output)"),
     "Shell download/upload via curl or wget"),
    ("NET-003", "MEDIUM",
     re.compile(r"\bsocket\.(socket|connect)\b"),
     "Raw socket usage"),
    ("NET-004", "HIGH",
     re.compile(r"https?://[a-zA-Z0-9\-\.]+\.(ngrok\.io|pastebin\.com|transfer\.sh|webhook\.site|requestbin\.\w+)"),
     "URL pointing to a known exfil/relay service (ngrok, pastebin, webhook.site, etc.)"),
    ("NET-005", "LOW",
     re.compile(r"https?://[a-zA-Z0-9\-\._/]+"),
     "Hardcoded URL (verify it's the tool's official domain)"),

    # --- Credential / sensitive file access ---
    ("CRED-001", "HIGH",
     re.compile(r"(~/\.ssh|\.aws/credentials|\.aws/config|~/\.gnupg|id_rsa|id_ed25519)"),
     "Reference to SSH/AWS/GPG credential paths"),
    ("CRED-002", "HIGH",
     re.compile(r"\.env\b|os\.environ|process\.env"),
     "Reads environment variables or .env file (check what it does with them)"),
    ("CRED-003", "HIGH",
     re.compile(r"(Cookies|Login Data|cookies\.sqlite|Local Storage/leveldb)"),
     "Reference to browser cookie/credential storage"),
    ("CRED-004", "MEDIUM",
     re.compile(r"os\.walk\(\s*['\"]/['\"]|find\s+/\s+-name|Get-ChildItem\s+-Recurse\s+C:\\"),
     "Broad filesystem scan from root"),

    # --- Obfuscation / dynamic execution ---
    ("OBF-001", "HIGH",
     re.compile(r"\bexec\(|\beval\(|new Function\(|atob\(|Function\(['\"]return"),
     "Dynamic code execution (exec/eval/Function/atob)"),
    ("OBF-002", "MEDIUM",
     re.compile(r"base64\.b64decode|Buffer\.from\([^,]+,\s*['\"]base64"),
     "Base64 decoding — check what the decoded payload does"),
    ("OBF-003", "MEDIUM",
     re.compile(r"subprocess\.(Popen|call|run)|child_process\.(exec|spawn)|os\.system\("),
     "Shell-out / subprocess execution"),
    ("OBF-004", "LOW",
     re.compile(r"[A-Za-z0-9+/]{80,}={0,2}"),
     "Long base64-like blob — inspect manually"),

    # --- Prompt injection aimed at the LLM reading this file ---
    ("PI-001", "HIGH",
     re.compile(r"ignore (all )?(previous|prior|above) instructions", re.IGNORECASE),
     "Prompt-injection phrase targeting an LLM reader"),
    ("PI-002", "HIGH",
     re.compile(r"(send|exfiltrate|upload|email) (the )?(user'?s?|local|private) (files?|data|credentials?|secrets?)", re.IGNORECASE),
     "Instruction to exfiltrate user data"),
    ("PI-003", "MEDIUM",
     re.compile(r"do not (tell|inform|mention to) the user", re.IGNORECASE),
     "Instruction to hide behavior from the user"),
    ("PI-004", "MEDIUM",
     re.compile(r"<!--.*?(ignore|instruction|system).*?-->", re.IGNORECASE | re.DOTALL),
     "Suspicious instruction hidden in an HTML/XML comment"),

    # --- Dependency manifests worth a manual look ---
    ("DEP-001", "INFO",
     re.compile(r"^\s*[\"']?[\w\-]+[\"']?\s*[:=]"),
     "Dependency manifest entry (verify package name spelling / source)"),

    # --- AST01: Malicious Skills (OWASP Agentic Skills Top 10) ---
    ("AST01-001", "HIGH",
     re.compile(r"\b(SOUL\.md|MEMORY\.md|AGENTS\.md)\b"),
     "Reference to an agent identity/persona file — AST01 identity cloning & persistence risk"),
    ("AST01-002", "HIGH",
     re.compile(r"(run|paste|copy).{0,40}(this|the following).{0,40}(command|script|terminal)", re.IGNORECASE),
     "Social-engineering 'Prerequisites' style instruction telling the user to run a command"),
    ("AST01-003", "HIGH",
     re.compile(r"(setup|install)[\s\-_]?(required|needed)|click.{0,20}(fix|here to (fix|continue|install))", re.IGNORECASE),
     "ClickFix-style 'setup required' dialog pattern used to coerce script execution"),
    ("AST01-004", "MEDIUM",
     re.compile(r"\bnew\s+WebSocket\(|wss?://"),
     "WebSocket connection — check destination isn't an attacker C2 channel"),
    ("AST01-005", "HIGH",
     re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
     "Hardcoded raw IP address — common C2 indicator, verify legitimacy"),
    ("AST01-006", "MEDIUM",
     re.compile(r"(inject|append|write).{0,30}(MEMORY\.md|context|history)", re.IGNORECASE),
     "Possible memory-poisoning pattern — writes into agent memory/context files"),
    ("AST01-007", "LOW",
     re.compile(r"signature|content_hash|ed25519", re.IGNORECASE),
     "Signing/provenance metadata present — verify signature actually validates, don't assume trust from presence alone"),
]

# Reference: https://owasp.org/www-project-agentic-skills-top-10/ast01
# AST01 "Malicious Skills" evidence base: malicious skills combine code-layer
# payloads (shell/Python) with natural-language instruction-layer payloads
# embedded in SKILL.md prose. Pattern matching alone (this script) is *not*
# sufficient per OWASP's own guidance — pair with sandboxed dynamic analysis
# and, where possible, signature/provenance verification before trusting a skill.

DEP_FILES = {"requirements.txt", "package.json", "pyproject.toml", "Gemfile", "go.mod", "Cargo.toml"}


def iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() not in SKIP_EXTENSIONS:
            yield p


def scan_file(path: Path, root: Path):
    findings = []
    try:
        text = path.read_text(errors="ignore")
    except Exception as e:
        return [{"rule": "READ-ERR", "severity": "LOW", "line": 0,
                  "desc": f"Could not read file: {e}", "snippet": ""}]

    is_dep_file = path.name in DEP_FILES
    lines = text.splitlines()

    for i, line in enumerate(lines, start=1):
        for rule_id, severity, pattern, desc in RULES:
            if rule_id == "DEP-001" and not is_dep_file:
                continue
            if rule_id == "NET-005":
                # only flag URLs not already caught by a higher-severity net rule on this line
                pass
            m = pattern.search(line)
            if m:
                findings.append({
                    "rule": rule_id,
                    "severity": severity,
                    "line": i,
                    "desc": desc,
                    "snippet": line.strip()[:160],
                })
    return findings


def severity_rank(sev):
    return {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}.get(sev, 4)


def main():
    ap = argparse.ArgumentParser(description="Static security scan for downloaded skill/plugin files.")
    ap.add_argument("path", help="Path to a skill file or folder")
    ap.add_argument("--json", help="Write full results to this JSON file")
    ap.add_argument("--min-severity", choices=["HIGH", "MEDIUM", "LOW", "INFO"], default="LOW",
                     help="Only print findings at or above this severity (default: LOW)")
    args = ap.parse_args()

    root = Path(args.path).expanduser().resolve()
    if not root.exists():
        print(f"Path not found: {root}", file=sys.stderr)
        sys.exit(1)

    all_results = {}
    total_by_sev = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for f in iter_files(root):
        findings = scan_file(f, root)
        if findings:
            all_results[str(f.relative_to(root) if root.is_dir() else f.name)] = findings
            for finding in findings:
                total_by_sev[finding["severity"]] += 1

    min_rank = severity_rank(args.min_severity)

    print(f"\n=== Skill Audit Report: {root} ===\n")
    if not all_results:
        print("No pattern matches found. (Static scan only — still review manually before trusting.)")
    else:
        for file_rel, findings in all_results.items():
            shown = [x for x in findings if severity_rank(x["severity"]) <= min_rank]
            if not shown:
                continue
            print(f"--- {file_rel} ---")
            for x in sorted(shown, key=lambda f: severity_rank(f["severity"])):
                print(f"  [{x['severity']:6}] {x['rule']}  line {x['line']}: {x['desc']}")
                print(f"           > {x['snippet']}")
            print()

    print("=== Summary ===")
    for sev in ["HIGH", "MEDIUM", "LOW", "INFO"]:
        print(f"  {sev:8}: {total_by_sev[sev]}")
    if total_by_sev["HIGH"] > 0:
        print("\n⚠ HIGH severity findings present — do not run this skill until each is manually reviewed.")

    ast01_hits = [r for res in all_results.values() for r in res if r["rule"].startswith("AST01")]
    if ast01_hits:
        print("\nNote: findings tagged AST01-xxx map to OWASP Agentic Skills Top 10, AST01 (Malicious Skills).")
        print("Static scanning is not sufficient per OWASP's own guidance for this risk — before trusting this")
        print("skill, also: run it in a network-isolated sandbox, verify any signature against a known publisher")
        print("key, and check whether it reads/writes SOUL.md, MEMORY.md, or AGENTS.md (identity persistence).")
        print("Reference: https://owasp.org/www-project-agentic-skills-top-10/ast01")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(all_results, fh, indent=2)
        print(f"\nFull results written to {args.json}")


if __name__ == "__main__":
    main()
