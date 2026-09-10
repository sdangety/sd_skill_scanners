# scan_skill.py test suite

Regression tests for `scan_skill.py`, one test per rule extracted from the
OWASP Agentic Skills Top 10 (AST01–AST10).

## Run

```bash
# from owasp_skill_checker/
./tests/run_tests.sh

# or directly (no dependencies, stdlib unittest only)
python3 -m unittest discover -s tests -v
python3 tests/test_scan_skill.py
```

Exit code `0` means all rules still fire as expected and a known-clean skill
produces zero findings. Non-zero means a check regressed.

## What is covered

- **Clean baseline** — a well-formed Universal Skill Format `SKILL.md` must
  yield **0** findings, and `main()` must exit `0`.
- **AST01 Malicious Skills** — base64 payload, non-HTTPS URL, identity access,
  identity-write persistence, typosquatting, missing signature/publisher,
  obfuscated blob, dynamic eval, unusual YAML key, unrestricted permissions,
  social engineering, pipe-to-shell, **AST01-EXT-SCRIPT** (external `.py`/`.sh`
  via `python3`, `bash`, `exec(open)`, `subprocess`, `source`, `run helper.py`,
  `./scripts/setup.py`), credential exfil, hidden-from-user, WebSocket C2.
- **AST02 Supply Chain** — version ranges, missing sha256 hashes, dependency
  confusion, unpinned git dep, config-file execution path.
- **AST03 Over-Privileged** — missing manifest, boolean network, unscoped
  shell, wildcard filesystem, env-secret read, destructive action, cron.
- **AST04 Insecure Metadata** — YAML RCE gadget, zero-width smuggling, ASCII
  control smuggling, prototype pollution, permission understating, risk-tier
  spoofing, brand impersonation.
- **AST05 Untrusted External Instructions** — external fetch, transitive
  chaining, untrusted host, unpinned URL.
- **AST06 Weak Isolation** — bind `0.0.0.0`, host process spawn, sandbox
  disabled, hot-reload, unauthenticated WebSocket.
- **AST07 Update Drift** — mutable ref, auto-update, versioned-without-hash.
- **AST08 Poor Scanning** — padding truncation, natural-language exfil,
  scanner prompt injection, conditional malice, scanner impersonation, binary
  file flagged.
- **AST09 No Governance** — hardcoded credential, PII without audit, one-line
  install, sensitive skill without audit logging.
- **AST10 Cross-Platform Reuse** — incomplete Universal Skill Format metadata,
  missing `deny_write`.

A `TestCoverage` guard asserts that every AST standard has at least one test
class, so adding a new standard without tests will fail the suite.
