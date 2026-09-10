#!/usr/bin/env bash
# Validate scan_skill.py against the OWASP AST01–AST10 test suite.
# Usage: ./tests/run_tests.sh   (from the repo root or anywhere)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1

cd "$REPO_ROOT"
python3 -m unittest discover -s tests -p "test_*.py" -v
