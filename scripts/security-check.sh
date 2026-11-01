#!/usr/bin/env bash
# The re-lab security gate. Runs on every commit (the .githooks/pre-commit hook calls this)
# and in CI (.github/workflows/ci.yml). It blocks the commit if anything fails.
#
# Two checks, both offline and fast:
#   1. supply chain  (scripts/check_deps.py) -- every dependency is pinned with a sha256 hash and
#      installed index-only, every big download is integrity-verified, and nothing pipes a
#      download into a shell. This is the "prevent malicious packages" guard.
#   2. fuzzing       (tests/fuzz_agent.py)   -- throws malformed/hostile input at the parsers that
#      read untrusted sample and model data, asserting they never crash, hang, or blow up.
#
# Optional (set SECURITY_PIP_AUDIT=1, needs network): pip-audit scans the locks for packages with
# known published vulnerabilities. CI runs this; the pre-commit hook does not, to stay offline/fast.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$LAB_DIR"

PY="${PYTHON:-python3}"
FUZZ_ITERATIONS="${FUZZ_ITERATIONS:-2000}"
FUZZ_SECONDS="${FUZZ_SECONDS:-12}"
rc=0

echo "[security] 1/2 supply-chain check ..."
"$PY" scripts/check_deps.py || rc=1

echo "[security] 2/2 fuzzing untrusted-input parsers (${FUZZ_ITERATIONS} cases, <=${FUZZ_SECONDS}s) ..."
"$PY" tests/fuzz_agent.py --iterations "$FUZZ_ITERATIONS" --seconds "$FUZZ_SECONDS" || rc=1

if [ "${SECURITY_PIP_AUDIT:-0}" = "1" ]; then
  echo "[security] + pip-audit (known-vulnerability scan) ..."
  if command -v pip-audit >/dev/null 2>&1; then
    pip-audit -r agent/requirements.lock || rc=1
    pip-audit -r ghidra/requirements.lock || rc=1
  else
    echo "[security] pip-audit not installed; skipping (pip install pip-audit to enable)"
  fi
fi

if [ "$rc" -eq 0 ]; then
  echo "[security] PASSED"
else
  echo "[security] FAILED — fix the problems above (commit blocked)"
fi
exit "$rc"
