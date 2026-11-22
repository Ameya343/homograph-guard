#!/usr/bin/env bash
# Build a wheel, install it into a fresh virtual environment and run the installed
# commands from outside the source tree. The test suite imports straight from src/,
# so this is what proves the app actually works after `pip install`.
#
#   bash scripts/check-install.sh            # uses `python` on PATH
#   PY=python3.12 bash scripts/check-install.sh
set -euo pipefail

PY="${PY:-python}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# a private data folder and no policy file: never touch the real lists or settings
export HGUARD_HOME="$work/data" HGUARD_POLICY="$work/no-policy.json"

"$PY" -m pip wheel -q --no-deps -w "$work/dist" "$repo"
"$PY" -m venv "$work/venv"
bin="$work/venv/bin"; [ -d "$work/venv/Scripts" ] && bin="$work/venv/Scripts"
"$bin/python" -m pip install -q "$work"/dist/*.whl

cd "$work"   # outside the source tree, so nothing can fall back to src/

"$bin/homograph-guard" --version
"$bin/homograph-guard" --list-resolvers > /dev/null

set +e
"$bin/homograph-guard" --no-dns --json "https://xn--80ak6aa92e.com" > out.json; code=$?
set -e
test "$code" -eq 4 || { echo "expected exit code 4 (high risk), got $code"; cat out.json; exit 1; }
grep -q '"verdict": "high_risk"' out.json

# The GUI's local worker runs the installed _entry.py under `python -I`.
"$bin/python" -c "
import homograph_guard.gui.worker as w
r = w.run_batch(w.WorkerConfig(mode='local', dns=False), ['https://xn--pypal-4ve.com', 'https://google.com'])
assert [x['verdict'] for x in r] == ['high_risk', 'no_indicators'], r
"
if "$bin/python" -c "import tkinter" 2>/dev/null; then
    "$bin/python" -c "import homograph_guard.gui.app"
else
    echo "Tk is not available: skipped the GUI import (the CLI does not need it)"
fi
test -x "$bin/homograph-guard-gui" || test -f "$bin/homograph-guard-gui.exe"

# The on-device database: a blocklist entry is enforced by the installed command
"$bin/homograph-guard" db status > /dev/null
"$bin/homograph-guard" block add blocked-by-install-check.com > /dev/null
set +e
"$bin/homograph-guard" --no-dns --json "https://login.blocked-by-install-check.com/" > out.json; code=$?
set -e
test "$code" -eq 4 || { echo "a domain on the device blocklist should be high risk, got $code"; cat out.json; exit 1; }
grep -q '"LIST_BLOCKED"' out.json
"$bin/homograph-guard" native-host status > /dev/null
"$bin/homograph-guard" setup schedule show > /dev/null

echo "install check passed"
