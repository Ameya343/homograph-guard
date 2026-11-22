#!/bin/bash
# Runs inside a clean python:3.15-slim container: the test suite, the extension end to end
# (browser only and through the app), browser registration and the daily schedule, as a normal user.
set -u
export DEBIAN_FRONTEND=noninteractive PIP_ROOT_USER_ACTION=ignore PIP_DISABLE_PIP_VERSION_CHECK=1 PLAYWRIGHT_BROWSERS_PATH=/opt/pw
step() { echo; echo "=== $*"; }

step "system packages"
apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends xvfb xauth libtk8.6 libatomic1 cron >/dev/null || exit 1
mkdir -p /work
tar -C /src --exclude=./node_modules --exclude=./browser-test/node_modules --exclude=./.git --exclude=./dist \
    --exclude=./build --exclude=./.venv --exclude='*.egg-info' --exclude=__pycache__ -cf - . | tar -C /work -xf -
cd /work

step "python packages"
python -m pip install -q --upgrade pip >/dev/null
if ! python -m pip install -q -e ".[dev,tls]" playwright; then
  apt-get install -y -qq --no-install-recommends build-essential >/dev/null && python -m pip install -q -e ".[dev,tls]" playwright || exit 1
fi
python -m playwright install --with-deps chromium >/tmp/pw.log 2>&1 || { tail -20 /tmp/pw.log; exit 1; }
python -c "import sys, tkinter; print('python', sys.version.split()[0], '| tk', tkinter.TkVersion)"
grep PRETTY_NAME /etc/os-release
pip list --format=freeze 2>/dev/null | grep -iE '^(dnspython|idna|publicsuffixlist|cryptography|playwright|pytest)=='
useradd -m -s /bin/bash tester && chown -R tester /work
as_tester() { su tester -s /bin/bash -c "cd /work && $1"; }

step "pytest (as a normal user)"
as_tester 'xvfb-run -a python -m pytest -q -p no:cacheprovider -W error::ResourceWarning -rfEs 2>&1 | tail -25; echo "pytest exit: ${PIPESTATUS[0]}"'

step "extension end to end, browser only"
as_tester 'python extension/tests/e2e.py /work/shots/linux-fallback 2>&1 | grep -v "got {"; echo "e2e exit: ${PIPESTATUS[0]}"'

step "extension end to end, through the app (native messaging)"
as_tester 'HG_NATIVE=1 python extension/tests/e2e.py /work/shots/linux-native 2>&1 | grep -v "got {"; echo "e2e native exit: ${PIPESTATUS[0]}"'

step "sites keep working with the extension (stand-in Gmail and Outlook pages, strict CSP, 5,000 links)"
as_tester 'python extension/tests/compat.py /work/shots/linux-compat 2>&1 | grep -E "FAIL|checks passed|failed"; echo "compat exit: ${PIPESTATUS[0]}"'

step "browser registration for this user"
as_tester 'homograph-guard native-host install && homograph-guard native-host status && (cd ~ && find . -name "com.homograph_guard.host.json" | sort) && homograph-guard native-host uninstall'

step "daily schedule (this container has no systemd user session, so cron is used)"
service cron start >/dev/null 2>&1 || true
as_tester 'homograph-guard setup schedule install --hour 7; homograph-guard setup schedule status; homograph-guard setup schedule uninstall; crontab -l 2>&1 | head -3'
as_tester 'homograph-guard setup firewall status; echo "exit (expect 2): $?"'

step "machine-wide registration"
as_tester 'homograph-guard native-host install --machine; echo "as a normal user, exit (expect 2): $?"'
homograph-guard native-host install --machine \
  && ls -l /etc/opt/chrome/native-messaging-hosts /etc/chromium/native-messaging-hosts /usr/lib/mozilla/native-messaging-hosts /usr/local/lib/homograph-guard/native-messaging \
  && homograph-guard native-host status --machine && homograph-guard native-host uninstall --machine

mkdir -p /out && cp -r /work/shots /out/ 2>/dev/null || true
echo; echo "=== done"
