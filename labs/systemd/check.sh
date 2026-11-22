#!/bin/bash
# Runs inside the systemd container: install the app, create the daily timer as a normal user,
# run the update service once under its sandbox settings, then remove it again.
set -u
step() { echo; echo "=== $*"; }
export PIP_ROOT_USER_ACTION=ignore PIP_DISABLE_PIP_VERSION_CHECK=1
mkdir -p /work && tar -C /src --exclude=./node_modules --exclude=./browser-test/node_modules --exclude=./.git \
  --exclude=./dist --exclude=./build --exclude='*.egg-info' --exclude=__pycache__ -cf - . | tar -C /work -xf -
python -m pip install -q /work >/dev/null && homograph-guard --version
step "user session (linger, as on a desktop where the user is signed in)"
loginctl enable-linger tester
for i in $(seq 1 30); do [ -S /run/user/1000/bus ] && break; sleep 1; done
u() { runuser -u tester -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus HOME=/home/tester bash -c "cd ~ && $1"; }
u 'systemctl --user is-system-running || true'
step "setup schedule install"
u 'homograph-guard setup schedule install --hour 7'
u 'ls -l ~/.config/systemd/user/; systemctl --user list-timers --all --no-pager | head -5'
u 'homograph-guard setup schedule status'
step "run the update service once, under its sandbox settings"
u 'time systemctl --user start homograph-guard-update.service; systemctl --user show homograph-guard-update.service -p Result -p ExecMainStatus -p NoNewPrivileges -p RestrictNamespaces -p LockPersonality -p SystemCallArchitectures -p UMask --no-pager'
u 'journalctl --user -u homograph-guard-update.service --no-pager 2>/dev/null | tail -5 || true'
u 'homograph-guard db status | head -15; stat -c "%a %n" ~/.local/share/homograph-guard ~/.local/share/homograph-guard/threats.db'
step "a second run the same day is skipped (--if-due)"
u 'time systemctl --user start homograph-guard-update.service; systemctl --user show homograph-guard-update.service -p Result -p ExecMainStatus --no-pager'
step "setup schedule uninstall"
u 'homograph-guard setup schedule uninstall; ls ~/.config/systemd/user/ 2>/dev/null; systemctl --user list-timers --all --no-pager | grep -c homograph || true'
echo; echo "=== done"
