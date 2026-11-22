#!/bin/bash
# Runs the per-user daily update timer under a real systemd (as on a Linux desktop): creates it
# with `homograph-guard setup schedule install`, runs the update service once under its sandbox
# settings, checks the file permissions, then removes it. systemd as PID 1 needs a privileged
# container; it is removed at the end.
#   bash labs/systemd/run.sh
set -u
. "$(dirname "$0")/../_lib.sh"
here="$(hostpath "$(dirname "$0")")"
docker build -q -t hg-systemd-lab "$here" >/dev/null || exit 1
docker rm -f hg-systemd-lab >/dev/null 2>&1
docker run -d --name hg-systemd-lab --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
  -v "$REPO:/src:ro" -v "$here/check.sh:/check.sh:ro" hg-systemd-lab >/dev/null || exit 1
docker exec hg-systemd-lab systemctl is-system-running --wait >/dev/null
docker exec hg-systemd-lab bash /check.sh; rc=$?
docker rm -f hg-systemd-lab >/dev/null
exit $rc
