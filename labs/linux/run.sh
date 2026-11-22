#!/bin/bash
# Linux check in a clean Debian container (python:3.15-slim): the whole test suite as a normal
# user, the extension in Chromium with and without the app, browser registration (per user and
# machine-wide) and the daily schedule. Screenshots go to labs/linux/out.
#   bash labs/linux/run.sh
set -u
. "$(dirname "$0")/../_lib.sh"
here="$(hostpath "$(dirname "$0")")"
mkdir -p "$(dirname "$0")/out"
docker run --rm -v "$REPO:/src:ro" -v "$here/inside.sh:/inside.sh:ro" -v "$here/out:/out" python:3.15-slim bash /inside.sh
