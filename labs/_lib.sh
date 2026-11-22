# Sourced by the lab scripts. Docker on Windows (Git Bash) needs C:/... paths for -v mounts.
export MSYS_NO_PATHCONV=1
hostpath() { (cd "$1" && (pwd -W 2>/dev/null || pwd)); }
REPO="$(hostpath "$(dirname "${BASH_SOURCE[0]}")/..")"
