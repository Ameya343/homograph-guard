"""hg-update.exe - windowless threat-database updater (daily task, installer, 'Update now').

    hg-update.exe            update if the last update is older than 20 hours (the daily task)
    hg-update.exe --now      update now
    hg-update.exe --force    re-import every feed
"""

import sys

from homograph_guard.commands import main

if __name__ == "__main__":
    argv = sys.argv[1:]
    extra = [a for a in argv if a == "--force" or a.startswith("--feed=")]
    args = ["update", "--quiet", *extra] if ("--now" in argv or extra) else ["update", "--if-due", "--quiet"]
    raise SystemExit(main(args))
