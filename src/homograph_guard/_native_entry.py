"""Launcher for the native messaging host under ``python -I`` (pip installations).

Isolated mode keeps PYTHONPATH, PYTHONSTARTUP and the working directory from
injecting code into the process the browser starts.
"""

import os
import sys

_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from homograph_guard.native_host import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
