"""Launcher for ``python -I`` (isolated mode ignores PYTHONPATH, user site and the CWD).

Used by the Docker image and the GUI's local worker so that environment
variables such as PYTHONPATH or PYTHONSTARTUP can never inject code.
"""

import os
import sys

_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from homograph_guard.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
